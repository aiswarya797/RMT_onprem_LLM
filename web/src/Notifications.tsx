import { useEffect, useRef, useState, type FormEvent } from "react";
import { ApiError, api, type MutationAccess, type NotificationDestination, type NotificationTestJob, type WebhookDestinationDefinition } from "./api";

type Draft = {
  id: string | null;
  revision: number | null;
  displayName: string;
  url: string;
  hmacEnabled: boolean;
  secret: string;
};

const terminalStates = new Set(["succeeded", "failed", "cancelled"]);

export function NotificationsWorkspace({ access, onSessionLost }: { access: MutationAccess; onSessionLost: () => void }) {
  const [items, setItems] = useState<NotificationDestination[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [draft, setDraft] = useState<Draft | null>(null);
  const [saving, setSaving] = useState(false);
  const [testingID, setTestingID] = useState<string | null>(null);
  const [testJob, setTestJob] = useState<NotificationTestJob | null>(null);
  const [lastJob, setLastJob] = useState<NotificationTestJob | null>(null);
  const attempt = useRef<{ signature: string; key: string } | null>(null);
  const active = useRef(true);
  const canWrite = access.role === "admin" && access.mutationsAllowed;

  useEffect(() => {
    active.current = true;
    setItems([]);
    setLoaded(false);
    setDraft(null);
    setTestingID(null);
    setTestJob(null);
    setLastJob(null);
    setError("");
    setNotice("");
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => {
      active.current = false;
      controller.abort();
    };
  }, [access.generation]);

  async function refresh(signal?: AbortSignal) {
    try {
      const result = await api.destinations(signal);
      if (!active.current || signal?.aborted) return;
      setItems(result.items);
      setLoaded(true);
      setError("");
      const recent = result.items.find(item => item.last_test_job_id);
      if (recent?.last_test_job_id) {
        try {
          const job = await api.notificationJob(recent.last_test_job_id, signal);
          if (active.current && !signal?.aborted) setLastJob(job);
        } catch (cause) {
          if (active.current && !signal?.aborted) fail(cause);
        }
      } else {
        setLastJob(null);
      }
    } catch (cause) {
      if (active.current && !signal?.aborted) fail(cause);
    }
  }

  function fail(cause: unknown) {
    if (cause instanceof ApiError && (cause.status === 401 || cause.code === "authentication_required" || cause.code === "session_expired")) {
      onSessionLost();
      return;
    }
    setError(cause instanceof Error ? cause.message : "Notification destinations could not be loaded.");
  }

  function beginCreate() {
    setDraft({ id: null, revision: null, displayName: "", url: "https://", hmacEnabled: false, secret: "" });
    setError("");
    setNotice("");
  }

  function beginEdit(item: NotificationDestination) {
    const webhook = item.configuration.webhook;
    if (!webhook) return;
    setDraft({ id: item.id, revision: item.revision, displayName: item.display_name, url: webhook.https_url, hmacEnabled: webhook.hmac_enabled, secret: "" });
    setError("");
    setNotice("");
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || !canWrite || saving) return;
    const name = draft.displayName.trim();
    const url = draft.url.trim();
    if (name.length === 0) return setError("Enter a destination name.");
    if (!/^https:\/\/[^\s#]+$/i.test(url)) return setError("Use an HTTPS receiver URL without credentials or a fragment.");
    const existing = draft.id ? items.find(item => item.id === draft.id) : undefined;
    if (draft.hmacEnabled && !draft.secret && existing?.configuration.webhook && !existing.configuration.webhook.hmac_enabled) {
      return setError("Enter a webhook secret when enabling request signing.");
    }
    const definition: WebhookDestinationDefinition = {
      expected_revision: draft.revision,
      type: "webhook",
      display_name: name,
      webhook: { https_url: url, hmac_enabled: draft.hmacEnabled },
      smtp: null,
      secret_input: draft.secret || null,
    };
    const signature = JSON.stringify([access.generation, draft.id, definition]);
    if (attempt.current?.signature !== signature) attempt.current = { signature, key: crypto.randomUUID() };
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const saved = draft.id ? await api.updateDestination(access, draft.id, definition, attempt.current.key) : await api.createDestination(access, definition, attempt.current.key);
      if (!active.current) return;
      attempt.current = null;
      setDraft(null);
      setNotice(`Destination “${saved.display_name}” saved. Saving does not send a notification.`);
      await refresh();
    } catch (cause) {
      if (active.current) fail(cause);
    } finally {
      if (active.current) setSaving(false);
    }
  }

  async function sendTest(item: NotificationDestination) {
    if (!canWrite || testingID || item.type !== "webhook") return;
    setTestingID(item.id);
    setTestJob(null);
    setError("");
    setNotice("Test queued. Waiting for the receiver acknowledgement…");
    try {
      let job = await api.testDestination(access, item.id, item.revision, crypto.randomUUID());
      setTestJob(job);
      setLastJob(job);
      for (let attempt = 0; attempt < 120 && !terminalStates.has(job.state); attempt += 1) {
        await new Promise(resolve => window.setTimeout(resolve, 250));
        job = await api.notificationJob(job.job_id);
        if (!active.current) return;
        setTestJob(job);
        setLastJob(job);
      }
      if (!terminalStates.has(job.state)) throw new Error("The notification test did not finish before the UI wait limit.");
      if (job.state === "succeeded") {
        setNotice(job.receiver_ack_ms ? `Test succeeded. Receiver acknowledged at ${formatDate(job.receiver_ack_ms)}.` : "Test succeeded. Receiver acknowledgement was recorded.");
      } else {
        setError(job.error?.message ?? "The notification test failed. Check the receiver and retry.");
      }
      await refresh();
    } catch (cause) {
      if (active.current) fail(cause);
    } finally {
      if (active.current) setTestingID(null);
    }
  }

  function lastResult(item: NotificationDestination) {
    if (!item.last_test_result) return <p className="muted">No test has been sent.</p>;
    const job = lastJob?.job_id === item.last_test_job_id ? lastJob : null;
    if (item.last_test_result === "succeeded") {
      return <p className="notification-result success" role="status"><strong>Last test succeeded.</strong> {job?.receiver_ack_ms ? `Receiver acknowledged at ${formatDate(job.receiver_ack_ms)}.` : "Receiver acknowledgement was recorded."}</p>;
    }
    return <p className="notification-result failure" role="status"><strong>Last test failed.</strong> {job?.error?.message ?? "Check the receiver and retry."}</p>;
  }

  return <section aria-labelledby="notification-destinations-heading">
    <div className="section-heading">
      <h2 id="notification-destinations-heading">Notification destinations</h2>
      <button className="secondary" type="button" disabled={saving || testingID !== null} onClick={() => void refresh()}>Refresh destinations</button>
    </div>
    <p>Configure an HTTPS webhook, then send an explicit test through the durable delivery path. Saving a destination does not send anything.</p>
    {error && <p className="form-error" role="alert">{error}</p>}
    {notice && <p className="notice" role="status">{notice}</p>}
    {!loaded && !error && <p role="status">Loading notification destinations…</p>}
    {loaded && items.length === 0 && <p>No notification destinations configured.</p>}
    {items.map(item => <article className="notification-destination" key={item.id} aria-labelledby={`notification-destination-${item.id}`}>
      <div className="section-heading">
        <div><p className="eyebrow">{item.type === "webhook" ? "HTTPS webhook" : "Other transport"}</p><h3 id={`notification-destination-${item.id}`}>{item.display_name}</h3></div>
        <span className={`state-pill ${item.enabled ? "state-fresh" : "state-disconnected"}`}>{item.enabled ? "enabled" : "disabled"}</span>
      </div>
      {item.configuration.webhook ? <dl className="notification-details">
        <div><dt>Receiver</dt><dd><code>{item.configuration.webhook.https_url}</code></dd></div>
        <div><dt>Request signing</dt><dd>{item.configuration.webhook.hmac_enabled ? "HMAC enabled" : "Not enabled"}</dd></div>
        <div><dt>Credential</dt><dd>{item.secret_configured ? "Configured" : "Not configured"}</dd></div>
        <div><dt>Revision</dt><dd>{item.revision}</dd></div>
      </dl> : <p className="muted">This transport is not editable in the current UI workflow.</p>}
      {lastResult(item)}
      <div className="button-row">
        {canWrite && item.type === "webhook" && <button className="secondary" type="button" disabled={saving || testingID !== null} onClick={() => beginEdit(item)}>Edit</button>}
        {canWrite && item.type === "webhook" && <button type="button" disabled={saving || testingID !== null} onClick={() => void sendTest(item)}>{testingID === item.id ? "Sending test…" : "Send test"}</button>}
      </div>
    </article>)}
    {canWrite ? <button type="button" disabled={saving || testingID !== null} onClick={beginCreate}>{draft?.id === null ? "Close new destination" : "New webhook destination"}</button> : <p className="muted">Viewer access: notification destinations are read-only.</p>}
    {draft && <form onSubmit={save} aria-label={draft.id ? "Edit notification destination" : "New notification destination"}>
      <fieldset disabled={saving}>
        <legend>{draft.id ? "Edit webhook destination" : "New webhook destination"}</legend>
        <label>Destination name<input required value={draft.displayName} onChange={event => setDraft({ ...draft, displayName: event.target.value })} /></label>
        <label>HTTPS receiver URL<input required type="url" inputMode="url" value={draft.url} onChange={event => setDraft({ ...draft, url: event.target.value })} /></label>
        <label><input type="checkbox" checked={draft.hmacEnabled} onChange={event => setDraft({ ...draft, hmacEnabled: event.target.checked })} /> Sign requests with HMAC</label>
        <label>Webhook secret<input type="password" autoComplete="new-password" value={draft.secret} onChange={event => setDraft({ ...draft, secret: event.target.value })} aria-describedby="webhook-secret-help" /></label>
        <p id="webhook-secret-help" className="muted">The secret is stored separately and is never shown in responses or ordinary logs. Leave it blank when retaining an existing signing secret.</p>
        <button type="submit">{saving ? "Saving…" : "Save destination"}</button>
      </fieldset>
      <button className="secondary" type="button" disabled={saving} onClick={() => setDraft(null)}>Cancel</button>
    </form>}
  </section>;
}

function formatDate(value: number) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
