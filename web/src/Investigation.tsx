import { AlertEvidence, AlertStatePanel } from "./AlertEvidence";
import { FormEvent, useEffect, useRef, useState } from "react";
import { ApiError, api, type ComparisonResult, type HistoryScope, type IncidentAnnotation, type IncidentDetail, type IncidentSummary, type MutationAccess } from "./api";

export type InvestigationSelection = {
  scope: HistoryScope;
  startMS: number;
  endMS: number;
  timezone: string;
  fixed: boolean;
};

type RetryAttempt = { signature: string; key: string; timeMS: number };
type IncidentDraft = { note: string; editing: IncidentAnnotation | null; title: string; attempts: Map<string, RetryAttempt>; muteReason?: string; muteExpiry?: string };

// Retain the exact logical request after a lost response. A changed form is a
// new intent; retrying unchanged input preserves its key and declared time.
function mutationAttempt(attempts: Map<string, RetryAttempt>, kind: string, identity: unknown): RetryAttempt {
  const signature = JSON.stringify(identity);
  const previous = attempts.get(kind);
  if (previous?.signature === signature) return previous;
  const next = { signature, key: crypto.randomUUID(), timeMS: Date.now() };
  attempts.set(kind, next);
  return next;
}

export function InvestigationWorkspace({ selection, access, onSessionLost }: { selection: InvestigationSelection | null; access: MutationAccess; onSessionLost: () => void }) {
  const navigation = useRef(0);
  const drafts = useRef(new Map<string, IncidentDraft>());
  const createAttempts = useRef(new Map<string, RetryAttempt>());
  const [selectedNavigation, setSelectedNavigation] = useState(0);
  const [detailMutationBusy, setDetailMutationBusy] = useState(false);
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [selected, setSelected] = useState<IncidentDetail | null>(null);
  const [title, setTitle] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    const initialNavigation = navigation.current;
    void api.incidents(controller.signal).then((response) => {
      setItems(response.items);
      setNextCursor(response.next_cursor);
      setError("");
      const requestedIncident = new URL(window.location.href).searchParams.get("incident");
      if (requestedIncident && navigation.current === initialNavigation) void openIncident(requestedIncident);
    }).catch((requestError) => handleRequestError(requestError, onSessionLost, setError));
    return () => { controller.abort(); navigation.current++; };
  }, [onSessionLost]);

  useEffect(() => {
    if (selection) setTitle(`Investigation · ${selection.scope.display_name}`.slice(0, 160));
  }, [selection?.scope.id, selection?.startMS, selection?.endMS]);

  async function openIncident(id: string) {
    if (busy || detailMutationBusy) return;
    const ticket = ++navigation.current;
    setSelected(null);
    setError("");
    try {
      const detail = await api.incident(id);
      if (ticket !== navigation.current) return;
      setSelected(detail);
      setSelectedNavigation(ticket);
      setIncidentURL(id);
    } catch (requestError) {
      if (ticket === navigation.current) handleRequestError(requestError, onSessionLost, setError);
    }
  }

  async function loadMoreIncidents() {
    if (!nextCursor || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await api.incidents(undefined, nextCursor);
      setItems((current) => [...current, ...response.items.filter((item) => !current.some((existing) => existing.id === item.id))]);
      setNextCursor(response.next_cursor);
    } catch (requestError) {
      handleRequestError(requestError, onSessionLost, setError);
    } finally {
      setBusy(false);
    }
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    if (busy || detailMutationBusy || !selection || !canSave(selection) || access.role !== "admin" || !access.mutationsAllowed) return;
    setBusy(true);
    setSelected(null);
    setError("");
    try {
      const ticket = ++navigation.current;
      const attempt = mutationAttempt(createAttempts.current, "create", [access.generation, title.trim(), selection.scope.kind, selection.scope.id, selection.startMS, selection.endMS]);
      const summary = await api.createIncident(access, title.trim(), { kind: selection.scope.kind, id: selection.scope.id }, selection.startMS, selection.endMS, attempt.key);
      setItems((current) => [summary, ...current.filter((item) => item.id !== summary.id)]);
      let detail: IncidentDetail;
      try {
        detail = await api.incident(summary.id);
      } catch (requestError) {
        if (ticket === navigation.current) {
          handleRequestError(requestError, onSessionLost, () => setError("Investigation saved. Its details could not be loaded; retry the unchanged save to retrieve the same investigation."));
        }
        return;
      }
      createAttempts.current.delete("create");
      if (ticket === navigation.current) {
        setSelected(detail);
        setSelectedNavigation(ticket);
        setIncidentURL(summary.id);
      }
    } catch (requestError) {
      handleRequestError(requestError, onSessionLost, setError);
    } finally {
      setBusy(false);
    }
  }

  const saveAllowed = selection !== null && canSave(selection) && access.role === "admin" && access.mutationsAllowed;
  return (
    <section className="observed-card investigation-workspace" aria-labelledby="investigations">
      <div className="section-heading">
        <div><p className="eyebrow">Durable evidence</p><h2 id="investigations">Saved investigations</h2></div>
        <span className="state-pill state-paused">{selected?.origin === "alert" ? "Alert investigation" : "Manual · no alert state"}</span>
      </div>
      <p>Save an absolute range with its current evidence quality. This records an investigation; it does not create, acknowledge or resolve an alert.</p>
      {access.role === "admin" && selection && (
        <form className="investigation-save" onSubmit={save}>
          <label>Investigation title<input value={title} maxLength={160} onChange={(event) => setTitle(event.target.value)} required /></label>
          <button type="submit" disabled={!saveAllowed || busy || detailMutationBusy || title.trim().length === 0}>{busy ? "Saving evidence…" : "Save selected range"}</button>
          {!selection.fixed && <p className="muted">Choose a fixed historical range before saving evidence.</p>}
          {selection.endMS-selection.startMS > 24*60*60_000 && <p className="muted">A protected trigger capsule supports a five-minute to 24-hour focus window. Choose a shorter range.</p>}
          {!access.mutationsAllowed && <p className="muted">Investigation mutations are paused during recovery.</p>}
        </form>
      )}
      {access.role === "viewer" && <p className="muted">Viewer access can inspect saved evidence. An administrator is required to save a range or edit notes.</p>}
      {error && <p className="warning-inline" role="alert">{error}</p>}
      {items.length === 0 ? <p>No investigation or alert has been saved.</p> : (
        <div className="table-scroll"><table><caption className="sr-only">Saved investigations</caption><thead><tr><th scope="col">Title</th><th scope="col">Focus window</th><th scope="col">Evidence</th><th scope="col">Condition or workflow</th><th scope="col">Open</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td>{item.title}</td><td>{formatTime(item.start_ms)} to {formatTime(item.end_ms)}</td><td>{item.evidence_status}</td><td>{item.origin === "alert" ? `${item.alert_state?.condition ?? "unknown"} · data ${item.alert_state?.data_state ?? "unknown"}` : item.workflow_state}</td><td><button className="secondary" type="button" disabled={busy || detailMutationBusy} onClick={() => void openIncident(item.id)}>View</button></td></tr>)}</tbody></table></div>
      )}
      {nextCursor && <button className="secondary" type="button" disabled={busy} onClick={() => void loadMoreIncidents()}>{busy ? "Loading…" : "Load more investigations"}</button>}
      {detailMutationBusy && <p role="status">Saving this investigation. Navigation resumes when the request completes or times out.</p>}
      {selected && <IncidentView onMutationBusy={setDetailMutationBusy} key={`${selected.id}:${selectedNavigation}`} drafts={drafts.current} incident={selected} access={access} timezone={selection?.timezone ?? "UTC"} onSessionLost={onSessionLost} onBack={() => {
        if (detailMutationBusy) return;
        navigation.current++;
        setSelected(null);
        setIncidentURL(null);
      }} onChange={(next) => {
        if (navigation.current === selectedNavigation) setSelected(next);
        setItems((current) => current.map((item) => item.id === next.id && item.revision <= next.revision ? next : item));
      }} />}
    </section>
  );
}

function IncidentView({ incident, drafts, onMutationBusy, access, timezone, onSessionLost, onBack, onChange }: { onMutationBusy: (busy: boolean) => void; drafts: Map<string, IncidentDraft>; incident: IncidentDetail; access: MutationAccess; timezone: string; onSessionLost: () => void; onBack: () => void; onChange: (incident: IncidentDetail) => void }) {
  const [draft] = useState<IncidentDraft>(() => drafts.get(incident.id) ?? { note: "", editing: null, title: incident.title, attempts: new Map<string, RetryAttempt>() });
  const [note, setNote] = useState(draft.note);
  const [editing, setEditing] = useState<IncidentAnnotation | null>(draft.editing);
  const [incidentTitle, setIncidentTitle] = useState(draft.title);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [muteReason, setMuteReason] = useState(draft.muteReason ?? "");
  const [muteExpiry, setMuteExpiry] = useState(draft.muteExpiry ?? localDateInput(Date.now() + 3600000));
  const [controlMessage, setControlMessage] = useState("");
  const [controlRefreshNeeded, setControlRefreshNeeded] = useState(false);
  const [comparison, setComparison] = useState<ComparisonResult | null>(null);
  const [comparisonBusy, setComparisonBusy] = useState(false);
  const [comparisonError, setComparisonError] = useState("");

  useEffect(() => {
    Object.assign(draft, { note, editing, title: incidentTitle, muteReason, muteExpiry });
    drafts.set(incident.id, draft);
  }, [draft, drafts, incident.id, note, editing, incidentTitle, muteReason, muteExpiry]);

  async function refreshAlert() {
    if (busy) return;
    setBusy(true); onMutationBusy(true); setError("");
    try {
      const current = await api.incident(incident.id);
      onChange({ ...incident, alert_state: current.alert_state, revision: current.revision, workflow_state: current.workflow_state, end_ms: current.end_ms });
      setControlRefreshNeeded(false);
    } catch (cause) {
      handleRequestError(cause, onSessionLost, setError);
    } finally { setBusy(false); onMutationBusy(false); }
  }

  async function alertControl(operation: "acknowledge" | "mute" | "unmute") {
    if (busy || controlRefreshNeeded || !access.mutationsAllowed || access.role !== "admin" || !incident.alert_state) return;
    const expiresMS = new Date(muteExpiry).getTime();
    if (operation === "mute" && (!Number.isFinite(expiresMS) || !muteReason.trim())) return;
    const reviewed = operation === "acknowledge" ? incident.alert_state.transition_seq : operation === "mute" ? [muteReason.trim(), expiresMS] : null;
    const attempt = mutationAttempt(draft.attempts, operation, [access.generation, incident.id, reviewed]);
    setBusy(true); onMutationBusy(true); setError(""); setControlMessage("");
    try {
      const result = operation === "acknowledge" ? await api.acknowledgeIncident(access, incident.id, incident.alert_state.transition_seq, attempt.key)
        : operation === "mute" ? await api.muteIncident(access, incident.id, muteReason.trim(), expiresMS, attempt.key)
        : await api.unmuteIncident(access, incident.id, attempt.key);
      draft.attempts.delete(operation);
      setControlRefreshNeeded(true);
      setControlMessage(`Alert action saved.${result.notification_may_be_in_flight ? " One notification may still arrive." : ""}`);
      try {
        const current = await api.incident(incident.id);
        onChange({ ...incident, alert_state: current.alert_state, revision: current.revision, workflow_state: current.workflow_state, end_ms: current.end_ms });
        setControlRefreshNeeded(false);
      } catch (cause) {
        setControlMessage("Alert action saved. The current state could not be refreshed; use Refresh alert state.");
        handleRequestError(cause, onSessionLost, setError);
      }
    } catch (cause) {
      handleRequestError(cause, onSessionLost, setError);
    } finally { setBusy(false); onMutationBusy(false); }
  }

  async function updateMetadata(update: { title?: string; workflow_state?: "open" | "closed" }) {
    if (access.role !== "admin" || !access.mutationsAllowed || busy) return;
    setBusy(true);
    onMutationBusy(true);
    setError("");
    try {
      const attempt = mutationAttempt(draft.attempts, "metadata", [access.generation, incident.id, incident.revision, update]);
      const summary = await api.updateIncident(access, incident.id, incident.revision, update, attempt.key);
      draft.attempts.delete("metadata");
      draft.title = summary.title;
      setIncidentTitle(summary.title);
      onChange({ ...incident, ...summary });
    } catch (requestError) {
      handleRequestError(requestError, onSessionLost, setError);
    } finally {
      setBusy(false);
      onMutationBusy(false);
    }
  }

  function renameIncident(event: FormEvent) {
    event.preventDefault();
    const nextTitle = incidentTitle.trim();
    if (nextTitle.length === 0 || nextTitle === incident.title) return;
    void updateMetadata({ title: nextTitle });
  }

  async function addNote(event: FormEvent) {
    event.preventDefault();
    if (busy || !access.mutationsAllowed || access.role !== "admin" || note.trim().length === 0) return;
    setBusy(true);
    onMutationBusy(true);
    try {
      const attempt = mutationAttempt(draft.attempts, "add", [access.generation, incident.id, note.trim()]);
      const annotation = await api.createAnnotation(access, incident.id, attempt.timeMS, note.trim(), attempt.key);
      draft.attempts.delete("add");
      draft.note = "";
      onChange({ ...incident, annotations: [...incident.annotations, annotation] });
      setNote("");
      setError("");
    } catch (requestError) {
      handleRequestError(requestError, onSessionLost, setError);
    } finally {
      setBusy(false);
      onMutationBusy(false);
    }
  }

  async function editNote(event: FormEvent) {
    event.preventDefault();
    if (busy || !access.mutationsAllowed || !editing || editing.incident_id !== incident.id || access.role !== "admin" || editing.text.trim().length === 0) return;
    setBusy(true);
    onMutationBusy(true);
    try {
      const attempt = mutationAttempt(draft.attempts, "edit", [access.generation, editing.id, editing.revision, editing.text.trim()]);
      const updated = await api.editAnnotation(access, editing.id, editing.revision, editing.text.trim(), attempt.key);
      draft.attempts.delete("edit");
      draft.editing = null;
      onChange({ ...incident, annotations: incident.annotations.map((item) => item.id === updated.id ? updated : item) });
      setEditing(null);
      setError("");
    } catch (requestError) {
      handleRequestError(requestError, onSessionLost, setError);
    } finally {
      setBusy(false);
      onMutationBusy(false);
    }
  }

  async function loadMoreNotes() {
    if (!incident.annotations_next_cursor || busy) return;
    setBusy(true);
    setError("");
    try {
      const response = await api.incidentAnnotations(incident.id, incident.annotations_next_cursor);
      onChange({
        ...incident,
        annotations: [...incident.annotations, ...response.items.filter((item) => !incident.annotations.some((existing) => existing.id === item.id))],
        annotations_next_cursor: response.next_cursor,
      });
    } catch (requestError) {
      handleRequestError(requestError, onSessionLost, setError);
    } finally {
      setBusy(false);
    }
  }

  async function openComparison(id: string) {
    if (comparisonBusy) return;
    setComparisonBusy(true);
    setComparisonError("");
    try {
      setComparison(await api.comparison(id));
    } catch (cause) {
      if (cause instanceof ApiError && (cause.status === 401 || cause.code === "authentication_required" || cause.code === "session_expired")) onSessionLost();
      else setComparisonError(cause instanceof Error ? cause.message : "The saved comparison could not be loaded.");
    } finally {
      setComparisonBusy(false);
    }
  }

  return (
    <article className="investigation-detail" aria-labelledby={`incident-${incident.id}`}>
      <div className="section-heading"><div><p className="eyebrow">{incident.origin === "manual" ? "Saved manual investigation" : "Alert incident"}</p><h3 id={`incident-${incident.id}`}>{incident.title}</h3></div><span className={`state-pill state-${incident.evidence_status === "expired" ? "stale" : "partial"}`}>{incident.evidence_status} evidence</span></div>
      <button className="secondary" type="button" disabled={busy} onClick={onBack}>Back to investigation list</button>
      {incident.origin === "alert" && <AlertStatePanel state={incident.alert_state} />}
      {incident.origin === "alert" && <>
        <button type="button" disabled={busy} onClick={() => void refreshAlert()}>Refresh alert state</button>
        {access.role === "admin" && incident.alert_state && <fieldset disabled={busy || controlRefreshNeeded || !access.mutationsAllowed}>
          <legend>Alert actions</legend>
          <button type="button" disabled={incident.alert_state.acknowledged_ms !== null} onClick={() => void alertControl("acknowledge")}>Acknowledge alert</button>
          <form onSubmit={event => { event.preventDefault(); void alertControl("mute"); }}>
            <label>Mute reason<input required maxLength={256} value={muteReason} onChange={event => setMuteReason(event.target.value)} /></label>
            <label>Mute expires (local time, within 24 hours)<input required type="datetime-local" value={muteExpiry} onChange={event => setMuteExpiry(event.target.value)} /></label>
            <button type="submit">Mute delivery</button>
          </form>
          <button type="button" disabled={incident.alert_state.muted_until_ms === null} onClick={() => void alertControl("unmute")}>Unmute delivery</button>
        </fieldset>}
        {controlMessage && <p role="status">{controlMessage}</p>}
      </>}
      <p><strong>Workflow:</strong> {incident.workflow_state}. {incident.origin === "manual" ? "Closing marks this manual investigation done; it does not resolve or change an alert condition." : "The observed condition controls resolution. An active alert cannot be manually forced healthy."}</p>
      {incident.origin === "manual" && access.role === "admin" && <div className="investigation-actions">
        <form onSubmit={renameIncident}><label>Rename investigation<input value={incidentTitle} maxLength={160} onChange={(event) => setIncidentTitle(event.target.value)} /></label><button type="submit" disabled={!access.mutationsAllowed || busy || incidentTitle.trim().length === 0 || incidentTitle.trim() === incident.title}>Save title</button></form>
        <button className="secondary" type="button" disabled={!access.mutationsAllowed || busy} onClick={() => void updateMetadata({ workflow_state: incident.workflow_state === "open" ? "closed" : "open" })}>{incident.workflow_state === "open" ? "Close investigation" : "Reopen investigation"}</button>
        {!access.mutationsAllowed && <p className="muted">Investigation mutations are paused during recovery.</p>}
      </div>}
      <p className="muted">{incident.origin === "manual" ? "Original focus" : "Alert episode"} {formatTime(incident.start_ms, timezone)} to {formatTime(incident.end_ms, timezone)} · capsule <code>{incident.capsule_sha256.slice(0, 12)}</code>. This immutable focus is separate from any later chart viewport.</p>
      {incident.capsule === null ? <p className="warning-inline">Trigger evidence expired under the recorded retention policy. The incident metadata and original evidence hash remain.</p> : incident.capsule.schema_revision === "alert-trigger-capsule-1" ? <AlertEvidence capsule={incident.capsule} /> : (
        <>
          <p><strong>Baseline:</strong> {formatTime(incident.capsule.baseline_window.start_ms, timezone)} to {formatTime(incident.capsule.baseline_window.end_ms, timezone)} · <strong>Focus:</strong> {formatTime(incident.capsule.focus_window.start_ms, timezone)} to {formatTime(incident.capsule.focus_window.end_ms, timezone)}</p>
          <div className="evidence-cards">{incident.capsule.cards.map((card) => <section className="evidence-card" key={`${card.card_id}-${card.scope.id}`}><p className="eyebrow">{card.card_id} · {card.eligibility}</p><h4>{card.title}</h4><p>{card.summary}</p><p><strong>Next check:</strong> {card.next_check_label}</p>{card.source_links.length > 0 && <p>{card.source_links.map((link) => <a key={`${link.metric}-${link.start_ms}`} href={sourceLink(link, timezone)}>Open {link.metric} evidence</a>)}</p>}<details><summary>Evidence details</summary><p>Coverage: {card.coverage_ratio === null ? "unavailable" : `${Math.round(card.coverage_ratio*100)}%`} · sources {card.source_ids.length} · gaps {card.gaps.length}</p><p>Reason codes: {card.reason_codes.join(", ") || "none"}</p></details></section>)}</div>
          {incident.capsule.collapsed_card_count > 0 && <p>{incident.capsule.collapsed_card_count} additional bounded card instance(s) were collapsed in this capsule.</p>}
        </>
      )}
      <AttachedComparisons incident={incident} comparison={comparison} busy={comparisonBusy} error={comparisonError} onOpen={openComparison} />
      <section className="investigation-notes" aria-labelledby={`notes-${incident.id}`}><h4 id={`notes-${incident.id}`}>Notes and declared changes</h4><p className="muted">Notes are operator declarations. Do not include prompts, credentials or keys.</p>{incident.annotations.length === 0 ? <p>No note has been recorded.</p> : <ul>{incident.annotations.map((annotation) => <li key={annotation.id}><p>{annotation.text}</p><p className="muted">Declared {formatTime(annotation.declared_time_ms, timezone)}{annotation.edited_ms !== null ? ` · edited ${formatTime(annotation.edited_ms, timezone)}` : ""}</p>{access.role === "admin" && <button className="secondary" type="button" onClick={() => setEditing({ ...annotation })}>Edit note</button>}</li>)}</ul>}
        {incident.annotations_next_cursor && <button className="secondary" type="button" disabled={busy} onClick={() => void loadMoreNotes()}>{busy ? "Loading…" : "Load more notes"}</button>}
        {access.role === "admin" && !editing && <form onSubmit={addNote}><label>Add a plain-text note<textarea value={note} maxLength={2048} onChange={(event) => setNote(event.target.value)} /></label><button type="submit" disabled={!access.mutationsAllowed || busy || note.trim().length === 0}>Add note</button></form>}
        {editing && <form onSubmit={editNote}><label>Edit note<textarea value={editing.text} maxLength={2048} onChange={(event) => setEditing({ ...editing, text: event.target.value })} /></label><div className="button-row"><button type="submit" disabled={!access.mutationsAllowed || busy || editing.text.trim().length === 0}>Save note revision</button><button className="secondary" type="button" onClick={() => setEditing(null)}>Cancel</button></div></form>}
        {error && <p className="warning-inline" role="alert">{error}</p>}
      </section>
    </article>
  );
}

function AttachedComparisons({ incident, comparison, busy, error, onOpen }: { incident: IncidentDetail; comparison: ComparisonResult | null; busy: boolean; error: string; onOpen: (id: string) => void }) {
  const items = incident.comparisons ?? [];
  return <section className="investigation-comparisons" aria-labelledby={`comparisons-${incident.id}`}>
    <h4 id={`comparisons-${incident.id}`}>Attached comparisons</h4>
    {items.length === 0 ? <p className="muted">No comparison is attached to this investigation.</p> : <div className="table-scroll"><table><caption className="sr-only">Saved comparisons attached to this investigation</caption><thead><tr><th scope="col">Metric</th><th scope="col">Runs</th><th scope="col">Status</th><th scope="col">Result</th></tr></thead><tbody>{items.map((item) => <tr key={item.comparison_id}><td>{item.metric_id}</td><td><code>{item.before_run_id.slice(0, 8)}</code> → <code>{item.after_run_id.slice(0, 8)}</code></td><td>{item.status}</td><td><button className="secondary" type="button" disabled={busy} onClick={() => onOpen(item.comparison_id)}>Open comparison</button></td></tr>)}</tbody></table></div>}
    {busy && <p role="status">Loading the saved comparison…</p>}
    {error && <p className="warning-inline" role="alert">{error}</p>}
    {comparison && <div className="comparison-result" aria-live="polite">
      <p><strong>{comparison.status.replaceAll("_", " ")}</strong> · {comparison.metric_id}</p>
      <div className="table-scroll"><table><caption className="sr-only">Comparison summary</caption><thead><tr><th scope="col">Statistic</th><th scope="col">Before</th><th scope="col">After</th></tr></thead><tbody>
        <tr><th scope="row">Valid / completed</th><td>{comparison.before.valid_count} / {comparison.before.completed_count}</td><td>{comparison.after.valid_count} / {comparison.after.completed_count}</td></tr>
        <tr><th scope="row">Minimum</th><td>{comparison.before.summary?.minimum ?? "unavailable"}</td><td>{comparison.after.summary?.minimum ?? "unavailable"}</td></tr>
        <tr><th scope="row">Median</th><td>{comparison.before.summary?.median ?? "unavailable"}</td><td>{comparison.after.summary?.median ?? "unavailable"}</td></tr>
        <tr><th scope="row">Maximum</th><td>{comparison.before.summary?.maximum ?? "unavailable"}</td><td>{comparison.after.summary?.maximum ?? "unavailable"}</td></tr>
        <tr><th scope="row">p95</th><td>{comparison.before.summary?.p95 ?? "unavailable (<100 valid)"}</td><td>{comparison.after.summary?.p95 ?? "unavailable (<100 valid)"}</td></tr>
      </tbody></table></div>
      {comparison.blocked_reasons.length > 0 && <p><strong>Eligibility blockers:</strong> {comparison.blocked_reasons.join(", ")}</p>}
      {comparison.confounds.length > 0 && <p><strong>Confounds:</strong> {comparison.confounds.join(", ")}</p>}
      <p className="muted">Claim scope: {comparison.claim_scope}. Imported values remain operator-declared and unverified.</p>
    </div>}
  </section>;
}

function setIncidentURL(id: string | null) {
  const url = new URL(window.location.href);
  if (id) url.searchParams.set("incident", id);
  else url.searchParams.delete("incident");
  window.history.replaceState(null, "", `${url.pathname}${url.search}${url.hash}`);
}

function canSave(selection: InvestigationSelection) {
  const duration = selection.endMS-selection.startMS;
  return selection.fixed && duration >= 5*60_000 && duration <= 24*60*60_000;
}

function sourceLink(link: { scope_id: string; metric: string; start_ms: number; end_ms: number }, timezone: string) {
  const parameters = new URLSearchParams({ scope: link.scope_id, metric: link.metric, mode: "historical", start: new Date(link.start_ms).toISOString(), end: new Date(link.end_ms).toISOString(), tz: timezone });
  return `?${parameters}`;
}

function handleRequestError(error: unknown, onSessionLost: () => void, setError: (message: string) => void) {
  if (error instanceof ApiError && (error.status === 401 || error.code === "authentication_required" || error.code === "session_expired")) {
    onSessionLost();
    return;
  }
  if (error instanceof ApiError) {
    setError(error.message);
    return;
  }
  setError("The local monitor could not complete the investigation request.");
}

function formatTime(value: number | null, timezone = "UTC") {
  if (value === null) return "ongoing";
  return new Intl.DateTimeFormat(undefined, { timeZone: timezone, dateStyle: "medium", timeStyle: "long" }).format(value);
}

function localDateInput(value: number) {
  const date = new Date(value);
  return new Date(value - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
