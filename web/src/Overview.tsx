import { useEffect, useRef, useState } from "react";
import {
  ApiError,
  api,
  type HostOverview,
  type FoundationStatus,
  type HistoryCatalog,
  type HistoryScope,
  type LocalProbeReceipt,
  type MetricReading,
  type MutationAccess,
  type Overview,
  type EnrollmentToken,
  type Series,
  type SourceState,
  type TargetOverview,
  type RequestRun,
} from "./api";
import { InvestigationWorkspace, type InvestigationSelection } from "./Investigation";
import { NotificationsWorkspace } from "./Notifications";
import { RulesWorkspace } from "./Rules";
import { ComparisonsWorkspace } from "./Comparisons";

const metricNames: Record<string, string> = {
  "host.cpu.busy_ratio": "Host CPU busy",
  "host.memory.pressure_level": "Memory pressure",
  "host.memory.compressed_bytes": "Compressed memory",
  "host.memory.swap_used_bytes": "Swap used",
  "host.disk.free_bytes": "Monitor volume available",
  "runtime.reachable": "Runtime reachable",
  "runtime.model.loaded": "Model reported loaded",
  "runtime.model.reported_size_bytes": "Model reported size",
  "runtime.model.reported_size_vram_bytes": "Reported unified-memory placement",
  "process.cpu.busy_ratio": "Process CPU busy",
  "process.physical_footprint_bytes": "Process physical footprint",
};

export function LiveOverview({ initial, initialStatus, mutationAccess, onSessionLost }: { initial: Overview; initialStatus: FoundationStatus; mutationAccess?: MutationAccess; onSessionLost: () => void }) {
  const [overview, setOverview] = useState(initial);
  const [status, setStatus] = useState(initialStatus);
  const [refreshError, setRefreshError] = useState("");
  const [announcement, setAnnouncement] = useState("");
  const [nowMS, setNowMS] = useState(Date.now());
  const requestRef = useRef<AbortController | null>(null);
  const generationRef = useRef(0);
  const stateRef = useRef(initial.state);
  const [investigationSelection, setInvestigationSelection] = useState<InvestigationSelection | null>(null);
  const [rulesOpened, setRulesOpened] = useState(false);
  const [notificationsOpened, setNotificationsOpened] = useState(false);
  const [comparisonsOpened, setComparisonsOpened] = useState(false);

  useEffect(() => {
    let stopped = false;

    async function refresh(includeOverview: boolean) {
      requestRef.current?.abort();
      const controller = new AbortController();
      requestRef.current = controller;
      const generation = ++generationRef.current;
      let next = overview;
      let nextStatus = status;
      try {
        if (includeOverview) [next, nextStatus] = await Promise.all([api.overview(controller.signal), api.status(controller.signal)]);
        if (stopped || generation !== generationRef.current) return;
        if (includeOverview) {
          setOverview(next);
          setStatus(nextStatus);
          setNowMS(Date.now());
          if (next.state !== stateRef.current) {
            setAnnouncement(`Monitor state changed to ${stateLabel(next.state)}.`);
            stateRef.current = next.state;
          }
        }
        if (!stopped && generation === generationRef.current) setRefreshError("");
      } catch (error) {
        if (stopped || generation !== generationRef.current || (error instanceof ApiError && error.code === "request_cancelled")) return;
        if (error instanceof ApiError && (error.status === 401 || error.code === "authentication_required" || error.code === "session_expired")) {
          onSessionLost();
          return;
        }
        setRefreshError("Live data could not be refreshed. The last observed values remain visible with their ages.");
        return;
      }
    }

    void refresh(false);
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void refresh(true);
    }, 5_000);
    const ageTimer = window.setInterval(() => setNowMS(Date.now()), 1_000);
    const refreshVisible = () => {
      if (document.visibilityState === "visible") void refresh(true);
    };
    document.addEventListener("visibilitychange", refreshVisible);
    window.addEventListener("focus", refreshVisible);
    return () => {
      stopped = true;
      window.clearInterval(timer);
      window.clearInterval(ageTimer);
      document.removeEventListener("visibilitychange", refreshVisible);
      window.removeEventListener("focus", refreshVisible);
      requestRef.current?.abort();
    };
  }, [onSessionLost]);

  return (
    <>
      <p className="sr-only" role="status" aria-live="polite">{announcement}</p>
      <ServiceStatus status={status} unknown={refreshError !== ""} />
      {status.experimental_features ? <TrafficBoundary overview={overview} mutationAccess={mutationAccess} onSessionLost={onSessionLost} /> : <p className="preview-note">Same-machine preview · Passive monitoring. No inference requests or application traffic capture.</p>}
      {status.experimental_features && <p className="warning-inline" role="status">Experimental workflows enabled. Remote collection, inference tests, comparisons and notification delivery are not qualified for this preview.</p>}
      <section aria-labelledby="live-overview">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Observed state</p>
            <h2 id="live-overview">Live overview</h2>
          </div>
          <span className={`state-pill state-${refreshError ? "disconnected" : overview.state}`}>{refreshError ? "connection unknown" : stateLabel(overview.state)}</span>
        </div>
        <p className="muted">Updated {formatAge(Math.max(0, nowMS - overview.generated_ms))}. Each value keeps its own observation age and source quality.</p>
        {refreshError && <p className="warning-inline" role="status">{refreshError}</p>}
        <dl className="overview-counts">
          <div><dt>Hosts</dt><dd>{overview.host_count}</dd></div>
          <div><dt>Targets</dt><dd>{overview.target_count}</dd></div>
          <div><dt>Open incidents</dt><dd>{overview.open_incident_count}</dd></div>
          <div><dt>Observed requests</dt><dd>{overview.observed_request_population}</dd></div>
        </dl>
      </section>

      {status.experimental_features && mutationAccess?.role === "admin" && <PairingPanel access={mutationAccess} onSessionLost={onSessionLost} />}
      {overview.hosts.length === 0 ? <EmptyMonitoring /> : overview.hosts.map((host) => <HostCard key={host.id} host={host} nowMS={nowMS} lastKnown={refreshError !== ""} />)}
      {overview.targets.map((target) => <TargetCard key={target.id} target={target} nowMS={nowMS} lastKnown={refreshError !== ""} />)}
      <CapabilityCard overview={overview} />
      {overview.history_available && <HistoryExplorer overview={overview} onSessionLost={onSessionLost} onInvestigationSelection={setInvestigationSelection} />}
      {mutationAccess && <InvestigationWorkspace selection={investigationSelection} access={mutationAccess} onSessionLost={onSessionLost} />}
      {mutationAccess && <details className="card" onToggle={event => { if (event.currentTarget.open) setRulesOpened(true); }}>
        <summary>Alert rules</summary>
        {rulesOpened && <RulesWorkspace overview={overview} access={mutationAccess} onSessionLost={onSessionLost} />}
      </details>}
      {status.experimental_features && mutationAccess && <details className="card" onToggle={event => { if (event.currentTarget.open) setNotificationsOpened(true); }}>
        <summary>Notification destinations</summary>
        {notificationsOpened && <NotificationsWorkspace access={mutationAccess} onSessionLost={onSessionLost} />}
      </details>}
      {status.experimental_features && mutationAccess && <details className="card" onToggle={event => { if (event.currentTarget.open) setComparisonsOpened(true); }}>
        <summary>Compare request runs</summary>
        {comparisonsOpened && <ComparisonsWorkspace access={mutationAccess} onSessionLost={onSessionLost} />}
      </details>}
    </>
  );
}

function TrafficBoundary({ overview, mutationAccess, onSessionLost }: { overview: Overview; mutationAccess?: MutationAccess; onSessionLost: () => void }) {
  const localTarget = overview.targets.find((target) => target.host_local && !target.retired);
  return (
    <section className="observed-card traffic-boundary" aria-labelledby="request-traffic">
      <div className="section-heading"><h2 id="request-traffic">Request traffic</h2><span className="state-pill state-paused">Explicit test only</span></div>
      <p><strong>Application traffic is not captured.</strong> The observed request population is {overview.observed_request_population}. Any request below is one deliberate local smoke request and is retained without prompt or response content.</p>
      <p className="muted">Reachability, a loaded model and process presence are separate observations. Loaded means Ollama reported a model in its inventory; generating is shown only while the bounded request is active.</p>
      {localTarget && mutationAccess?.role === "admin" ? <LocalProbePanel target={localTarget} deploymentID={overview.deployment_state.deployment_id} access={mutationAccess} onSessionLost={onSessionLost} /> : !localTarget ? <p className="warning-inline">The explicit local request is unavailable until this Mac has a current local Ollama target.</p> : <p className="muted">Only an administrator can start the explicit local request.</p>}
    </section>
  );
}

const localProbeProfileSHA256 = "2222222222222222222222222222222222222222222222222222222222222222";
const localProbeBudgetSHA256 = "dc23909f6bc825f96427ae5072bcc7f4fbf184c1e14b14b07d0e90574883f284";

function LocalProbePanel({ target, deploymentID, access, onSessionLost }: { target: TargetOverview; deploymentID: string; access: MutationAccess; onSessionLost: () => void }) {
  const [confirmed, setConfirmed] = useState(false);
  const [running, setRunning] = useState(false);
  const [receipt, setReceipt] = useState<LocalProbeReceipt | null>(null);
  const [run, setRun] = useState<RequestRun | null>(null);
  const [error, setError] = useState("");

  async function execute() {
    if (!confirmed || !access.mutationsAllowed || running) return;
    setRunning(true);
    setReceipt(null);
    setRun(null);
    setError("");
    try {
      const next = await api.runLocalProbe(access, {
        target_id: target.id,
        profile_id: "short_text_v1",
        count: 1,
        load_confirmation: { confirmation: "confirm_load", profile_sha256: localProbeProfileSHA256, displayed_budget_sha256: localProbeBudgetSHA256 },
        confirm_deployment_id: deploymentID,
      }, crypto.randomUUID());
      setReceipt(next);
      if (next.run_id) setRun(await api.probeRun(next.run_id));
    } catch (requestError) {
      if (requestError instanceof ApiError && (requestError.status === 401 || requestError.code === "authentication_required" || requestError.code === "session_expired")) {
        onSessionLost();
        return;
      }
      setError(requestError instanceof ApiError ? requestError.message : "The bounded local request could not be completed.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="local-probe-panel">
      <div className="section-heading"><div><p className="eyebrow">Administrator action</p><h3>One bounded local request</h3></div><span className={`state-pill ${running ? "state-stale" : "state-paused"}`}>{running ? "Generating" : "Ready"}</span></div>
      <p>Target <code>{target.display_name}</code>. The fixed public profile uses context 1024, output limit 64, concurrency 1, temperature 0, seed 7, streaming, thinking disabled, and a 60-second request deadline.</p>
      <p className="muted">The monitor selects only a locally observed, quantized model between 0.5B and 1B parameters. It never substitutes a larger installed model. Profile hash <code>{localProbeProfileSHA256.slice(0, 16)}…</code> · budget hash <code>{localProbeBudgetSHA256.slice(0, 16)}…</code>.</p>
      <label className="probe-confirmation"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} disabled={running || !access.mutationsAllowed} /> I confirm one request may load the selected local model.</label>
      <button type="button" onClick={() => void execute()} disabled={!confirmed || running || !access.mutationsAllowed}>{running ? "Running one bounded request…" : "Run one bounded request"}</button>
      {!access.mutationsAllowed && <p className="warning-inline">Direct requests are paused while the deployment is in recovery.</p>}
      {error && <p className="form-error" role="alert">{error}</p>}
      {receipt && <LocalProbeReceiptView receipt={receipt} run={run} />}
    </div>
  );
}

function LocalProbeReceiptView({ receipt, run }: { receipt: LocalProbeReceipt; run: RequestRun | null }) {
  if (receipt.status === "blocked") {
    return <div className="local-probe-result failure" role="status"><p><strong>Request blocked before submission.</strong> Safe code <code>{receipt.safe_code}</code>.</p><p>Reasons: {receipt.reasons.length === 0 ? "not recorded" : receipt.reasons.map(humanize).join(", ")}.</p><p className="muted">Submitted {receipt.submitted_count} of {receipt.requested_count}; no Ollama generation request was sent and no request sample was retained. The block decision is retained in the local audit.</p></div>;
  }
  if (!run) return <div className="local-probe-result" role="status"><p><strong>{humanize(receipt.status)}.</strong> Loading the retained request outcome…</p></div>;
  const sample = run.samples[0];
  const metrics = sample?.metrics;
  return (
    <div className={receipt.status === "succeeded" ? "local-probe-result" : "local-probe-result failure"} role="status">
      <p><strong>Request outcome: {humanize(receipt.status)}.</strong> The result below is the retained direct capture, not an inference claim beyond this one request.</p>
      <dl className="probe-result-grid">
        <div><dt>Terminal status</dt><dd>{humanize(sample?.terminal_status ?? "unavailable")}</dd></div>
        <div><dt>Done reason</dt><dd>{sample?.done_reason ?? "Unavailable"}</dd></div>
        <div><dt>HTTP status</dt><dd>{sample?.http_status ?? "Unavailable"}</dd></div>
        <div><dt>Elapsed</dt><dd>{formatProbeMetric(metrics?.["request.client.total_ms"])} ms</dd></div>
        <div><dt>First byte</dt><dd>{formatProbeMetric(metrics?.["request.client.first_byte_ms"])} ms</dd></div>
        <div><dt>First content</dt><dd>{formatProbeMetric(metrics?.["request.client.first_content_ms"])} ms</dd></div>
        <div><dt>Runtime total</dt><dd>{formatProbeMetric(metrics?.["request.runtime.total_duration_ms"])} ms</dd></div>
        <div><dt>Runtime load</dt><dd>{formatProbeMetric(metrics?.["request.runtime.load_duration_ms"])} ms</dd></div>
        <div><dt>Prompt tokens</dt><dd>{formatProbeMetric(metrics?.["request.runtime.prompt_tokens"])}</dd></div>
        <div><dt>Output tokens</dt><dd>{formatProbeMetric(metrics?.["request.runtime.output_tokens"])}</dd></div>
      </dl>
      <p className="muted">Run <code>{run.run_id}</code> · model digest <code>{run.population_key.model_digest.slice(0, 16)}…</code> · source {run.source_kind} · {run.verification_state} · content persistence {run.content_persistence}.</p>
      {sample?.safe_error_category && <p className="warning-inline">Safe error category: <code>{sample.safe_error_category}</code>.</p>}
      <p className="muted">Host CPU, memory, freshness, model identity and process observations remain in the cards below; they are not replaced by this request result.</p>
    </div>
  );
}

function formatProbeMetric(value: number | null | undefined) {
  return value === null || value === undefined || !Number.isFinite(value) ? "Unavailable" : value.toFixed(3);
}

type PairingLifecycle = "idle" | "waiting" | "connected" | "expired" | "failed";

function PairingPanel({ access, onSessionLost }: { access: MutationAccess; onSessionLost: () => void }) {
  const [displayName, setDisplayName] = useState("Remote Mac");
  const [reservation, setReservation] = useState<EnrollmentToken | null>(null);
  const [state, setState] = useState<PairingLifecycle>("idle");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!reservation || state !== "waiting") return;
    let stopped = false;
    const poll = async () => {
      try {
        const next = await api.enrollmentStatus(reservation.host_id);
        if (stopped) return;
        setState(next.state);
        setMessage("");
      } catch (error) {
        if (stopped) return;
        if (error instanceof ApiError && (error.status === 401 || error.code === "authentication_required" || error.code === "session_expired")) {
          onSessionLost();
          return;
        }
        setState("failed");
        setMessage("The master could not confirm the pairing state. Retry the command or generate a new one.");
      }
    };
    void poll();
    const timer = window.setInterval(() => void poll(), 2_000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [reservation?.host_id, state, onSessionLost]);

  async function generate(event: React.FormEvent) {
    event.preventDefault();
    if (!access.mutationsAllowed) {
      setMessage("Configuration changes are paused while the deployment is in recovery.");
      return;
    }
    setBusy(true);
    setCopied(false);
    setMessage("");
    try {
      const next = await api.createEnrollment(access, displayName.trim() || "Remote Mac", crypto.randomUUID());
      setReservation(next);
      setState("waiting");
    } catch (error) {
      if (error instanceof ApiError && (error.status === 401 || error.code === "authentication_required" || error.code === "session_expired")) {
        onSessionLost();
        return;
      }
      if (error instanceof ApiError && error.code === "collector_listener_disabled") {
        setMessage("Remote pairing is not enabled on this installation. Set up the Mac as a master first.");
      } else if (error instanceof ApiError && error.code === "host_limit_reached") {
        setMessage("This deployment already has its two supported host slots. Remove or review an existing host before pairing another Mac.");
      } else {
        setMessage("The master could not create a pairing command. Check its status and retry.");
      }
      setState("failed");
    } finally {
      setBusy(false);
    }
  }

  const command = reservation ? `./llm-monitor-install.sh collector --hub-url ${shellQuote(reservation.hub_url)} --pairing-code ${shellQuote(reservation.token)}` : "";
  async function copyCommand() {
    if (!command) return;
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      setMessage("");
    } catch {
      setCopied(false);
      setMessage("Copy is unavailable in this browser. Select the command below manually.");
    }
  }

  return (
    <section className="observed-card pairing-card" aria-labelledby="remote-pairing">
      <div className="section-heading">
        <div><p className="eyebrow">Administrator action</p><h2 id="remote-pairing">Connect another Mac</h2></div>
        <span className={`state-pill pairing-state pairing-${state}`}>{pairingStateLabel(state)}</span>
      </div>
      <p>Generate one command for the other Mac. It uses the verified artifact already transferred there; no source checkout, token file or manual certificate step is needed.</p>
      <form className="pairing-form" onSubmit={generate}>
        <label htmlFor="pairing-display-name">Remote machine name</label>
        <input id="pairing-display-name" value={displayName} maxLength={128} onChange={(event) => setDisplayName(event.target.value)} disabled={busy || !access.mutationsAllowed} />
        <button type="submit" disabled={busy || !access.mutationsAllowed}>{busy ? "Generating pairing command…" : "Generate pairing command"}</button>
      </form>
      {!access.mutationsAllowed && <p className="warning-inline">Pairing is paused until recovery returns to a normal state.</p>}
      {reservation && (
        <div className="pairing-result">
          <p><strong>{pairingStateLabel(state)}.</strong> The reservation expires {new Date(reservation.expires_ms).toLocaleString()}.</p>
          <p className="muted">On the other Mac, run this from the folder containing the package and this installer helper:</p>
          <pre className="pairing-command"><code>{command}</code></pre>
          <div className="button-row"><button className="secondary" type="button" onClick={() => void copyCommand()}>{copied ? "Copied" : "Copy command"}</button><button className="secondary" type="button" onClick={() => { setReservation(null); setState("idle"); setMessage(""); setCopied(false); }}>Generate new command</button></div>
          <p className="muted">The master waits for the other Mac to redeem this one-use code. Connected means the certificate was accepted; it does not mean inference is running.</p>
        </div>
      )}
      {state === "expired" && <p className="warning-inline">This pairing command expired. Generate a new command.</p>}
      {state === "failed" && message && <p className="form-error" role="alert">{message}</p>}
      {state !== "failed" && message && <p className="warning-inline" role="status">{message}</p>}
    </section>
  );
}

function pairingStateLabel(value: PairingLifecycle) {
  return { idle: "Ready", waiting: "Waiting", connected: "Connected", expired: "Expired", failed: "Failed" }[value];
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function ServiceStatus({ status, unknown }: { status: FoundationStatus; unknown: boolean }) {
  return (
    <section aria-labelledby="foundation-status">
      <div className="section-heading">
        <h2 id="foundation-status">Services</h2>
        <span className="muted">{unknown ? "Last checked" : "Checked"} {new Date(status.generated_ms).toLocaleString()}</span>
      </div>
      {unknown && <p className="warning-inline">Current service state is unknown. Showing the last successful check.</p>}
      <dl className="status-grid">
        <div><dt>Hub</dt><dd><span className={`status-dot ${unknown ? "idle" : "ready"}`} aria-hidden="true" />{unknown ? "Last known configured" : "Configured"}</dd></div>
        <div><dt>Collector</dt><dd><span className={`status-dot ${!unknown && status.collector_state === "observing" ? "ready" : "idle"}`} aria-hidden="true" />{unknown ? `Last known ${collectorStatusLabel(status.collector_state).toLowerCase()}` : collectorStatusLabel(status.collector_state)}</dd></div>
        <div><dt>Ollama targets</dt><dd><span className={`status-dot ${!unknown && status.target_state === "reachable" ? "ready" : "idle"}`} aria-hidden="true" />{unknown ? `Last known ${targetStatusLabel(status.target_state).toLowerCase()}` : targetStatusLabel(status.target_state)}</dd></div>
        <div><dt>Storage</dt><dd><span className={`status-dot ${!unknown && status.storage_state === "normal" ? "ready" : "idle"}`} aria-hidden="true" />{unknown ? `Last known ${storageStateLabel(status.storage_state).toLowerCase()}` : storageStateLabel(status.storage_state)}</dd></div>
        <div><dt>Inference requests</dt><dd>{status.inference_started ? "Direct request recorded" : "None sent by LLM Monitor"}</dd></div>
        <div><dt>Alert evaluation</dt><dd>{unknown || !status.evaluator ? "Unknown" : !status.evaluator.started || status.evaluator.last_success_ms === null ? "Awaiting first successful pass" : status.evaluator.last_pass_failed ? "Last pass failed" : status.evaluator.lag_ms > 15000 ? "Delayed" : "Current"}</dd></div>
      </dl>
      {status.evaluator && (status.evaluator.last_pass_failed || status.evaluator.lag_ms > 15000) && <p className="warning-inline" role="status">Alert evaluation needs attention. Last successful pass: {status.evaluator.last_success_ms === null ? "none in this hub session" : new Date(status.evaluator.last_success_ms).toLocaleString()}. A stale alert condition cannot establish recovery.</p>}
    </section>
  );
}

function collectorStatusLabel(value: FoundationStatus["collector_state"]) {
  return {
    not_registered: "Awaiting registration",
    registered_not_observed: "Registered; no observations",
    observing: "Observing",
    stale_or_disconnected: "Registered; data stale or disconnected",
  }[value];
}

function targetStatusLabel(value: FoundationStatus["target_state"]) {
  return {
    none: "None configured",
    reachable: "Reachable",
    unreachable: "Unreachable",
    partial_or_unknown: "Partial or unknown",
  }[value];
}

function storageStateLabel(value: FoundationStatus["storage_state"]) {
  return {
    normal: "Capacity normal",
    warning: "Storage pressure warning",
    optional_jobs_stopped: "Optional storage jobs stopped",
    bulk_ingest_paused: "Metric ingestion paused",
    read_only_enospc: "Read-only after disk full",
  }[value];
}

function EmptyMonitoring() {
  return (
    <section className="empty-card" aria-labelledby="no-target">
      <h2 id="no-target">No Ollama target is configured</h2>
      <p>No collector observations exist yet. LLM Monitor does not load a model or send inference requests during monitoring.</p>
    </section>
  );
}

function HostCard({ host, nowMS, lastKnown }: { host: HostOverview; nowMS: number; lastKnown: boolean }) {
  const networkFailure = host.capabilities_missing.find((missing) => missing.id.startsWith("host.network."));
  return (
	<section className="observed-card" aria-labelledby={`host-${host.id}`}>
      <div className="section-heading">
        <div><p className="eyebrow">{host.local ? "This Mac" : "Remote machine"} · Host</p><h2 id={`host-${host.id}`}>{host.display_name}</h2></div>
        <span className={`state-pill state-${lastKnown ? "disconnected" : host.source_state}`}>{lastKnown ? `last known ${stateLabel(host.source_state)}` : stateLabel(host.source_state)}</span>
      </div>
      <p className="muted">Identity <code>{host.id}</code> · Last observation {host.heartbeat_ms === null ? "unavailable" : formatTimestamp(host.heartbeat_ms, localTimezone())} · collector heartbeat {formatObservedAge(host.heartbeat_ms, nowMS)}.</p>
      <div className="metric-grid">
        {host.metrics.map((metric) => <MetricCard key={metric.metric} metric={metric} nowMS={nowMS} />)}
      </div>

      <details className="observation-details">
        <summary>Process coverage and observed processes</summary>
        {host.process_summary ? (
          <>
            <p><strong>{host.process_summary.coverage} coverage</strong> at {formatObservedAge(host.process_observed_ms, nowMS)}: examined {host.process_summary.examined_pid_count} of {host.process_summary.eligible_pid_count} eligible same-user processes; retained {host.process_summary.retained_process_count}.</p>
            {host.process_summary.permission_denied_count > 0 && <p className="muted">Permission denied for {host.process_summary.permission_denied_count} eligible processes. Totals are partial.</p>}
            <ul className="compact-list">
              {host.process_observations.map((process) => (
                <li key={process.process_key}>
                  <strong>{process.display_basename ?? "Name unavailable"}</strong> · {process.category.replaceAll("_", " ")} · CPU {displayValue(process.cpu_busy_ratio, "ratio")} · footprint {displayValue(process.physical_footprint_bytes, "bytes")}
                </li>
              ))}
            </ul>
          </>
        ) : <p>Process population has not been observed. It is not treated as zero.</p>}
      </details>

      <details className="observation-details">
        <summary>Network counters</summary>
        <p className="muted">Observed {formatObservedAge(host.network_observed_ms, nowMS)}. Counters reset when their epoch changes.</p>
        {host.network_observed_ms === null ? <p>Network interface population has not been observed. It is not treated as empty.</p> : networkFailure && host.network_observations.length === 0 ? <p>The latest network collection attempt did not produce interface counters ({networkFailure.reason.replaceAll("_", " ")}).</p> : host.network_observations.length === 0 ? <p>The latest successful network observation reported no interface counters.</p> : (
          <>
            {networkFailure && <p>The latest network observation retained usable counters, but coverage is partial ({networkFailure.reason.replaceAll("_", " ")}).</p>}
          <ul className="compact-list">
            {host.network_observations.map((network) => (
              <li key={`${network.interface_id}-${network.counter_epoch_id}`}>
                <strong>{network.interface_id}</strong>{network.loopback ? " · loopback" : ""} · received {displayValue(network.received_bytes_total, "bytes")} · sent {displayValue(network.sent_bytes_total, "bytes")}
              </li>
            ))}
          </ul>
          </>
        )}
      </details>
    </section>
  );
}

function MetricCard({ metric, nowMS }: { metric: MetricReading; nowMS: number }) {
  return (
    <div className="metric-card">
      <span className="metric-name">{metricNames[metric.metric] ?? metric.metric}</span>
      <strong className="metric-value">{displayValue(metric.value, metric.unit)}</strong>
      <span className="metric-meta">{metric.missing_reason ? humanize(metric.missing_reason) : metric.quality} · {metric.observed_ms === null ? "observed unavailable" : `observed ${formatTimestamp(metric.observed_ms, localTimezone())}`} · {formatObservedAge(metric.observed_ms, nowMS)}</span>
      <span className="metric-source">{metric.provenance.source} · {humanize(metric.provenance.verification)}</span>
    </div>
  );
}

function TargetCard({ target, nowMS, lastKnown }: { target: TargetOverview; nowMS: number; lastKnown: boolean }) {
  return (
    <section className="observed-card" aria-labelledby={`target-${target.id}`}>
      <div className="section-heading">
        <div><p className="eyebrow">{target.host_local ? "This Mac" : "Remote machine"} · Ollama target</p><h2 id={`target-${target.id}`}>{target.display_name}</h2></div>
        <span className={`state-pill state-${lastKnown ? "disconnected" : target.source_state}`}>{lastKnown ? `last known ${stateLabel(target.source_state)}` : stateLabel(target.source_state)}</span>
      </div>
      <p>Endpoint association: <strong>{humanize(target.association_state)}</strong>. Reachable means the read-only endpoint responded; it does not mean inference succeeded.</p>
      <div className="metric-grid"><MetricCard metric={target.reachable} nowMS={nowMS} /></div>
      <h3>Installed and loaded model identities</h3>
      <p className="muted">State {stateLabel(target.models_state)} · observed {formatObservedAge(target.models_observed_ms, nowMS)}. Loaded is runtime-reported inventory, not active generation.</p>
      {target.models.length === 0 ? <p>{emptyModelMessage(target.models_state)}</p> : (
        <ul className="model-list">
          {target.models.map((model) => (
            <li key={model.id}>
              <strong>{model.alias || "Model identity unavailable"}</strong>
              <span>Digest {model.digest ? model.digest.slice(0, 16) : "unavailable"}</span>
              <span>{model.load_state === "reported_loaded" ? "reported loaded" : model.load_state === "reported_not_loaded" ? "reported not loaded" : "load state unavailable"}</span>
              <span>size {displayValue(model.reported_size_bytes, "bytes")}</span>
              <span>reported unified-memory placement {displayValue(model.reported_size_vram_bytes, "bytes")}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function CapabilityCard({ overview }: { overview: Overview }) {
  if (overview.capabilities_missing.length === 0) return null;
  return (
    <section className="capability-card" aria-labelledby="capability-limitations">
      <h2 id="capability-limitations">Unavailable capabilities</h2>
      <p>These fields remain missing. They are never replaced with zero or an estimate.</p>
      <ul className="compact-list">
        {overview.capabilities_missing.map((capability) => <li key={capability.id}><code>{capability.id}</code> · {humanize(capability.reason)}</li>)}
      </ul>
    </section>
  );
}

type HistoryMode = "live" | "historical";
type HistorySelection = { mode: HistoryMode; windowMS: number; startMS: number; endMS: number };

const historyWindows = [
  { id: "live-5m", label: "Live · 5 minutes", mode: "live" as const, windowMS: 5 * 60_000 },
  { id: "live-1h", label: "Live · 1 hour", mode: "live" as const, windowMS: 60 * 60_000 },
  { id: "past-6h", label: "Fixed · previous 6 hours", mode: "historical" as const, windowMS: 6 * 60 * 60_000 },
  { id: "past-24h", label: "Fixed · previous 24 hours", mode: "historical" as const, windowMS: 24 * 60 * 60_000 },
  { id: "past-7d", label: "Fixed · previous 7 days", mode: "historical" as const, windowMS: 7 * 24 * 60 * 60_000 },
  { id: "past-30d", label: "Fixed · previous 30 days", mode: "historical" as const, windowMS: 30 * 24 * 60 * 60_000 },
];

function HistoryScopeSelect({ scopes, value, onChange }: { scopes: HistoryScope[]; value: string; onChange: (value: string) => void }) {
  return <label>Scope<select aria-label="History scope" value={value} onChange={(event) => onChange(event.target.value)}><option value="" disabled>Select a retained scope</option>{scopes.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.kind.charAt(0).toUpperCase() + candidate.kind.slice(1)} · {candidate.display_name}{candidate.retired ? " (retired)" : ""}</option>)}</select></label>;
}

function historyErrorMessage(error: unknown) {
  if (!(error instanceof ApiError)) return "History could not be refreshed. Any values below are from the last successful range.";
  switch (error.code) {
    case "point_limit_exceeded": return "This range contains too many retained points. Choose a shorter range; the existing query limit remains in force.";
    case "resolution_unavailable": return "This range is unavailable at its required retention tier. Choose a newer or shorter range.";
    case "metric_scope_unavailable": return "This metric was not retained for the selected scope. Choose another metric or historical scope.";
    case "query_timeout":
    case "hub_timeout": return "The bounded history query timed out. Choose a shorter range and retry.";
    case "hub_unreachable": return "The local hub is unreachable. Any values below are from the last successful range.";
    default: return "History could not be refreshed. Any values below are from the last successful range.";
  }
}

function HistoryExplorer({ overview, onSessionLost, onInvestigationSelection }: { overview: Overview; onSessionLost: () => void; onInvestigationSelection: (selection: InvestigationSelection | null) => void }) {
  const initialURL = useRef(new URL(window.location.href));
  const requestedScope = useRef(initialURL.current.searchParams.get("scope"));
  const [catalog, setCatalog] = useState<HistoryCatalog | null>(null);
  const [catalogError, setCatalogError] = useState("");
  const scopes = catalog?.scopes ?? [];
  const [scope, setScope] = useState(requestedScope.current ?? "");
  const selectedScope = scopes.find((candidate) => candidate.id === scope);
  const metricOptions = selectedScope?.metrics ?? [];
  const requestedMetric = useRef(initialURL.current.searchParams.get("metric"));
  const [metric, setMetric] = useState(requestedMetric.current ?? "");
  const [selection, setSelection] = useState(() => historySelectionFromURL(initialURL.current, overview.generated_ms + 1));
  const localTimezone = validTimezone(Intl.DateTimeFormat().resolvedOptions().timeZone) ? Intl.DateTimeFormat().resolvedOptions().timeZone : "UTC";
  const requestedTimezone = initialURL.current.searchParams.get("tz") ?? localTimezone;
  const [timezone, setTimezone] = useState(validTimezone(requestedTimezone) ? requestedTimezone : localTimezone);
  const [series, setSeries] = useState<Series | null>(null);
  const [error, setError] = useState("");
  const [updating, setUpdating] = useState(false);
  const requestRef = useRef<AbortController | null>(null);
  const generationRef = useRef(0);

  useEffect(() => {
	const controller = new AbortController();
	void api.historyCatalog(controller.signal).then((next) => {
		setCatalog(next);
		setCatalogError("");
		if (!requestedScope.current) setScope(next.scopes[0]?.id ?? "");
		else if (!next.scopes.some((candidate) => candidate.id === requestedScope.current)) {
			setCatalogError("The scope saved in this URL is no longer retained. Choose an available historical scope.");
		}
	}).catch((requestError) => {
		if (requestError instanceof ApiError && requestError.code === "request_cancelled") return;
		if (requestError instanceof ApiError && (requestError.status === 401 || requestError.code === "authentication_required" || requestError.code === "session_expired")) {
			onSessionLost();
			return;
		}
		setCatalogError("Historical scopes could not be loaded. Retry after the local hub is reachable.");
	});
	return () => controller.abort();
  }, [onSessionLost]);

  useEffect(() => {
    if (!selectedScope) return;
	if (!metricOptions.includes(metric)) setMetric(metricOptions.includes(requestedMetric.current ?? "") ? requestedMetric.current! : metricOptions[0] ?? "");
  }, [selectedScope?.id, metricOptions.join("\u0000"), metric]);

  const liveEndMS = overview.generated_ms + 1;
  const startMS = selection.mode === "live" ? Math.max(0, liveEndMS - selection.windowMS) : selection.startMS;
  const endMS = selection.mode === "live" ? liveEndMS : selection.endMS;

  useEffect(() => {
    if (!selectedScope || endMS <= startMS) {
      onInvestigationSelection(null);
      return;
    }
    onInvestigationSelection({ scope: selectedScope, startMS, endMS, timezone, fixed: selection.mode === "historical" });
    return () => onInvestigationSelection(null);
  }, [selectedScope?.id, selectedScope?.display_name, selectedScope?.kind, startMS, endMS, timezone, selection.mode, onInvestigationSelection]);

  useEffect(() => {
    if (!selectedScope || !metric || !metricOptions.includes(metric) || endMS <= startMS) return;
    requestRef.current?.abort();
    const controller = new AbortController();
    requestRef.current = controller;
    const generation = ++generationRef.current;
    setUpdating(true);
    setError("");
    void api.series(scope, metric, startMS, endMS, controller.signal).then((next) => {
      if (generation !== generationRef.current) return;
      setSeries(next);
      setUpdating(false);
    }).catch((requestError) => {
      if (generation !== generationRef.current || (requestError instanceof ApiError && requestError.code === "request_cancelled")) return;
      setUpdating(false);
      if (requestError instanceof ApiError && (requestError.status === 401 || requestError.code === "authentication_required" || requestError.code === "session_expired")) {
        onSessionLost();
        return;
      }
      setError(historyErrorMessage(requestError));
    });
    return () => controller.abort();
  }, [scope, selectedScope?.id, metric, metricOptions.join("\u0000"), startMS, endMS, onSessionLost]);

  useEffect(() => {
    const url = new URL(window.location.href);
    url.searchParams.set("scope", scope);
    url.searchParams.set("metric", metric);
    url.searchParams.set("mode", selection.mode);
    url.searchParams.set("window_ms", String(selection.windowMS));
    url.searchParams.set("start", new Date(startMS).toISOString());
    url.searchParams.set("end", new Date(endMS).toISOString());
    url.searchParams.set("tz", timezone);
    window.history.replaceState(null, "", url);
  }, [scope, metric, selection.mode, startMS, endMS, timezone]);

  if (!catalog) {
    return <section className="observed-card" aria-labelledby="history"><h2 id="history">History</h2><p role="status">{catalogError || "Loading retained historical scopes…"}</p></section>;
  }
  if (!selectedScope || metricOptions.length === 0) {
    return <section className="observed-card" aria-labelledby="history"><h2 id="history">History</h2>{catalogError && <p className="warning-inline">{catalogError}</p>}<HistoryScopeSelect scopes={scopes} value={scope} onChange={setScope} /><p>No metric is retained for the selected scope.</p></section>;
  }

  const selectedWindowID = historyWindows.find((candidate) => candidate.mode === selection.mode && candidate.windowMS === selection.windowMS)?.id ?? "custom";
  const chooseWindow = (value: string) => {
    if (value === "custom") return;
    const option = historyWindows.find((candidate) => candidate.id === value);
    if (!option) return;
    const end = overview.generated_ms + 1;
    setSelection({ mode: option.mode, windowMS: option.windowMS, startMS: Math.max(0, end - option.windowMS), endMS: end });
  };
  const chooseScope = (nextScope: string) => {
    const next = scopes.find((candidate) => candidate.id === nextScope);
    setScope(nextScope);
    setCatalogError("");
    if (next && !next.metrics.includes(metric)) setMetric(next.metrics[0] ?? "");
  };
  const changeBoundary = (boundary: "start" | "end", value: string) => {
    const parsed = Date.parse(`${value}Z`);
    if (!Number.isFinite(parsed)) return;
    const nextStart = boundary === "start" ? parsed : selection.startMS;
    const nextEnd = boundary === "end" ? parsed : selection.endMS;
    if (nextEnd <= nextStart || nextEnd-nextStart > 30 * 24 * 60 * 60_000) return;
    setSelection({ mode: "historical", windowMS: nextEnd - nextStart, startMS: nextStart, endMS: nextEnd });
  };

  return (
    <section className="observed-card history-explorer" aria-labelledby="history">
      <div className="section-heading">
        <div><p className="eyebrow">Retained observations</p><h2 id="history">Metric history</h2></div>
        <span className={`state-pill ${selection.mode === "live" ? "state-fresh" : "state-paused"}`}>{selection.mode === "live" ? "Live range" : "Live paused · fixed range"}</span>
      </div>
      <div className="history-controls">
        <HistoryScopeSelect scopes={scopes} value={scope} onChange={chooseScope} />
        <label>Metric<select value={metric} onChange={(event) => setMetric(event.target.value)}>{metricOptions.map((id) => <option key={id} value={id}>{metricNames[id] ?? id}</option>)}</select></label>
        <label>Range<select aria-label="History range" value={selectedWindowID} onChange={(event) => chooseWindow(event.target.value)}>{selectedWindowID === "custom" && <option value="custom">Fixed · custom range</option>}{historyWindows.map((window) => <option key={window.id} value={window.id}>{window.label}</option>)}</select></label>
        <label>Timezone<select value={timezone} onChange={(event) => setTimezone(event.target.value)}>{timezone !== localTimezone && timezone !== "UTC" && <option value={timezone}>{timezone}</option>}<option value={localTimezone}>{localTimezone}</option>{localTimezone !== "UTC" && <option value="UTC">UTC</option>}</select></label>
      </div>
      {selection.mode === "historical" && <div className="history-boundaries"><label>Start (UTC)<input type="datetime-local" step="1" value={dateTimeInput(selection.startMS)} onChange={(event) => changeBoundary("start", event.target.value)} /></label><label>End (UTC)<input type="datetime-local" step="1" value={dateTimeInput(selection.endMS)} onChange={(event) => changeBoundary("end", event.target.value)} /></label><p className="muted">Custom fixed ranges may span up to 30 days. Times below are displayed in the selected timezone.</p></div>}
      <p className="muted">Requested {formatTimestamp(startMS, timezone)} to {formatTimestamp(endMS, timezone)}. The URL preserves this host, metric, range, and timezone.</p>
      {catalog.truncated && <p className="warning-inline">The retained scope catalog reached its bounded limit. Narrower historical identities may not appear here.</p>}
      {error && <p className="warning-inline" role="status">{error}</p>}
      {!series ? <p role="status">{error ? "No retained series is available for this view." : "Loading retained observations…"}</p> : (
        <>
          <div className={updating ? "history-result history-updating" : "history-result"} aria-busy={updating}>
          {updating && <p className="history-update-note" role="status">Updating this range. Previous observations remain visible.</p>}
          <p><strong>Data quality:</strong> coverage {series.coverage_ratio === null ? "unavailable" : `${Math.round(series.coverage_ratio * 100)}%`} · resolution {series.resolution_tier ?? "unavailable"} · {series.gaps.length} explicit gap{series.gaps.length === 1 ? "" : "s"}. Values are never filled across gaps.</p>
          {series.effective_range ? <p className="muted">Retained observations in this selection run from {formatTimestamp(series.effective_range.start_ms, timezone)} to {formatTimestamp(series.effective_range.end_ms, timezone)}.</p> : <p className="muted">No retained observation interval exists inside this selection.{catalog.earliest_retained_ms !== null && endMS <= catalog.earliest_retained_ms ? ` The earliest retained observation is ${formatTimestamp(catalog.earliest_retained_ms, timezone)}.` : ""} Review the explicit gap reasons or choose another range.</p>}
          {series.warnings.map((warning) => <p className="warning-inline" key={warning}>{warning}</p>)}
          <SeriesChart series={series} timezone={timezone} />
          <SeriesTable series={series} timezone={timezone} />
          <GapTable series={series} timezone={timezone} />
          <details className="observation-details"><summary>Definition and provenance</summary><dl className="series-provenance"><div><dt>Definition</dt><dd>{series.definition_revision}</dd></div><div><dt>Method</dt><dd>{series.method_revision ?? "Unavailable"}</dd></div><div><dt>Clock</dt><dd>{series.clock_method ? humanize(series.clock_method) : "Unavailable"}</dd></div><div><dt>Source</dt><dd>{series.source_id ?? "Unavailable"}</dd></div></dl></details>
          </div>
        </>
      )}
    </section>
  );
}

function SeriesChart({ series, timezone }: { series: Series; timezone: string }) {
  const valid = series.points.map((point) => ({ point, value: chartValue(point.value, series.unit) })).filter((entry): entry is { point: Series["points"][number]; value: number } => entry.value !== null && entry.point.missing_reason === null);
  if (valid.length === 0) return <div className="history-empty"><p>No measured values were retained in this range. Missing observations remain explicit below.</p></div>;
  const start = series.requested_range.start_ms;
  const end = series.requested_range.end_ms;
  const values = valid.map((entry) => entry.value);
  const minimum = Math.min(...values);
  const maximum = Math.max(...values);
  const span = maximum - minimum || 1;
  const x = (time: number) => 42 + ((time - start) / Math.max(1, end - start)) * 716;
  const y = (value: number) => 188 - ((value - minimum) / span) * 150;
  const segments: Array<Array<{ point: Series["points"][number]; value: number }>> = [];
  for (const entry of valid) {
    const previous = segments.at(-1)?.at(-1);
    const crossesGap = previous && series.gaps.some((gap) => gap.start_ms < entry.point.time_ms && gap.end_ms > previous.point.time_ms);
    const crossesMissing = previous && series.points.some((point) => point.time_ms > previous.point.time_ms && point.time_ms < entry.point.time_ms && (point.value === null || point.missing_reason !== null));
    const changesEpoch = previous && previous.point.epoch_id !== entry.point.epoch_id;
    if (!previous || crossesGap || crossesMissing || changesEpoch) segments.push([entry]); else segments.at(-1)!.push(entry);
  }
  return (
    <figure className="series-chart">
      <svg viewBox="0 0 800 230" role="img" aria-labelledby="series-chart-title series-chart-description">
        <title id="series-chart-title">{metricNames[series.metric] ?? series.metric} history</title>
        <desc id="series-chart-description">{valid.length} measured points from {formatTimestamp(start, timezone)} to {formatTimestamp(end, timezone)}, with {series.gaps.length} explicit gaps. Lines stop at gaps.</desc>
        <line x1="42" x2="758" y1="188" y2="188" className="chart-axis" />
        {series.gaps.map((gap, index) => <rect key={`${gap.start_ms}-${index}`} x={x(gap.start_ms)} y="28" width={Math.max(2, x(gap.end_ms) - x(gap.start_ms))} height="160" className="chart-gap" />)}
        {segments.map((segment, index) => <polyline key={index} points={segment.map((entry) => `${x(entry.point.time_ms)},${y(entry.value)}`).join(" ")} className="chart-line" />)}
        {valid.map((entry) => <circle key={`${entry.point.time_ms}-${entry.point.epoch_id ?? "none"}`} cx={x(entry.point.time_ms)} cy={y(entry.value)} r="3.5" className="chart-point"><title>{formatTimestamp(entry.point.time_ms, timezone)} · {displayValue(entry.point.value, series.unit)} · {entry.point.quality}</title></circle>)}
      </svg>
      <figcaption>{chartAxisDisplay(minimum, series.unit)} to {chartAxisDisplay(maximum, series.unit)} in returned observations. Shaded bands are explicit gaps.{series.unit === "bytes" ? " Chart positions use a bounded graphical conversion; the table preserves each exact decimal byte value." : ""}</figcaption>
    </figure>
  );
}

function SeriesTable({ series, timezone }: { series: Series; timezone: string }) {
  const [descending, setDescending] = useState(true);
  const [page, setPage] = useState(0);
  const pageSize = 25;
  useEffect(() => setPage(0), [series, descending]);
  const ordered = [...series.points].sort((a, b) => descending ? b.time_ms - a.time_ms : a.time_ms - b.time_ms);
  const pageCount = Math.max(1, Math.ceil(ordered.length / pageSize));
  const visible = ordered.slice(page * pageSize, (page + 1) * pageSize);
  return (
    <div className="history-table-section">
      <div className="table-heading"><h3>Returned observations</h3><button className="secondary" type="button" onClick={() => setDescending((value) => !value)}>Time {descending ? "newest first" : "oldest first"}</button></div>
      {ordered.length === 0 ? <p>No observation points were retained for this range. The explicit gaps below state what the monitor can establish; this view does not infer zero activity.</p> : <div className="table-scroll"><table><caption className="sr-only">Returned metric observations</caption><thead><tr><th scope="col">Observed</th><th scope="col">Value</th><th scope="col">Unit</th><th scope="col">Quality</th><th scope="col">Provenance</th><th scope="col">Epoch</th></tr></thead><tbody>{visible.map((point, index) => <tr key={`${point.time_ms}-${index}`}><td>{formatTimestamp(point.time_ms, timezone)}</td><td>{point.value === null ? "Unavailable" : String(point.value)}</td><td>{series.unit}</td><td>{point.missing_reason ? humanize(point.missing_reason) : humanize(point.quality)}</td><td>{series.method_revision ?? "Unavailable"}</td><td><code>{point.epoch_id ?? "Unavailable"}</code></td></tr>)}</tbody></table></div>}
      {ordered.length > pageSize && <div className="pagination"><button className="secondary" type="button" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous</button><span>Page {page + 1} of {pageCount}</span><button className="secondary" type="button" disabled={page + 1 >= pageCount} onClick={() => setPage((value) => value + 1)}>Next</button></div>}
    </div>
  );
}

function GapTable({ series, timezone }: { series: Series; timezone: string }) {
  if (series.gaps.length === 0) return <p>No explicit gaps were returned for this range.</p>;
  return <details className="observation-details"><summary>{series.gaps.length} explicit data gap{series.gaps.length === 1 ? "" : "s"}</summary><div className="table-scroll"><table><caption className="sr-only">Explicit missing data ranges</caption><thead><tr><th scope="col">Start</th><th scope="col">End</th><th scope="col">Duration</th><th scope="col">Reason</th></tr></thead><tbody>{series.gaps.map((gap, index) => <tr key={`${gap.start_ms}-${index}`}><td>{formatTimestamp(gap.start_ms, timezone)}</td><td>{formatTimestamp(gap.end_ms, timezone)}</td><td>{formatDuration(gap.end_ms - gap.start_ms)}</td><td>{humanize(gap.reason)}</td></tr>)}</tbody></table></div></details>;
}

function displayValue(value: number | boolean | string | null, unit: string) {
  if (value === null) return "Unavailable";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (unit === "bytes" && typeof value === "string" && /^\d+$/.test(value)) value = Number(value);
  if (typeof value === "number") {
    if (unit === "ratio") return `${(value * 100).toFixed(1)}%`;
    if (unit === "bytes") {
      const units = ["B", "KiB", "MiB", "GiB", "TiB"];
      const index = value > 0 ? Math.min(4, Math.floor(Math.log(value) / Math.log(1024))) : 0;
      return `${(value / 1024 ** index).toFixed(index === 0 ? 0 : 2)} ${units[index]}`;
    }
    return `${Number(value.toFixed(2))} ${unit}`;
  }
  return unit === "state" ? humanize(value) : `${value} ${unit}`;
}

function formatObservedAge(observedMS: number | null, nowMS: number) {
  return observedMS === null ? "not observed" : `${formatAge(Math.max(0, nowMS - observedMS))} ago`;
}

function formatAge(value: number) {
  if (value < 1_000) return "just now";
  if (value < 60_000) return `${Math.floor(value / 1_000)}s`;
  return `${Math.floor(value / 60_000)}m`;
}

function humanize(value: string) {
  return value.replaceAll("_", " ");
}

function stateLabel(value: SourceState) {
  return humanize(value);
}

function historySelectionFromURL(url: URL, fallbackEndMS: number): HistorySelection {
  const mode = url.searchParams.get("mode");
  const startMS = Date.parse(url.searchParams.get("start") ?? "");
  const endMS = Date.parse(url.searchParams.get("end") ?? "");
  const maximumWindow = 30 * 24 * 60 * 60_000;
  if (mode === "historical" && Number.isFinite(startMS) && Number.isFinite(endMS) && endMS > startMS && endMS - startMS <= maximumWindow) {
    return { mode, windowMS: endMS - startMS, startMS, endMS };
  }
  const requestedWindow = Number(url.searchParams.get("window_ms"));
  const windowMS = historyWindows.some((window) => window.mode === "live" && window.windowMS === requestedWindow) ? requestedWindow : 5 * 60_000;
  return { mode: "live", windowMS, startMS: Math.max(0, fallbackEndMS - windowMS), endMS: fallbackEndMS };
}

function validTimezone(value: string) {
  try {
    new Intl.DateTimeFormat("en", { timeZone: value }).format(0);
    return true;
  } catch {
    return false;
  }
}

function formatTimestamp(value: number, timezone: string) {
  return new Intl.DateTimeFormat(undefined, {
    timeZone: timezone,
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "shortOffset",
  }).format(value);
}

function localTimezone() {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

function dateTimeInput(value: number) {
  return new Date(value).toISOString().slice(0, 19);
}

function formatDuration(value: number) {
  if (value < 60_000) return `${Math.max(0, Math.round(value / 1_000))} seconds`;
  if (value < 60 * 60_000) return `${Math.round(value / 60_000)} minutes`;
  if (value < 24 * 60 * 60_000) return `${Math.round(value / (60 * 60_000))} hours`;
  return `${Math.round(value / (24 * 60 * 60_000))} days`;
}

function chartValue(value: number | boolean | string | null, unit: string) {
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "boolean") return value ? 1 : 0;
  if (unit === "bytes" && typeof value === "string" && /^(0|[1-9][0-9]{0,19})$/.test(value)) {
    try {
      if (BigInt(value) > 18_446_744_073_709_551_615n) return null;
      const graphical = Number(value);
      return Number.isFinite(graphical) ? graphical : null;
    } catch {
      return null;
    }
  }
  if (unit === "state" && typeof value === "string") {
    return ({ normal: 0, warning: 1, critical: 2 } as Record<string, number>)[value] ?? null;
  }
  return null;
}

function chartAxisDisplay(value: number, unit: string) {
  if (unit === "boolean") return value === 0 ? "No" : "Yes";
  if (unit === "state") return ["normal", "warning", "critical"][value] ?? "unknown";
  return displayValue(value, unit);
}

function emptyModelMessage(state: SourceState) {
  if (state === "fresh" || state === "stale") {
    return `No model was reported loaded by the ${state === "fresh" ? "latest" : "last retained"} successful inventory.`;
  }
  return `Model inventory is ${stateLabel(state)}. An empty model population cannot be inferred.`;
}
