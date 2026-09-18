import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, ApiError, type MutationAccess, type Overview, type RuleDefinition, type RuleRecord, type RuleRequestPopulation, type RuleType } from "./api";

type PopulationOption = { label: string; population: RuleRequestPopulation };
const presets: Record<RuleType, { label: string; kind: "host" | "target" | "deployment"; threshold: RuleDefinition["threshold"]; dwell: number; recovery: number; explanation: string }> = {
  ollama_unreachable: { label: "Ollama unreachable", kind: "target", threshold: null, dwell: 30000, recovery: 30000, explanation: "Fires after 30 seconds of failed reachability while the collector is fresh, outside startup grace. Clears after 30 seconds of recovery." },
  host_not_reporting: { label: "Host not reporting", kind: "host", threshold: 60000, dwell: 0, recovery: 30000, explanation: "Fires when the collector heartbeat is at least 60 seconds old. Clears after 30 seconds of reporting." },
  source_missing: { label: "Monitoring source missing", kind: "target", threshold: null, dwell: 30000, recovery: 30000, explanation: "Fires after 30 seconds of missing source evidence while the host reports. Clears after 30 seconds of valid source evidence." },
  memory_pressure: { label: "Memory pressure", kind: "host", threshold: "warning", dwell: 30000, recovery: 60000, explanation: "Fires after 30 seconds of warning pressure, or immediately at critical pressure. Clears after 60 seconds of normal pressure." },
  heavy_cpu: { label: "Heavy CPU", kind: "host", threshold: 0.9, dwell: 60000, recovery: 60000, explanation: "Fires at 90% or higher CPU busy for 60 seconds. Clears below 80% for 60 seconds. Missing observations do not count as recovery." },
  observed_request_duration: { label: "Observed request duration", kind: "target", threshold: 1500, dwell: 0, recovery: 0, explanation: "Evaluates only the selected completed request population. The p95 needs at least 100 valid samples. It does not measure all inference traffic." },
  disk_monitor_health: { label: "Monitor health", kind: "deployment", threshold: 15000, dwell: 30000, recovery: 30000, explanation: "Fires for storage pressure or final delivery failure immediately, or evaluator lag above 15 seconds for 30 seconds. Clears after 30 seconds of healthy evidence." },
};
const durationMetrics = [
  ["request.client.first_byte_ms", "Client first byte"], ["request.client.first_content_ms", "Client first content"],
  ["request.client.total_ms", "Client total"], ["request.runtime.eval_duration_ms", "Runtime generation"],
  ["request.runtime.load_duration_ms", "Runtime model load"], ["request.runtime.prompt_eval_duration_ms", "Runtime prompt evaluation"],
  ["request.runtime.total_duration_ms", "Runtime total"],
];

// Population choices come from retained, explicitly observed request groups.
// The form never invents a population from an Ollama inventory poll.
export function RulesWorkspace({ overview, access, populations = [], onSessionLost }: {
  overview: Overview; access: MutationAccess; populations?: PopulationOption[]; onSessionLost: () => void;
}) {
  const [items, setItems] = useState<RuleRecord[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [draft, setDraft] = useState<RuleDefinition | null>(null);
  const [editingID, setEditingID] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const attempt = useRef<{ signature: string; key: string } | null>(null);
  const active = useRef(true);
  const currentGeneration = useRef(access.generation);
  currentGeneration.current = access.generation;
  const readTicket = useRef(0);
  const canWrite = access.role === "admin" && access.mutationsAllowed;
  function fail(cause: unknown) {
    if (cause instanceof ApiError && cause.status === 401) { onSessionLost(); return; }
    setError(cause instanceof Error ? cause.message : "Alert rules could not be loaded.");
  }
  async function refresh(signal?: AbortSignal) {
    const ticket = ++readTicket.current;
    try {
      const result = await api.rules(signal);
      if (!active.current || signal?.aborted || ticket !== readTicket.current) return;
      setItems(result.items); setLoaded(true); setError("");
    } catch (cause) {
      if (active.current && !signal?.aborted && ticket === readTicket.current) fail(cause);
    }
  }
  useEffect(() => {
    active.current = true;
    setDraft(null); setEditingID(null); setItems([]); setLoaded(false);
    setMessage(""); attempt.current = null;
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => { active.current = false; controller.abort(); ++readTicket.current; };
  }, [access.generation]);
  function options(type: RuleType) {
    if (presets[type].kind === "host") return overview.hosts.map(host => ({ id: host.id, label: host.display_name }));
    if (presets[type].kind === "target") return overview.targets.filter(target => !target.retired).map(target => ({ id: target.id, label: target.display_name }));
    return [{ id: overview.deployment_state.deployment_id, label: "This deployment" }];
  }
  function newDefinition(type: RuleType): RuleDefinition {
    const preset = presets[type];
    return { expected_revision: null, evaluator_type: type, scope_id: options(type)[0]?.id ?? "", enabled: true,
      threshold: preset.threshold, dwell_ms: preset.dwell, recovery_ms: preset.recovery,
      metric_id: type === "observed_request_duration" ? "request.client.total_ms" : null,
      aggregation: type === "observed_request_duration" ? "p95" : null, request_population: null };
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!draft || !canWrite || inFlight.current) return;
    const definition = structuredClone(draft);
    const generation = access.generation;
    const signature = JSON.stringify([access.generation, editingID, definition]);
    if (attempt.current?.signature !== signature) attempt.current = { signature, key: crypto.randomUUID() };
    const key = attempt.current.key;
    inFlight.current = true; setBusy(true); setError(""); setMessage("");
    // Invalidate earlier list responses before the write starts.
    ++readTicket.current;
    try {
      const result = editingID ? await api.updateRule(access, editingID, definition, key) : await api.createRule(access, definition, key);
      if (!active.current || currentGeneration.current !== generation) return;
      attempt.current = null; setDraft(null); setEditingID(null);
      setMessage(`Rule revision ${result.revision} saved. Delivery status is tracked separately.`);
      await refresh();
    } catch (cause) {
      if (active.current && currentGeneration.current === generation) fail(cause);
      // Keep this identity for an ambiguous retry with exactly the same intent.
    } finally {
      inFlight.current = false;
      if (active.current) setBusy(false);
    }
  }
  const selectedPreset = draft ? presets[draft.evaluator_type] : null;
  const populationChoices = populations.filter(option => option.population.target_id === draft?.scope_id);
  if (draft?.request_population && !populationChoices.some(option => JSON.stringify(option.population) === JSON.stringify(draft.request_population))) {
    populationChoices.push({ label: "Saved population (current availability not established)", population: draft.request_population });
  }
  return <section aria-labelledby="alert-rules-heading">
    <div className="section-heading"><h2 id="alert-rules-heading">Alert rules</h2>
      <button type="button" disabled={busy} onClick={() => void refresh()}>Refresh rules</button></div>
    <p>Rules use observed evidence. Condition, acknowledgement, mute and delivery are tracked independently.</p>
    {error && <p role="alert">{error}{draft && " Your unsaved definition is preserved. Retry unchanged input to reuse the same request."}</p>}
    {message && <p role="status">{message}</p>}
    {!loaded && !error && <p role="status">Loading rules…</p>}
    {loaded && items.length === 0 && <p>No alert rules configured.</p>}
    {items.length > 0 && <table><caption>Current rule definitions</caption><thead><tr><th>Rule</th><th>Scope</th><th>Enabled</th><th>Revision</th><th>Definition</th></tr></thead><tbody>
      {items.map(item => <tr key={item.id}><th scope="row">{presets[item.definition.evaluator_type].label}</th><td>{options(item.definition.evaluator_type).find(scope => scope.id === item.definition.scope_id)?.label ?? item.definition.scope_id}</td><td>{item.definition.enabled ? "Yes" : "No"}</td><td>{item.revision}</td><td><button type="button" disabled={busy} onClick={() => { setEditingID(item.id); setDraft({ ...structuredClone(item.definition), expected_revision: item.revision }); setError(""); setMessage(""); }}>{canWrite ? "Edit" : "View"}</button></td></tr>)}
    </tbody></table>}
    {canWrite && <button type="button" disabled={busy} onClick={() => { setEditingID(null); setDraft(newDefinition("memory_pressure")); setError(""); setMessage(""); }}>New rule</button>}
    {!canWrite && <p>{access.role === "viewer" ? "Viewer access: definitions are read-only." : "Rule changes are unavailable during deployment recovery."}</p>}
    {draft && selectedPreset && <form onSubmit={save} aria-label={editingID ? "Rule definition" : "New rule definition"}>
      <fieldset disabled={busy || !canWrite}><legend>{editingID ? "Edit rule" : "Create rule"}</legend>
        <label>Rule type<select value={draft.evaluator_type} onChange={event => setDraft({ ...newDefinition(event.target.value as RuleType), expected_revision: draft.expected_revision })}>{Object.entries(presets).map(([value, preset]) => <option key={value} value={value}>{preset.label}</option>)}</select></label>
        <label>Scope<select required value={draft.scope_id} onChange={event => setDraft({ ...draft, scope_id: event.target.value, request_population: null })}><option value="">Select a scope</option>{options(draft.evaluator_type).map(scope => <option key={scope.id} value={scope.id}>{scope.label}</option>)}</select></label>
        <p>{selectedPreset.explanation}</p>
        {draft.evaluator_type === "observed_request_duration" && <>
          <label>Observed request population<select required value={draft.request_population ? JSON.stringify(draft.request_population) : ""} onChange={event => setDraft({ ...draft, request_population: event.target.value ? JSON.parse(event.target.value) as RuleRequestPopulation : null })}><option value="">Select an observed population</option>{populationChoices.map(option => <option key={JSON.stringify(option.population)} value={JSON.stringify(option.population)}>{option.label}</option>)}</select></label>
          {populationChoices.length === 0 && <p>No retained request populations are available for this scope. Passive polling does not capture request timing.</p>}
          <label>Duration<select value={draft.metric_id ?? ""} onChange={event => setDraft({ ...draft, metric_id: event.target.value })}>{durationMetrics.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
          <label>Statistic<select value={draft.aggregation ?? "p95"} onChange={event => setDraft({ ...draft, aggregation: event.target.value as "p95" | "median" })}><option value="p95">p95</option><option value="median">Median</option></select></label>
          <label>Threshold in milliseconds<input type="number" required min="0" max="120000" step="any" value={typeof draft.threshold === "number" ? draft.threshold : ""} onChange={event => setDraft({ ...draft, threshold: event.target.valueAsNumber })} /></label>
        </>}
        <label><input type="checkbox" checked={draft.enabled} onChange={event => setDraft({ ...draft, enabled: event.target.checked })} />Enabled</label>
        <p>Trigger dwell: {draft.dwell_ms / 1000} seconds. Recovery dwell: {draft.recovery_ms / 1000} seconds.</p>
        {canWrite && <button type="submit" disabled={!draft.scope_id || draft.evaluator_type === "observed_request_duration" && !draft.request_population}>{busy ? "Saving…" : "Save rule"}</button>}
      </fieldset>
      <button type="button" disabled={busy} onClick={() => { setDraft(null); setEditingID(null); }}>Close definition</button>
    </form>}
  </section>;
}
