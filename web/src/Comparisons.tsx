import { useEffect, useRef, useState, type ChangeEvent } from "react";
import { ApiError, api, type ComparisonJob, type ComparisonResult, type IncidentSummary, type MutationAccess, type RequestComparison } from "./api";

const importLimit = 8 * 1024 * 1024;
const metricOptions = [
  ["request.client.first_byte_ms", "Client first byte"],
  ["request.client.first_content_ms", "Client first content"],
  ["request.client.total_ms", "Client total"],
  ["request.runtime.total_duration_ms", "Runtime total"],
  ["request.runtime.load_duration_ms", "Runtime load"],
  ["request.runtime.prompt_eval_duration_ms", "Runtime prompt eval"],
  ["request.runtime.eval_duration_ms", "Runtime eval"],
  ["request.runtime.prompt_tokens", "Prompt tokens"],
  ["request.runtime.output_tokens", "Output tokens"],
] as const;

type ImportedRun = {
  fileName: string;
  input: Record<string, unknown>;
  run: Record<string, unknown>;
  importedJob: ComparisonJob;
};

export function ComparisonsWorkspace({ access, onSessionLost }: { access: MutationAccess; onSessionLost: () => void }) {
  const [files, setFiles] = useState<[File | null, File | null]>([null, null]);
  const [runs, setRuns] = useState<ImportedRun[]>([]);
  const [importing, setImporting] = useState<number | null>(null);
  const [importError, setImportError] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [beforeID, setBeforeID] = useState("");
  const [afterID, setAfterID] = useState("");
  const [metric, setMetric] = useState("request.client.total_ms");
  const [result, setResult] = useState<ComparisonResult | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedJob, setSavedJob] = useState<ComparisonJob | null>(null);
  const [incidentID, setIncidentID] = useState("");
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [attached, setAttached] = useState(false);
  const attempts = useRef(new Map<string, string>());

  const selectedBefore = runs.find((item) => item.run.run_id === beforeID);
  const selectedAfter = runs.find((item) => item.run.run_id === afterID);
  const canCompare = Boolean(selectedBefore && selectedAfter && beforeID !== afterID && access.role !== undefined);
  const canWrite = access.role === "admin" && access.mutationsAllowed;

  useEffect(() => {
    setRuns([]);
    setFiles([null, null]);
    setBeforeID("");
    setAfterID("");
    setResult(null);
    setSavedJob(null);
    setIncidentID("");
    setAttached(false);
    setError("");
    setNotice("");
    const controller = new AbortController();
    void api.incidents(controller.signal).then((response) => setIncidents(response.items)).catch((cause) => {
      if (cause instanceof ApiError && (cause.status === 401 || cause.code === "authentication_required" || cause.code === "session_expired")) onSessionLost();
    });
    return () => controller.abort();
  }, [access.generation, onSessionLost]);

  function chooseFile(index: number, event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0] ?? null;
    setFiles((current) => { const next: [File | null, File | null] = [...current] as [File | null, File | null]; next[index] = file; return next; });
    setImportError("");
  }

  async function importFile(index: number) {
    const file = files[index];
    if (!file || importing !== null) return;
    setImporting(index);
    setImportError("");
    setError("");
    setNotice("");
    try {
      if (file.size > importLimit) throw new Error("The normalized import is larger than 8 MiB.");
      const bytes = new Uint8Array(await file.arrayBuffer());
      const input = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
      const run = input.run;
      if (!isSafeImportShape(input) || typeof run !== "object" || run === null) throw new Error("Choose a complete content-free request-run envelope.");
      const runRecord = run as Record<string, unknown>;
      const secretLike = JSON.stringify(input).match(/"(?:prompt|answer|secret|credential|content)"\s*:/i);
      if (secretLike) throw new Error("Prompt, answer, credential and content fields are not accepted.");
      const runID = typeof runRecord.run_id === "string" ? runRecord.run_id : "";
      if (!runID || runs.some((item) => item.run.run_id === runID)) throw new Error("This run is already loaded or its identity is missing.");
      const original = typeof input.original_artifact_sha256 === "string" ? input.original_artifact_sha256 : "";
      if (!/^[0-9a-f]{64}$/.test(original)) throw new Error("The envelope must include its original artifact SHA-256.");
      const key = `${access.generation}:${runID}:${original}`;
      const retryKey = attempts.current.get(key) ?? crypto.randomUUID();
      attempts.current.set(key, retryKey);
      const importedJob = await api.importProbe(access, input, retryKey);
      attempts.current.delete(key);
      const imported: ImportedRun = { fileName: file.name, input, run: runRecord, importedJob };
      setRuns((current) => [...current, imported]);
      if (!beforeID) setBeforeID(runID);
      else if (!afterID && beforeID !== runID) setAfterID(runID);
      setNotice(`Imported run ${runID.slice(0, 8)}. Values remain operator-declared and unverified.`);
    } catch (cause) {
      if (cause instanceof ApiError && (cause.status === 401 || cause.code === "authentication_required" || cause.code === "session_expired")) onSessionLost();
      else setImportError(cause instanceof Error ? cause.message : "The request-run import could not be accepted.");
    } finally {
      setImporting(null);
    }
  }

  async function preview() {
    if (!canCompare || !selectedBefore || !selectedAfter) return;
    setError("");
    setNotice("");
    try {
	  const next = await api.previewComparison({ comparison_kind: "request_run", scope_id: String(selectedBefore.run.target_id), metric_id: metric, before_run_id: beforeID, after_run_id: afterID });
      setResult(next);
      setSavedJob(null);
      setAttached(false);
    } catch (cause) {
      handleComparisonError(cause, onSessionLost, setError);
    }
  }

  async function save() {
    if (!result || result.blocked_reasons.length > 0 || !canWrite || saving || !selectedBefore) return;
    setSaving(true);
    setError("");
	  const request: RequestComparison = { comparison_kind: "request_run", scope_id: String(selectedBefore.run.target_id), metric_id: metric, before_run_id: beforeID, after_run_id: afterID, declared_intervention: null };
    const identity = JSON.stringify([access.generation, request]);
    const retryKey = attempts.current.get(identity) ?? crypto.randomUUID();
    attempts.current.set(identity, retryKey);
    try {
      const job = await api.createComparison(access, request, retryKey);
      attempts.current.delete(identity);
      setSavedJob(job);
      if (job.result?.resource_id) setResult(await api.comparison(job.result.resource_id));
      setNotice(`Comparison saved for 30 days. It remains explicitly observed evidence and makes no causal claim.`);
      if (incidents.length === 0) {
        const response = await api.incidents();
        setIncidents(response.items);
      }
    } catch (cause) {
      handleComparisonError(cause, onSessionLost, setError);
    } finally {
      setSaving(false);
    }
  }

  async function attach() {
    if (!savedJob?.result?.resource_id || !incidentID || !canWrite || attached) return;
    setError("");
    try {
      await api.attachComparison(access, incidentID, savedJob.result.resource_id, crypto.randomUUID());
      setAttached(true);
      setNotice("Comparison attached. Reopen the investigation to see its saved provenance and retention state.");
    } catch (cause) {
      handleComparisonError(cause, onSessionLost, setError);
    }
  }

  return <section className="observed-card comparison-workspace" aria-labelledby="comparison-heading">
    <div className="section-heading"><div><p className="eyebrow">Content-free evidence</p><h2 id="comparison-heading">Compare request runs</h2></div><span className="state-pill state-paused">No inference</span></div>
    <p>Import two bounded normalized summaries, preview eligibility, then save and attach the observed comparison. Imported values stay operator-declared and unverified; prompts, answers and secrets are never accepted.</p>
    <div className="comparison-import-grid">
      {[0, 1].map((index) => <div className="comparison-import" key={index}>
        <label htmlFor={`comparison-file-${index}`}>{index === 0 ? "Before run file" : "After run file"}<input id={`comparison-file-${index}`} type="file" accept="application/json,.json" onChange={(event) => chooseFile(index, event)} /></label>
        {files[index] && <p className="muted">{files[index]?.name} · {Math.round((files[index]?.size ?? 0) / 1024)} KiB</p>}
        <button type="button" disabled={!files[index] || importing !== null || !canWrite} onClick={() => void importFile(index)}>{importing === index ? "Validating and importing…" : "Validate and import"}</button>
      </div>)}
    </div>
    <p className="muted">The hub admits one new import per minute. A rate-limit response is actionable; wait for the indicated retry window instead of resubmitting different evidence.</p>
    {importError && <p className="form-error" role="alert">{importError}</p>}
    {notice && <p className="notice" role="status">{notice}</p>}
    {runs.length > 0 && <div className="table-scroll"><table><caption className="sr-only">Imported request runs</caption><thead><tr><th scope="col">Role</th><th scope="col">Run</th><th scope="col">Host</th><th scope="col">Completed</th><th scope="col">Provenance</th></tr></thead><tbody>{runs.map((item) => <tr key={String(item.run.run_id)}><th scope="row">{item.run.run_id === beforeID ? "Before" : item.run.run_id === afterID ? "After" : "Available"}</th><td><code>{String(item.run.run_id)}</code></td><td><code>{String(item.run.host_id)}</code></td><td>{String(item.run.completed_count ?? 0)} / {String(item.run.submitted_count ?? 0)}</td><td>operator-declared / unverified</td></tr>)}</tbody></table></div>}
    <div className="comparison-selection">
      <label>Before run<select value={beforeID} onChange={(event) => setBeforeID(event.target.value)}><option value="">Select a run</option>{runs.map((item) => <option key={`before-${String(item.run.run_id)}`} value={String(item.run.run_id)}>{String(item.run.run_id).slice(0, 12)} · host {String(item.run.host_id).slice(0, 8)}</option>)}</select></label>
      <label>After run<select value={afterID} onChange={(event) => setAfterID(event.target.value)}><option value="">Select a run</option>{runs.map((item) => <option key={`after-${String(item.run.run_id)}`} value={String(item.run.run_id)}>{String(item.run.run_id).slice(0, 12)} · host {String(item.run.host_id).slice(0, 8)}</option>)}</select></label>
      <label>Metric<select value={metric} onChange={(event) => setMetric(event.target.value)}>{metricOptions.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
    </div>
    {selectedBefore && selectedAfter && selectedBefore.run.target_id !== selectedAfter.run.target_id && <p className="warning-inline" role="alert">These runs use different targets. Preview will explain the population mismatch and will not pool them.</p>}
    <button type="button" disabled={!canCompare || !canWrite && access.role === "admin" && !access.mutationsAllowed} onClick={() => void preview()}>Preview eligibility</button>
    {result && <ComparisonPreview result={result} />}
    {error && <p className="form-error" role="alert">{error}</p>}
    {result && result.blocked_reasons.length === 0 && <div className="comparison-save"><button type="button" disabled={!canWrite || saving} onClick={() => void save()}>{saving ? "Saving comparison…" : "Save comparison"}</button>{access.role === "viewer" && <p className="muted">Viewer previews are non-persisting. An administrator is required to save or attach.</p>}</div>}
    {savedJob?.result?.resource_id && <div className="comparison-attach"><p role="status">Saved comparison <code>{savedJob.result.resource_id}</code> · retention expires in 30 days.</p><label>Attach to investigation<select value={incidentID} onChange={(event) => setIncidentID(event.target.value)}><option value="">Select an investigation</option>{incidents.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label><button type="button" disabled={!incidentID || !canWrite || attached} onClick={() => void attach()}>{attached ? "Attached" : "Attach comparison"}</button></div>}
  </section>;
}

function ComparisonPreview({ result }: { result: ComparisonResult }) {
  return <section className="comparison-preview" aria-labelledby="comparison-eligibility"><h3 id="comparison-eligibility">Eligibility: {result.status.replaceAll("_", " ")}</h3><div className="table-scroll"><table><caption className="sr-only">Before and after request summary</caption><thead><tr><th scope="col">Measurement</th><th scope="col">Before</th><th scope="col">After</th></tr></thead><tbody>
    <tr><th scope="row">Completed / valid</th><td>{result.before.completed_count} / {result.before.valid_count}</td><td>{result.after.completed_count} / {result.after.valid_count}</td></tr>
    <tr><th scope="row">Failed / cancelled / incomplete</th><td>{result.before.failed_count} / {result.before.cancelled_count} / {result.before.incomplete_count}</td><td>{result.after.failed_count} / {result.after.cancelled_count} / {result.after.incomplete_count}</td></tr>
    <tr><th scope="row">Minimum</th><td>{result.before.summary?.minimum ?? "unavailable"}</td><td>{result.after.summary?.minimum ?? "unavailable"}</td></tr>
    <tr><th scope="row">Median</th><td>{result.before.summary?.median ?? "unavailable"}</td><td>{result.after.summary?.median ?? "unavailable"}</td></tr>
    <tr><th scope="row">Maximum</th><td>{result.before.summary?.maximum ?? "unavailable"}</td><td>{result.after.summary?.maximum ?? "unavailable"}</td></tr>
    <tr><th scope="row">p95</th><td>{result.before.summary?.p95 ?? "unavailable (<100 valid)"}</td><td>{result.after.summary?.p95 ?? "unavailable (<100 valid)"}</td></tr>
  </tbody></table></div>
  {result.blocked_reasons.length > 0 && <p className="warning-inline" role="alert"><strong>Not eligible:</strong> {result.blocked_reasons.join(", ")}</p>}
  {result.confounds.length > 0 && <p><strong>Confounds:</strong> {result.confounds.join(", ")}</p>}
  <p className="muted">{result.claim_scope}. {result.before.warnings.concat(result.after.warnings).join(" ")}</p>
  </section>;
}

function isSafeImportShape(value: Record<string, unknown>) {
  const run = value.run;
  if (!run || typeof run !== "object") return false;
  const record = run as Record<string, unknown>;
  return value.normalization_revision === "probe-import-1" && typeof value.original_artifact_sha256 === "string" && record.source_kind === "imported_test" && record.verification_state === "operator_imported_unverified" && Array.isArray(record.samples);
}

function handleComparisonError(error: unknown, onSessionLost: () => void, setError: (message: string) => void) {
  if (error instanceof ApiError && (error.status === 401 || error.code === "authentication_required" || error.code === "session_expired")) {
    onSessionLost();
    return;
  }
  setError(error instanceof ApiError ? error.message : error instanceof Error ? error.message : "The comparison operation could not be completed.");
}
