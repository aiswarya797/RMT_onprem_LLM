import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { ComparisonsWorkspace } from "./Comparisons";
import type { IncidentDetail, IncidentSummary, MutationAccess } from "./api";

const generation = "10000000-0000-4000-8000-000000000002";
const beforeID = "30000000-0000-4000-8000-000000000001";
const afterID = "30000000-0000-4000-8000-000000000002";
const incidentID = "10000000-0000-4000-8000-000000000010";
const targetID = "10000000-0000-4000-8000-000000000020";
const hostID = "10000000-0000-4000-8000-000000000021";
const metricID = "request.client.total_ms";

const access: MutationAccess = {
  role: "admin",
  csrfToken: "csrf-token-000000000000000000000000",
  generation,
  mutationsAllowed: true,
};

const incident: IncidentSummary = {
  schema_version: "1.0",
  id: incidentID,
  revision: 1,
  title: "Request timing investigation",
  origin: "manual",
  scope: { kind: "host", id: hostID },
  start_ms: 1_800_000_000_000,
  end_ms: 1_800_000_300_000,
  workflow_state: "open",
  owner_user_id: null,
  evidence_status: "available",
  capsule_sha256: "a".repeat(64),
  created_ms: 1_800_000_000_000,
  updated_ms: 1_800_000_000_000,
};

function envelope(runID: string, original = "a".repeat(64), extra: Record<string, unknown> = {}) {
  return {
    original_artifact_sha256: original,
    normalization_revision: "probe-import-1",
    run: {
      run_id: runID,
      target_id: targetID,
      host_id: hostID,
      source_kind: "imported_test",
      verification_state: "operator_imported_unverified",
      samples: [],
      ...extra,
    },
  };
}

function job(type: "probe_import" | "comparison", resourceID: string) {
  return {
    schema_version: "1.0",
    job_id: `40000000-0000-4000-8000-${type === "probe_import" ? "000000000001" : "000000000002"}`,
    deployment_generation: generation,
    type,
    state: "succeeded",
    progress_ratio: 1,
    created_ms: 1_800_000_000_000,
    updated_ms: 1_800_000_000_001,
    result: { resource_id: resourceID, resource_type: type === "probe_import" ? "probe_run" : "comparison", download_expires_ms: null },
    error: null,
    cancel_state: "none",
  };
}

function comparisonResult(persisted: boolean, resultID: string | null) {
  const population = {
    target_id: targetID,
    model_digest: "b".repeat(64),
    runtime_version: "0.34.0",
    runtime_build: "fixture-source-build",
    config_revision: "c".repeat(64),
    profile_id: "short_text_v1",
    profile_sha256: "d".repeat(64),
    options: { num_ctx: 1024, num_predict: 64, temperature: null, seed: null, think: false, stream: true, cold_warm_policy: "not_controlled" },
    concurrency: 1,
    vantage_id: "local_hub",
    clock_method: "monotonic_aligned",
    source_kind: "imported_test",
    verification_state: "operator_imported_unverified",
  };
  const summary = (median: number) => ({ valid_n: 3, minimum: median - 10, median, maximum: median + 10, p95: null, algorithm: "exact_median_empirical_nearest_rank_p95" });
  const requestSummary = (runID: string, median: number) => ({
    schema_version: "1.0",
    aggregation_revision: "exact-field-nearest-rank-1",
    population_key: population,
    population_status: "complete",
    run_ids: [runID],
    metric_id: metricID,
    completed_count: 3,
    valid_count: 3,
    failed_count: 0,
    cancelled_count: 0,
    incomplete_count: 0,
    provenance_key: { source_kind: "imported_test", verification_state: "operator_imported_unverified", metric_source: "operator_import" },
    summary: summary(median),
    warnings: ["explicit_observed_requests_only", "operator_imported_unverified"],
  });
  return {
    schema_version: "1.0",
    comparison_kind: "request_run",
    result_id: resultID,
    persisted,
    status: "observed_change_similar_recorded_conditions",
    metric_id: metricID,
    before: requestSummary(beforeID, 20),
    after: requestSummary(afterID, 30),
    declared_intervention: null,
    confounds: ["operator_imported_unverified"],
    blocked_reasons: [],
    claim_scope: "explicit_observed_requests_only_no_causal_claim",
  };
}

function detail(): IncidentDetail {
  return {
    ...incident,
    capsule: null,
    annotations: [],
    annotations_next_cursor: null,
    comparisons: [{ comparison_id: "50000000-0000-4000-8000-000000000001", metric_id: metricID, status: "observed_change_similar_recorded_conditions", before_run_id: beforeID, after_run_id: afterID, created_ms: 1_800_000_000_000, expires_ms: 1_802_592_000_000 }],
  };
}

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

it("imports two runs, previews eligibility, saves, and attaches the persisted comparison", async () => {
  const user = userEvent.setup();
  const fetchMock = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (path === "/api/v1/incidents" && !init?.method) return json({ items: [incident], next_cursor: null });
    if (path === "/api/v1/probes" && init?.method === "POST") return json(job("probe_import", path.includes(beforeID) ? beforeID : afterID), 202);
    if (path.startsWith("/api/v1/comparisons/preview?")) return json(comparisonResult(false, null));
    if (path === "/api/v1/comparisons" && init?.method === "POST") return json(job("comparison", "50000000-0000-4000-8000-000000000001"), 202);
    if (path === "/api/v1/comparisons/50000000-0000-4000-8000-000000000001") return json(comparisonResult(true, "50000000-0000-4000-8000-000000000001"));
    if (path === `/api/v1/incidents/${incidentID}/comparisons` && init?.method === "POST") return json(detail());
    throw new Error(`unexpected request ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<ComparisonsWorkspace access={access} onSessionLost={() => {}} />);

  const beforeFile = new File([JSON.stringify(envelope(beforeID))], "before.json", { type: "application/json" });
  const afterFile = new File([JSON.stringify(envelope(afterID, "b".repeat(64)))], "after.json", { type: "application/json" });
  await user.upload(screen.getByLabelText("Before run file"), beforeFile);
  await user.click(screen.getAllByRole("button", { name: "Validate and import" })[0]);
  expect(await screen.findByText(new RegExp(`Imported run ${beforeID.slice(0, 8)}`))).toBeTruthy();
  await user.upload(screen.getByLabelText("After run file"), afterFile);
  await user.click(screen.getAllByRole("button", { name: "Validate and import" })[1]);
  expect(await screen.findByText(new RegExp(`Imported run ${afterID.slice(0, 8)}`))).toBeTruthy();

  await user.selectOptions(screen.getByLabelText("Before run"), beforeID);
  await user.selectOptions(screen.getByLabelText("After run"), afterID);
  await user.click(screen.getByRole("button", { name: "Preview eligibility" }));
  expect(await screen.findByRole("heading", { name: "Eligibility: observed change similar recorded conditions" })).toBeTruthy();
  expect(screen.getByRole("row", { name: "Median 20 30" })).toBeTruthy();
  expect(screen.getAllByText("unavailable (<100 valid)")).toHaveLength(2);

  await user.click(screen.getByRole("button", { name: "Save comparison" }));
  expect(await screen.findByText(/Saved comparison/)).toBeTruthy();
  await user.selectOptions(screen.getByLabelText("Attach to investigation"), incidentID);
  await user.click(screen.getByRole("button", { name: "Attach comparison" }));
  expect(await screen.findByText("Comparison attached. Reopen the investigation to see its saved provenance and retention state.")).toBeTruthy();
  await waitFor(() => expect(fetchMock.mock.calls.some(([path, init]) => path === `/api/v1/incidents/${incidentID}/comparisons` && init?.method === "POST")).toBe(true));
});

it("rejects prompt-bearing content before making an import request", async () => {
  const user = userEvent.setup();
  const fetchMock = vi.fn().mockImplementation((path: string) => {
    if (path === "/api/v1/incidents") return json({ items: [], next_cursor: null });
    throw new Error(`unexpected request ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<ComparisonsWorkspace access={access} onSessionLost={() => {}} />);
  const unsafe = new File([JSON.stringify(envelope(beforeID, "a".repeat(64), { content: "do not retain" }))], "unsafe.json", { type: "application/json" });
  await user.upload(screen.getByLabelText("Before run file"), unsafe);
  await user.click(screen.getAllByRole("button", { name: "Validate and import" })[0]);
  expect((await screen.findByRole("alert")).textContent).toContain("Prompt, answer, credential and content fields are not accepted.");
  expect(fetchMock.mock.calls.some(([path]) => path === "/api/v1/probes")).toBe(false);
});
