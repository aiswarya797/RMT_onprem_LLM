import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { LiveOverview } from "./Overview";
import type { FoundationStatus, HistoryCatalog, MutationAccess, Overview, Series, TargetOverview } from "./api";

const generatedMS = 1_800_000_000_000;
const overview: Overview = {
  generated_ms: generatedMS,
  deployment_state: {
    schema_version: "1.0",
    deployment_id: "10000000-0000-4000-8000-000000000001",
    deployment_generation: "10000000-0000-4000-8000-000000000002",
    recovery_state: "normal",
    recovery_point_ms: null,
    mutations_allowed: true,
  },
  state: "fresh",
  host_count: 0,
  target_count: 0,
  open_incident_count: 0,
  observed_request_population: "absent",
  history_available: false,
  hosts: [],
  targets: [],
  capabilities_missing: [],
};

const status: FoundationStatus = {
  experimental_features: true,
  schema_version: "1.0",
  generated_ms: generatedMS,
  deployment_state: overview.deployment_state,
  hub_state: "configured",
  collector_state: "not_registered",
  target_state: "none",
  host_count: 0,
  target_count: 0,
  source_count: 0,
  collection_started: false,
  inference_started: false,
  storage_state: "normal",
};

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

function observedHost(metrics = ["host.cpu.busy_ratio", "host.memory.swap_used_bytes"]): Overview {
  return {
    ...overview,
    history_available: true,
    host_count: 1,
    hosts: [{
      id: "10000000-0000-4000-8000-000000000001",
      display_name: "Local Mac",
      state: "active",
      source_state: "fresh",
      collector_version: "0.1.0",
      current_session_generation: 1,
      updated_ms: generatedMS,
      heartbeat_ms: generatedMS,
      heartbeat_age_ms: 0,
      metrics: metrics.map((metric) => ({
        metric,
        unit: metric.endsWith("bytes") ? "bytes" as const : "ratio" as const,
        scope_id: "10000000-0000-4000-8000-000000000001",
        source_id: "10000000-0000-4000-8000-000000000002",
        observed_ms: generatedMS,
        age_ms: 0,
        value: metric.endsWith("bytes") ? 1024 : 0.5,
        quality: "measured",
        missing_reason: null,
        method_revision: "fixture-v1",
        provenance: { source: "darwin_api", method_revision: "fixture-v1", verification: "direct_capture" },
      })),
      network_observed_ms: null,
      network_age_ms: null,
      network_observations: [],
      process_observed_ms: null,
      process_age_ms: null,
      process_summary: null,
      process_observations: [],
      capabilities_missing: [],
    }],
  };
}

const adminAccess: MutationAccess = {
  role: "admin",
  csrfToken: "csrf-token-000000000000000000000000",
  generation: overview.deployment_state.deployment_generation,
  mutationsAllowed: true,
};

function observedLocalTarget(): TargetOverview {
  return {
    id: "10000000-0000-4000-8000-000000000003",
    host_id: "10000000-0000-4000-8000-000000000001",
    host_local: true,
    display_name: "Local Ollama",
    adapter_id: "ollama",
    association_state: "verified",
    retired: false,
    source_state: "fresh",
    reachable: {
      metric: "runtime.reachable",
      unit: "boolean",
      scope_id: "10000000-0000-4000-8000-000000000003",
      source_id: "10000000-0000-4000-8000-000000000004",
      observed_ms: generatedMS,
      age_ms: 0,
      value: true,
      quality: "measured",
      missing_reason: null,
      method_revision: "fixture-v1",
      provenance: { source: "ollama_api", method_revision: "fixture-v1", verification: "direct_capture" },
    },
    models_state: "fresh",
    models_observed_ms: generatedMS,
    models_age_ms: 0,
    models: [],
    capabilities_missing: [],
  };
}

function retainedSeries(metric = "host.cpu.busy_ratio"): Series {
  return {
    schema_version: "1.0",
    metric,
    definition_revision: "mac-ollama-1",
    unit: metric.endsWith("bytes") ? "bytes" : "ratio",
    requested_range: { start: "2027-01-15T07:55:00Z", end: "2027-01-15T08:00:00Z", start_ms: generatedMS - 300_000, end_ms: generatedMS, inclusive_start_exclusive_end: true },
    effective_range: { start: "2027-01-15T07:56:00Z", end: "2027-01-15T07:59:00Z", start_ms: generatedMS - 240_000, end_ms: generatedMS - 60_000, inclusive_start_exclusive_end: true },
    population: "host",
    host_id: "10000000-0000-4000-8000-000000000001",
    source_id: "10000000-0000-4000-8000-000000000002",
    resolution_tier: "raw",
    method_revision: "fixture-v1",
    epoch_id: null,
    clock_method: "single_host_monotonic_aligned",
    coverage_ratio: 0.5,
    population_key: null,
    completed_count: 0,
    cancelled_count: 0,
    failed_count: 0,
    incomplete_count: 0,
    summary: null,
    points: [
      { time_ms: generatedMS - 240_000, value: 0.25, quality: "measured", missing_reason: null, epoch_id: null },
      { time_ms: generatedMS - 120_000, value: null, quality: "unavailable", missing_reason: "source_timeout", epoch_id: null },
      { time_ms: generatedMS - 60_000, value: 0.75, quality: "measured", missing_reason: null, epoch_id: null },
    ],
    gaps: [{ start_ms: generatedMS - 180_000, end_ms: generatedMS - 90_000, reason: "source_timeout" }],
    warnings: [],
  };
}

function retainedCatalog(overrides: Partial<HistoryCatalog> = {}): HistoryCatalog {
  return {
    schema_version: "1.0",
    generated_ms: generatedMS,
    earliest_retained_ms: generatedMS - 30 * 24 * 60 * 60_000,
    latest_retained_ms: generatedMS,
    scopes: [{
      id: "10000000-0000-4000-8000-000000000001",
      kind: "host",
      display_name: "Local Mac",
      retired: false,
      host_id: "10000000-0000-4000-8000-000000000001",
      target_id: null,
      earliest_retained_ms: generatedMS - 30 * 24 * 60 * 60_000,
      latest_retained_ms: generatedMS,
      metrics: ["host.cpu.busy_ratio", "host.memory.swap_used_bytes"],
    }],
    truncated: false,
    ...overrides,
  };
}

function historyFetch(series = retainedSeries()) {
  return vi.fn().mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(path === "/api/v1/history/catalog" ? retainedCatalog() : series), { status: 200 })));
}

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
}

it("marks a failed refresh unknown and advances the last-known age", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(generatedMS);
  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("connection refused")));
  render(<LiveOverview initial={overview} initialStatus={status} onSessionLost={() => {}} />);

  await act(async () => {
    await vi.advanceTimersByTimeAsync(5_000);
  });
  expect(screen.getByText("connection unknown")).toBeTruthy();
  expect(screen.getByText(/last observed values remain visible/)).toBeTruthy();

  await act(async () => {
    await vi.advanceTimersByTimeAsync(5_000);
  });
  expect(screen.getByText(/Updated 10s/)).toBeTruthy();
  expect(screen.getByText(/Current service state is unknown/)).toBeTruthy();
});

it("keeps failed evaluator health visible separately from hub and collector state", () => {
  const failed = { ...status, evaluator: { started: true, last_attempt_ms: generatedMS, last_success_ms: generatedMS - 20_000, lag_ms: 20_000, last_pass_failed: true } };
  render(<LiveOverview initial={overview} initialStatus={failed} onSessionLost={() => {}} />);
  expect(screen.getByText("Last pass failed")).toBeTruthy();
  expect(screen.getByText(/Alert evaluation needs attention/)).toBeTruthy();
  expect(screen.getByText("Configured")).toBeTruthy();
});

it("requires confirmation and renders a blocked local probe outcome without a run fetch", async () => {
  const local = { ...overview, target_count: 1, targets: [observedLocalTarget()] };
  const fetchMock = vi.fn().mockImplementation((path: string) => json(path === "/api/v1/probes/run"
    ? { status: "blocked", run_id: null, requested_count: 1, submitted_count: 0, safe_code: "inference_policy_unresolved", reasons: ["inference_policy_unresolved", "model_not_suitable"] }
    : path === "/api/v1/incidents" ? { items: [], next_cursor: null } : {}));
  vi.stubGlobal("fetch", fetchMock);
  render(<LiveOverview initial={local} initialStatus={status} mutationAccess={adminAccess} onSessionLost={() => {}} />);

  const button = screen.getByRole("button", { name: "Run one bounded request" });
  expect((button as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getByLabelText(/I confirm one request may load/));
  expect((button as HTMLButtonElement).disabled).toBe(false);
  fireEvent.click(button);
  expect(await screen.findByText(/Request blocked before submission/)).toBeTruthy();
  expect(fetchMock.mock.calls.map(([path]) => path)).toContain("/api/v1/probes/run");
  expect(fetchMock.mock.calls.filter(([path]) => String(path).startsWith("/api/v1/probes/runs/")).length).toBe(0);
  expect(screen.getByText(/no Ollama generation request was sent/)).toBeTruthy();
});

it("refreshes service state with the live overview in the same polling generation", async () => {
  vi.useFakeTimers();
  vi.setSystemTime(generatedMS);
  const observing = { ...status, generated_ms: generatedMS + 5_000, collector_state: "observing" as const, storage_state: "warning" as const };
  const fetchMock = vi.fn()
    .mockResolvedValueOnce(new Response(JSON.stringify(overview), { status: 200 }))
    .mockResolvedValueOnce(new Response(JSON.stringify(observing), { status: 200 }));
  vi.stubGlobal("fetch", fetchMock);
  render(<LiveOverview initial={overview} initialStatus={status} onSessionLost={() => {}} />);

  expect(screen.getByText("Awaiting registration")).toBeTruthy();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(5_000);
  });
  expect(screen.getByText("Observing")).toBeTruthy();
  expect(screen.getByText("Storage pressure warning")).toBeTruthy();
  expect(fetchMock.mock.calls.map(([path]) => path)).toEqual(["/api/v1/overview", "/api/v1/status"]);
});

it("does not label a failed network read as an observed-empty population", () => {
  const failedNetwork: Overview = {
    ...overview,
    hosts: [{
      id: "10000000-0000-4000-8000-000000000001",
      display_name: "Local Mac",
      state: "active",
      source_state: "partial",
      collector_version: "0.1.0",
      current_session_generation: 1,
      updated_ms: generatedMS,
      heartbeat_ms: generatedMS,
      heartbeat_age_ms: 0,
      metrics: [],
      network_observed_ms: generatedMS,
      network_age_ms: 0,
      network_observations: [],
      process_observed_ms: null,
      process_age_ms: null,
      process_summary: null,
      process_observations: [],
      capabilities_missing: [{ id: "host.network.received_bytes_total", reason: "source_timeout", detail_code: null }],
    }],
  };
  render(<LiveOverview initial={failedNetwork} initialStatus={status} onSessionLost={() => {}} />);
  expect(screen.getByText(/latest network collection attempt did not produce interface counters/)).toBeTruthy();
  expect(screen.queryByText(/latest successful network observation reported no interface counters/)).toBeNull();
});

it("keeps usable counters visible when the bounded network population is partial", () => {
  const partialNetwork: Overview = {
    ...overview,
    hosts: [{
      id: "10000000-0000-4000-8000-000000000001",
      display_name: "Local Mac",
      state: "active",
      source_state: "partial",
      collector_version: "0.1.0",
      current_session_generation: 1,
      updated_ms: generatedMS,
      heartbeat_ms: generatedMS,
      heartbeat_age_ms: 0,
      metrics: [],
      network_observed_ms: generatedMS,
      network_age_ms: 0,
      network_observations: [{
        interface_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        boot_id: "10000000-0000-4000-8000-000000000010",
        counter_epoch_id: "10000000-0000-4000-8000-000000000011",
        loopback: false,
        received_bytes_total: "1024",
        sent_bytes_total: "2048",
        missing: [],
        provenance: { source: "darwin_api", method_revision: "darwin-net-rt-iflist2-ifdata64-candidate-1", verification: "direct_capture" },
      }],
      process_observed_ms: null,
      process_age_ms: null,
      process_summary: null,
      process_observations: [],
      capabilities_missing: [{ id: "host.network.received_bytes_total", reason: "limit_exceeded", detail_code: "interface_cap" }],
    }],
  };
  render(<LiveOverview initial={partialNetwork} initialStatus={status} onSessionLost={() => {}} />);
  expect(screen.getByText(/retained usable counters, but coverage is partial/)).toBeTruthy();
  expect(screen.getByText(/received 1\.00 KiB · sent 2\.00 KiB/)).toBeTruthy();
  expect(screen.queryByText(/did not produce interface counters/)).toBeNull();
});

it("keeps a fixed historical range and timezone in the URL", async () => {
  window.history.replaceState(null, "", `/?mode=historical&start=${encodeURIComponent(new Date(generatedMS - 24 * 60 * 60_000).toISOString())}&end=${encodeURIComponent(new Date(generatedMS).toISOString())}&tz=UTC`);
  const fetchMock = historyFetch();
  vi.stubGlobal("fetch", fetchMock);
  render(<LiveOverview initial={observedHost()} initialStatus={status} onSessionLost={() => {}} />);

  expect(await screen.findByText("Live paused · fixed range")).toBeTruthy();
  await screen.findByRole("img", { name: /Host CPU busy history/ });
  expect((screen.getByLabelText("History range") as HTMLSelectElement).value).toBe("past-24h");
  expect(new URL(window.location.href).searchParams.get("tz")).toBe("UTC");
  const seriesCall = fetchMock.mock.calls.find(([path]) => String(path).startsWith("/api/v1/series"));
  expect(new URL(seriesCall?.[0] as string, window.location.origin).searchParams.get("resolution")).toBe("auto");
});

it("cancels a superseded history request and only renders the new metric", async () => {
  let firstSignal: AbortSignal | undefined;
  const fetchMock = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
	if (path === "/api/v1/history/catalog") return Promise.resolve(new Response(JSON.stringify(retainedCatalog()), { status: 200 }));
    const metric = new URL(path, window.location.origin).searchParams.get("metric");
    if (metric === "host.cpu.busy_ratio") {
      firstSignal = init?.signal ?? undefined;
      return new Promise<Response>(() => {});
    }
    return Promise.resolve(new Response(JSON.stringify(retainedSeries("host.memory.swap_used_bytes")), { status: 200 }));
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<LiveOverview initial={observedHost()} initialStatus={status} onSessionLost={() => {}} />);

	const metricSelect = await screen.findByLabelText("Metric");
	await act(async () => Promise.resolve());
  fireEvent.change(metricSelect, { target: { value: "host.memory.swap_used_bytes" } });
  await act(async () => Promise.resolve());
  expect(firstSignal?.aborted).toBe(true);
  expect(screen.getByRole("img", { name: /Swap used history/ })).toBeTruthy();
  expect(new URL(window.location.href).searchParams.get("metric")).toBe("host.memory.swap_used_bytes");
});

it("shows explicit gaps in the chart and the accessible observation tables", async () => {
  vi.stubGlobal("fetch", historyFetch());
  const { container } = render(<LiveOverview initial={observedHost()} initialStatus={status} onSessionLost={() => {}} />);
  await screen.findByRole("img", { name: /Host CPU busy history/ });

  expect(container.querySelectorAll(".chart-gap")).toHaveLength(1);
  expect(container.querySelectorAll(".chart-line")).toHaveLength(2);
  expect(screen.getByText("1 explicit data gap")).toBeTruthy();
  expect(screen.getByRole("table", { name: "Returned metric observations" })).toBeTruthy();
  expect(screen.getAllByText("source timeout").length).toBeGreaterThan(0);
});

it("charts exact decimal byte values while preserving the table representation", async () => {
  const bytes = retainedSeries("host.memory.swap_used_bytes");
  bytes.points = [
    { time_ms: generatedMS - 120_000, value: "9007199254740993", quality: "measured", missing_reason: null, epoch_id: null },
    { time_ms: generatedMS - 60_000, value: "18446744073709551615", quality: "measured", missing_reason: null, epoch_id: null },
  ];
  bytes.gaps = [];
  vi.stubGlobal("fetch", historyFetch(bytes));
  render(<LiveOverview initial={observedHost()} initialStatus={status} onSessionLost={() => {}} />);

  expect(await screen.findByRole("img", { name: /Swap used history/ })).toBeTruthy();
  expect(screen.getByText("9007199254740993")).toBeTruthy();
  expect(screen.getByText("18446744073709551615")).toBeTruthy();
  expect(screen.getByText(/table preserves each exact decimal byte value/)).toBeTruthy();
});

it("keeps a retired process scope selected from the URL", async () => {
  const processKey = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
  window.history.replaceState(null, "", `/?scope=${processKey}&metric=process.cpu.busy_ratio`);
  const catalog = retainedCatalog({ scopes: [
    ...retainedCatalog().scopes,
    { id: processKey, kind: "process", display_name: "Observed process dddddddddddd", retired: true, host_id: "10000000-0000-4000-8000-000000000001", target_id: null, earliest_retained_ms: generatedMS - 60_000, latest_retained_ms: generatedMS, metrics: ["process.cpu.busy_ratio"] },
  ] });
  const fetchMock = vi.fn().mockImplementation((path: string) => Promise.resolve(new Response(JSON.stringify(path === "/api/v1/history/catalog" ? catalog : retainedSeries("process.cpu.busy_ratio")), { status: 200 })));
  vi.stubGlobal("fetch", fetchMock);
  render(<LiveOverview initial={observedHost()} initialStatus={status} onSessionLost={() => {}} />);

  expect(await screen.findByDisplayValue("Process · Observed process dddddddddddd (retired)")).toBeTruthy();
  await waitFor(() => {
    const seriesCall = fetchMock.mock.calls.find(([path]) => String(path).startsWith("/api/v1/series"));
    expect(seriesCall).toBeDefined();
    expect(new URL(seriesCall![0] as string, window.location.origin).searchParams.get("scope")).toBe(processKey);
  });
});

it("states the global earliest retained boundary for an expired range", async () => {
  const expired = retainedSeries();
	const oldStart = generatedMS - 40 * 24 * 60 * 60_000;
	const oldEnd = generatedMS - 39 * 24 * 60 * 60_000;
	expired.requested_range = { start: new Date(oldStart).toISOString(), end: new Date(oldEnd).toISOString(), start_ms: oldStart, end_ms: oldEnd, inclusive_start_exclusive_end: true };
  expired.points = [];
  expired.effective_range = null;
	expired.gaps = [{ start_ms: oldStart, end_ms: oldEnd, reason: "population_not_observed" }];
  window.history.replaceState(null, "", `/?mode=historical&start=${new Date(expired.requested_range.start_ms).toISOString()}&end=${new Date(expired.requested_range.end_ms).toISOString()}&tz=UTC`);
  vi.stubGlobal("fetch", historyFetch(expired));
  render(<LiveOverview initial={observedHost()} initialStatus={status} onSessionLost={() => {}} />);

  expect(await screen.findByText(/The earliest retained observation is/)).toBeTruthy();
});

it("shows bounded API guidance for an over-cap history request", async () => {
  const fetchMock = vi.fn().mockImplementation((path: string) => Promise.resolve(path === "/api/v1/history/catalog"
    ? new Response(JSON.stringify(retainedCatalog()), { status: 200 })
    : new Response(JSON.stringify({ code: "point_limit_exceeded", message: "bounded", recovery_action: "fix_input" }), { status: 422 })));
  vi.stubGlobal("fetch", fetchMock);
  render(<LiveOverview initial={observedHost()} initialStatus={status} onSessionLost={() => {}} />);

  expect(await screen.findByText(/contains too many retained points/)).toBeTruthy();
});

 it("keeps unqualified controls out of the same-machine preview", () => {
  render(<LiveOverview initial={overview} initialStatus={{ ...status, experimental_features: false }} mutationAccess={adminAccess} onSessionLost={vi.fn()} />);
  expect(screen.getByText(/Same-machine preview/)).toBeTruthy();
  expect(screen.queryByText("Connect another Mac")).toBeNull();
  expect(screen.queryByText("Notification destinations")).toBeNull();
  expect(screen.queryByText("Compare request runs")).toBeNull();
  expect(screen.queryByRole("button", { name: /Run.*request/i })).toBeNull();
  expect(screen.getByRole("heading", { name: "Live overview" })).toBeTruthy();
 });
