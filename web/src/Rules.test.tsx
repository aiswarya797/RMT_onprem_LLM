import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { RulesWorkspace } from "./Rules";
import type { MutationAccess, Overview, RuleDefinition, RuleRecord } from "./api";

const access: MutationAccess = { role: "admin", csrfToken: "csrf", generation: "10000000-0000-4000-8000-000000000002", mutationsAllowed: true };
const overview: Overview = {
  generated_ms: 1800000000000,
  deployment_state: { schema_version: "1.0", deployment_id: "10000000-0000-4000-8000-000000000001", deployment_generation: access.generation, recovery_state: "normal", recovery_point_ms: null, mutations_allowed: true },
  state: "fresh", host_count: 0, target_count: 0, open_incident_count: 0, observed_request_population: "absent", history_available: false, hosts: [], targets: [], capabilities_missing: [],
};
const definition: RuleDefinition = { expected_revision: null, evaluator_type: "disk_monitor_health", scope_id: overview.deployment_state.deployment_id, enabled: true, metric_id: null, request_population: null, aggregation: null, threshold: 15000, dwell_ms: 30000, recovery_ms: 30000 };
const record: RuleRecord = { id: "10000000-0000-4000-8000-000000000003", revision: 1, definition, created_ms: 1800000000000, updated_ms: 1800000000000 };
const json = (value: unknown) => new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
afterEach(() => vi.unstubAllGlobals());
async function createMonitorRule() {
  await screen.findByText("No alert rules configured.");
  fireEvent.click(screen.getByRole("button", { name: "New rule" }));
  fireEvent.change(screen.getByLabelText("Rule type"), { target: { value: "disk_monitor_health" } });
}

it("retries an uncertain write with the same identity and body, locking navigation while pending", async () => {
  const writes: RequestInit[] = [];
  let finish: ((value: Response) => void) | undefined;
  vi.stubGlobal("fetch", vi.fn((_path: string, init: RequestInit) => {
    if (init.method !== "POST") return Promise.resolve(json({ items: [] }));
    writes.push(init);
    if (writes.length === 1) return Promise.reject(new TypeError("connection lost after commit"));
    return new Promise<Response>(resolve => { finish = resolve; });
  }));
  render(<RulesWorkspace overview={overview} access={access} onSessionLost={vi.fn()} />);
  await createMonitorRule();
  fireEvent.click(screen.getByRole("button", { name: "Save rule" }));
  await screen.findByRole("alert");
  fireEvent.click(screen.getByRole("button", { name: "Save rule" }));
  await waitFor(() => expect(writes).toHaveLength(2));
  expect(writes[0].body).toBe(writes[1].body);
  expect(new Headers(writes[0].headers).get("Idempotency-Key")).toBe(new Headers(writes[1].headers).get("Idempotency-Key"));
  expect(new Headers(writes[1].headers).get("If-Deployment-Generation")).toBe(access.generation);
  expect(screen.getByRole("button", { name: "Close definition" }).matches(":disabled")).toBe(true);
  expect(screen.getByRole("button", { name: "New rule" }).matches(":disabled")).toBe(true);
  await act(async () => { finish?.(json(record)); });
  expect(await screen.findByText(/Rule revision 1 saved/)).not.toBeNull();
});

it("uses a new identity when the operator changes an uncertain definition", async () => {
  const writes: RequestInit[] = [];
  vi.stubGlobal("fetch", vi.fn((_path: string, init: RequestInit) => {
    if (init.method !== "POST") return Promise.resolve(json({ items: [] }));
    writes.push(init); return Promise.reject(new TypeError("connection lost"));
  }));
  render(<RulesWorkspace overview={overview} access={access} onSessionLost={vi.fn()} />);
  await createMonitorRule();
  fireEvent.click(screen.getByRole("button", { name: "Save rule" }));
  await screen.findByRole("alert");
  fireEvent.click(screen.getByLabelText("Enabled"));
  fireEvent.click(screen.getByRole("button", { name: "Save rule" }));
  await waitFor(() => expect(writes).toHaveLength(2));
  expect(new Headers(writes[0].headers).get("Idempotency-Key")).not.toBe(new Headers(writes[1].headers).get("Idempotency-Key"));
  expect(JSON.parse(writes[1].body as string).enabled).toBe(false);
});

it("keeps viewer definitions read-only", async () => {
  const fetch = vi.fn(() => Promise.resolve(json({ items: [record] })));
  vi.stubGlobal("fetch", fetch);
  render(<RulesWorkspace overview={overview} access={{ ...access, role: "viewer" }} onSessionLost={vi.fn()} />);
  fireEvent.click(await screen.findByRole("button", { name: "View" }));
  expect(screen.getByLabelText("Enabled").matches(":disabled")).toBe(true);
  expect(screen.queryByRole("button", { name: "Save rule" })).toBeNull();
  expect(screen.queryByRole("button", { name: "New rule" })).toBeNull();
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("does not apply an old-generation save response to the restored deployment", async () => {
  let finish: ((value: Response) => void) | undefined;
  vi.stubGlobal("fetch", vi.fn((_path: string, init: RequestInit) => init.method === "POST"
    ? new Promise<Response>(resolve => { finish = resolve; }) : Promise.resolve(json({ items: [] }))));
  const view = render(<RulesWorkspace overview={overview} access={access} onSessionLost={vi.fn()} />);
  await createMonitorRule();
  fireEvent.click(screen.getByRole("button", { name: "Save rule" }));
  await waitFor(() => expect(finish).toBeDefined());
  view.rerender(<RulesWorkspace overview={overview} access={{ ...access, generation: "10000000-0000-4000-8000-000000000004" }} onSessionLost={vi.fn()} />);
  await act(async () => { finish?.(json(record)); });
  expect(screen.queryByText(/Rule revision 1 saved/)).toBeNull();
  expect(screen.queryByRole("form")).toBeNull();
});
