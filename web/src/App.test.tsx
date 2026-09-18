import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import type { DeploymentState, Overview, Series } from "./api";

const session = {
  user: {
    id: "10000000-0000-4000-8000-000000000001",
    revision: 1,
    name: "local-admin",
    role: "admin",
    disabled: false,
    trust_generation: "20000000-0000-4000-8000-000000000001",
    historical_restored: false,
  },
  expires_ms: 1_900_000_000_000,
  csrf_token: "csrf-token-with-at-least-thirty-two-characters",
};

const deployment: DeploymentState = {
  schema_version: "1.0",
  deployment_id: "30000000-0000-4000-8000-000000000001",
  deployment_generation: "40000000-0000-4000-8000-000000000001",
  recovery_state: "normal",
  recovery_point_ms: null,
  mutations_allowed: true,
};

const status = {
  schema_version: "1.0",
  generated_ms: 1_800_000_000_000,
  deployment_state: deployment,
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

const emptyOverview: Overview = {
  generated_ms: 1_800_000_000_000,
  deployment_state: deployment,
  state: "not_observed",
  host_count: 0,
  target_count: 0,
  open_incident_count: 0,
  observed_request_population: "absent",
  history_available: false,
  hosts: [],
  targets: [],
  capabilities_missing: [],
};

const cli = '"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor"';
const bootstrapToken = "setup-token-that-is-longer-than-thirty-two-characters";

function json(value: unknown, statusCode = 200) {
  return Promise.resolve(new Response(JSON.stringify(value), { status: statusCode, headers: { "Content-Type": "application/json" } }));
}

function rateLimitedEnvelope(requestId: string) {
  return {
    schema_version: "1.0",
    code: "login_rate_limited",
    message: "Too many sign-in attempts. Try again later.",
    recovery_action: "retry_later",
    request_id: requestId,
    retryable: true,
    cli_exit_code: 4,
  };
}

afterEach(() => vi.unstubAllGlobals());

describe("authentication foundation", () => {
  it("creates the first administrator with the real bootstrap contract", async () => {
    const storageSpy = vi.spyOn(Storage.prototype, "setItem");
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "required", expires_ms: 1_900_000_000_000 }))
      .mockImplementationOnce(() => json({ token: bootstrapToken, expires_ms: 1_900_000_000_000 }))
      .mockImplementationOnce(() => json(session))
      .mockImplementationOnce(() => json(deployment))
      .mockImplementationOnce(() => json(status))
      .mockImplementationOnce(() => json(emptyOverview))
      .mockImplementationOnce(() => json({ items: [], next_cursor: null }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: "Create the first administrator" });
    const password = "a-local-password-with-length";
    await user.type(screen.getByLabelText("Administrator username"), "local-admin");
    await user.type(screen.getByLabelText("Password", { exact: true }), password);
    await user.type(screen.getByLabelText("Confirm password"), password);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    await screen.findByRole("heading", { name: "No Ollama target is configured" });
    const [, options] = fetchMock.mock.calls[2] as [string, RequestInit];
    expect(JSON.parse(String(options.body))).toEqual({ bootstrap_token: bootstrapToken, username: "local-admin", password });
    expect(document.body.textContent).not.toContain(bootstrapToken);
    expect(document.body.textContent).not.toContain(password);
    expect(storageSpy).not.toHaveBeenCalled();
  });

  it("renders fresh, partial and uncertified observations without inventing zero values", async () => {
    const missingPressure = {
      metric: "host.memory.pressure_level",
      unit: "state" as const,
      scope_id: "10000000-0000-4000-8000-000000000001",
      source_id: "10000000-0000-4000-8000-000000000007",
      observed_ms: 1_800_000_000_000,
      age_ms: 1_000,
      value: null,
      quality: "unavailable",
      missing_reason: "method_uncertified",
      method_revision: "xnu-11417.121.6-pressure-flags",
      provenance: { source: "darwin_api", method_revision: "xnu-11417.121.6-pressure-flags", verification: "direct_capture" as const },
    };
    const liveOverview: Overview = {
      ...emptyOverview,
      state: "partial",
      host_count: 1,
      target_count: 1,
      history_available: true,
      hosts: [{
        id: "10000000-0000-4000-8000-000000000001",
        display_name: "Local Mac",
        state: "active",
        source_state: "partial",
        collector_version: "0.1.0",
        current_session_generation: 1,
        updated_ms: 1_800_000_000_000,
        heartbeat_ms: 1_800_000_000_000,
        heartbeat_age_ms: 1_000,
        metrics: [missingPressure],
        network_observed_ms: 1_800_000_000_000,
        network_age_ms: 1_000,
        network_observations: [],
        process_observed_ms: 1_800_000_000_000,
        process_age_ms: 1_000,
        process_summary: { eligible_pid_count: 4, examined_pid_count: 3, permission_denied_count: 1, retained_process_count: 1, enumeration_truncated: false, coverage: "partial", method_revision: "darwin-proc-list-candidate-1", sample_interval_ms: 1000, scan_duration_ms: 20 },
        process_observations: [],
        capabilities_missing: [{ id: "gpu.busy_ratio", reason: "unsupported_platform_contract", detail_code: null }],
      }],
      targets: [{
        id: "10000000-0000-4000-8000-000000000006",
        host_id: "10000000-0000-4000-8000-000000000001",
        display_name: "Local Ollama",
        adapter_id: "ollama",
        association_state: "declared_unverified",
        retired: false,
        source_state: "fresh",
        reachable: { ...missingPressure, metric: "runtime.reachable", unit: "boolean", scope_id: "10000000-0000-4000-8000-000000000006", value: true, quality: "runtime_reported", missing_reason: null, method_revision: "ollama-0.34.0-bounded-read-v1", provenance: { source: "runtime_api", method_revision: "ollama-0.34.0-bounded-read-v1", verification: "direct_capture" } },
        models_state: "fresh",
        models_observed_ms: 1_800_000_000_000,
        models_age_ms: 1_000,
        models: [],
        capabilities_missing: [{ id: "runtime.queue_depth", reason: "unsupported_platform_contract", detail_code: null }],
      }],
      capabilities_missing: [
        { id: "gpu.busy_ratio", reason: "unsupported_platform_contract", detail_code: null },
        { id: "runtime.queue_depth", reason: "unsupported_platform_contract", detail_code: null },
      ],
    };
    liveOverview.target_count = 2;
    liveOverview.targets.push({
      ...liveOverview.targets[0],
      id: "10000000-0000-4000-8000-000000000009",
      display_name: "Unresolved Ollama",
      models_state: "unavailable",
      models_observed_ms: null,
      models_age_ms: null,
    });
    const history: Series = {
      schema_version: "1.0",
      metric: "host.memory.pressure_level",
      definition_revision: "mac-ollama-1",
      unit: "state",
      requested_range: { start: "2027-01-15T07:55:00Z", end: "2027-01-15T08:00:00Z", start_ms: 1_799_999_700_000, end_ms: 1_800_000_000_000, inclusive_start_exclusive_end: true },
      effective_range: { start: "2027-01-15T08:00:00Z", end: "2027-01-15T08:00:01Z", start_ms: 1_800_000_000_000, end_ms: 1_800_000_000_001, inclusive_start_exclusive_end: true },
      population: "host",
      host_id: liveOverview.hosts[0].id,
      source_id: "10000000-0000-4000-8000-000000000007",
      resolution_tier: "raw",
      method_revision: "xnu-11417.121.6-pressure-flags",
      epoch_id: null,
      clock_method: "single_host_monotonic_aligned",
      coverage_ratio: 0.5,
      population_key: null,
      completed_count: 0,
      cancelled_count: 0,
      failed_count: 0,
      incomplete_count: 0,
      summary: null,
      points: [{ time_ms: 1_800_000_000_000, value: "warning", quality: "measured", missing_reason: null, epoch_id: null }],
      gaps: [{ start_ms: 1_799_999_700_000, end_ms: 1_800_000_000_000, reason: "collection_gap" }],
      warnings: [],
    };
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "configured", expires_ms: null }))
      .mockImplementationOnce(() => json(session))
      .mockImplementationOnce(() => json(deployment))
      .mockImplementationOnce(() => json(status))
      .mockImplementationOnce(() => json(liveOverview))
      .mockImplementationOnce(() => json({
        schema_version: "1.0",
        generated_ms: 1_800_000_000_000,
        earliest_retained_ms: 1_799_999_700_000,
        latest_retained_ms: 1_800_000_000_001,
        scopes: [{ id: liveOverview.hosts[0].id, kind: "host", display_name: "Local Mac", retired: false, host_id: liveOverview.hosts[0].id, target_id: null, earliest_retained_ms: 1_799_999_700_000, latest_retained_ms: 1_800_000_000_001, metrics: ["host.memory.pressure_level"] }],
        truncated: false,
      }))
      .mockImplementationOnce(() => json({ items: [], next_cursor: null }))
      .mockImplementationOnce(() => json(history));
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    await screen.findByRole("heading", { name: "Live overview" });
    expect(screen.getByText("Unavailable", { selector: ".metric-value" })).toBeTruthy();
    expect(screen.getByText(/method uncertified/)).toBeTruthy();
    expect(screen.getByText(/examined 3 of 4 eligible/)).toBeTruthy();
    expect(screen.getByText(/No model was reported loaded/)).toBeTruthy();
    expect(screen.getByText(/empty model population cannot be inferred/)).toBeTruthy();
    expect(await screen.findByText(/Data quality/)).toBeTruthy();
  });

  it("shows the exact local renewal path for an expired bootstrap", async () => {
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => json({ schema_version: "1.0", state: "expired", expires_ms: null })));
    render(<App />);

    await screen.findByRole("heading", { name: "The setup token expired" });
    expect(screen.getByText(`${cli} admin bootstrap-renew`)).toBeTruthy();
    expect(screen.queryByLabelText("Password")).toBeNull();
  });

  it("moves an expired bootstrap submission to visible renewal guidance", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "required", expires_ms: 1_900_000_000_000 }))
      .mockImplementationOnce(() => json({ token: bootstrapToken, expires_ms: 1_900_000_000_000 }))
      .mockImplementationOnce(() => json({ code: "bootstrap_expired", message: "The bootstrap token expired", recovery_action: "use_local_owner_command" }, 410));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "Create the first administrator" });
    const password = "a-local-password-with-length";
    await user.type(screen.getByLabelText("Administrator username"), "local-admin");
    await user.type(screen.getByLabelText("Password", { exact: true }), password);
    await user.type(screen.getByLabelText("Confirm password"), password);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));
    await screen.findByRole("heading", { name: "The setup token expired" });
    expect(screen.getByText(`${cli} admin bootstrap-renew`)).toBeTruthy();
  });

  it("never renders an auth error body that echoes a submitted secret", async () => {
    const leakedToken = "setup-token-that-must-never-appear-in-an-error";
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "required", expires_ms: null }))
      .mockImplementationOnce(() => json({ token: leakedToken, expires_ms: 1_900_000_000_000 }))
      .mockImplementationOnce(() => json({ code: "invalid_bootstrap_token", message: `Invalid token ${leakedToken}` }, 401));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("heading", { name: "Create the first administrator" });
    const password = "a-local-password-with-length";
    await user.type(screen.getByLabelText("Administrator username"), "local-admin");
    await user.type(screen.getByLabelText("Password", { exact: true }), password);
    await user.type(screen.getByLabelText("Confirm password"), password);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Administrator setup failed");
    expect(document.body.textContent).not.toContain(leakedToken);
    expect(document.body.textContent).not.toContain(password);
  });

  it("shows wait guidance for the real bootstrap admission throttle envelope", async () => {
    const token = "bootstrap-throttle-token-kept-out-of-visible-text";
    const password = "bootstrap-throttle-password";
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "required", expires_ms: null }))
      .mockImplementationOnce(() => json({ token, expires_ms: 1_900_000_000_000 }))
      .mockImplementationOnce(() => json(rateLimitedEnvelope("50000000-0000-4000-8000-000000000001"), 429));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: "Create the first administrator" });
    await user.type(screen.getByLabelText("Administrator username"), "local-admin");
    await user.type(screen.getByLabelText("Password", { exact: true }), password);
    await user.type(screen.getByLabelText("Confirm password"), password);
    await user.click(screen.getByRole("button", { name: "Create administrator" }));

    expect((await screen.findByRole("alert")).textContent).toBe("Too many sign-in attempts. Wait before trying again.");
    expect(document.body.textContent).not.toContain(token);
    expect(document.body.textContent).not.toContain(password);
    expect(document.body.textContent).not.toContain("login_rate_limited");
  });

  it("shows wait guidance for the real login throttle envelope", async () => {
    const password = "login-throttle-password";
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "configured", expires_ms: null }))
      .mockImplementationOnce(() => json({ code: "authentication_required", message: "Authentication required" }, 401))
      .mockImplementationOnce(() => json(rateLimitedEnvelope("50000000-0000-4000-8000-000000000002"), 429));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: "Sign in" });
    await user.type(screen.getByLabelText("Username"), "local-admin");
    await user.type(screen.getByLabelText("Password"), password);
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect((await screen.findByRole("alert")).textContent).toBe("Too many sign-in attempts. Wait before trying again.");
    expect(document.body.textContent).not.toContain(password);
    expect(document.body.textContent).not.toContain("login_rate_limited");
  });

  it("uses the configured login, foundation status, CSRF logout, and no-target state", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "configured", expires_ms: null }))
      .mockImplementationOnce(() => json({ code: "authentication_required", message: "Authentication required" }, 401))
      .mockImplementationOnce(() => json(session))
      .mockImplementationOnce(() => json(deployment))
      .mockImplementationOnce(() => json(status))
      .mockImplementationOnce(() => json(emptyOverview))
      .mockImplementationOnce(() => json({ items: [], next_cursor: null }))
      .mockImplementationOnce(() => Promise.resolve(new Response(null, { status: 204 })));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: "Sign in" });
    expect(screen.getByText(`${cli} status`)).toBeTruthy();
    await user.type(screen.getByLabelText("Username"), "local-admin");
    await user.type(screen.getByLabelText("Password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await screen.findByRole("heading", { name: "Monitor status" });
    expect(screen.getByText("None sent by LLM Monitor")).toBeTruthy();
    expect(screen.getAllByText(`${cli} status`).length).toBeGreaterThan(0);
    expect(screen.getByText(`${cli} install check --role local`)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Sign out" }));
    await screen.findByText("Signed out.");

    const [path, options] = fetchMock.mock.calls[7] as [string, RequestInit];
    expect(path).toBe("/api/v1/auth/session");
    expect(options.method).toBe("DELETE");
    expect(new Headers(options.headers).get("X-CSRF-Token")).toBe(session.csrf_token);
  });

  it("does not replay a successful login when the authenticated status read fails", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "configured", expires_ms: null }))
      .mockImplementationOnce(() => json({ code: "authentication_required", message: "Authentication required" }, 401))
      .mockImplementationOnce(() => json(session))
      .mockImplementationOnce(() => json({ code: "status_unavailable", message: "Status is temporarily unavailable" }, 503))
      .mockImplementationOnce(() => json(status))
      .mockImplementationOnce(() => json(emptyOverview))
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "configured", expires_ms: null }))
      .mockImplementationOnce(() => json(session))
      .mockImplementationOnce(() => json(deployment))
      .mockImplementationOnce(() => json(status))
      .mockImplementationOnce(() => json(emptyOverview))
      .mockImplementationOnce(() => json({ items: [], next_cursor: null }));
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    render(<App />);

    await screen.findByRole("heading", { name: "Sign in" });
    await user.type(screen.getByLabelText("Username"), "local-admin");
    await user.type(screen.getByLabelText("Password"), "correct horse battery staple");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await screen.findByRole("heading", { name: "Cannot reach the monitor" });
    expect(fetchMock.mock.calls.filter(([path]) => path === "/api/v1/auth/sessions")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Try again" }));
    await screen.findByRole("heading", { name: "Monitor status" });
    expect(fetchMock.mock.calls.filter(([path]) => path === "/api/v1/auth/sessions")).toHaveLength(1);
  });

  it("announces a session lost while authenticated", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "configured", expires_ms: null }))
      .mockImplementationOnce(() => json(session))
      .mockImplementationOnce(() => json({ code: "authentication_required", message: "Authentication required" }, 401))
      .mockImplementationOnce(() => json(status))
      .mockImplementationOnce(() => json(emptyOverview));
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);

    await screen.findByRole("heading", { name: "Sign in" });
    expect(screen.getByText("Your session ended. Sign in again.")).toBeTruthy();
  });

  it("announces local validation errors without sending a secret", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(() => json({ schema_version: "1.0", state: "required", expires_ms: null }))
      .mockImplementationOnce(() => json({ token: bootstrapToken, expires_ms: 1_900_000_000_000 }));
    vi.stubGlobal("fetch", fetchMock);
    render(<App />);
    await screen.findByRole("heading", { name: "Create the first administrator" });
    await waitFor(() => expect((screen.getByRole("button", { name: "Create administrator" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.submit(screen.getByRole("button", { name: "Create administrator" }).closest("form")!);
    expect((await screen.findByRole("alert")).textContent).toContain("administrator username");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
  });
});
