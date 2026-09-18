import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { InvestigationWorkspace, type InvestigationSelection } from "./Investigation";
import type { IncidentAnnotation, IncidentDetail, IncidentSummary, MutationAccess } from "./api";

const incidentID = "10000000-0000-4000-8000-000000000010";
const annotationID = "10000000-0000-4000-8000-000000000020";
const secondAnnotationID = "10000000-0000-4000-8000-000000000021";
const startMS = 1_800_000_000_000;
const endMS = startMS + 300_000;
const scopeID = "10000000-0000-4000-8000-000000000001";

const access: MutationAccess = {
  role: "admin",
  csrfToken: "csrf-token-000000000000000000000000",
  generation: "10000000-0000-4000-8000-000000000002",
  mutationsAllowed: true,
};

const selection: InvestigationSelection = {
  scope: {
    id: scopeID,
    kind: "host",
    display_name: "Retained Mac",
    retired: false,
    host_id: scopeID,
    target_id: null,
    earliest_retained_ms: startMS - 300_000,
    latest_retained_ms: endMS,
    metrics: ["host.cpu.busy_ratio"],
  },
  startMS,
  endMS,
  timezone: "UTC",
  fixed: true,
};

const summary = {
  schema_version: "1.0",
  id: incidentID,
  revision: 1,
  title: "Pressure review",
  origin: "manual",
  scope: { kind: "host", id: scopeID },
  start_ms: startMS,
  end_ms: endMS,
  workflow_state: "open",
  owner_user_id: null,
  evidence_status: "partial",
  capsule_sha256: "a".repeat(64),
  created_ms: endMS,
  updated_ms: endMS,
} satisfies IncidentSummary;

function annotation(id = annotationID, text = "Operator observed a foreground export.", revision = 1): IncidentAnnotation {
  return { id, revision, incident_id: incidentID, declared_time_ms: endMS, text, author_user_id: "10000000-0000-4000-8000-000000000003", edited_ms: revision > 1 ? endMS + 1 : null, created_ms: endMS, provenance: "operator_declared" };
}

function detail(notes: IncidentAnnotation[] = [], cursor: string | null = null): IncidentDetail {
  return {
    ...summary,
    annotations: notes,
    annotations_next_cursor: cursor,
    capsule: {
      schema_revision: "incident-capsule-1",
      catalogue_revision: "ec01-ec07-mac-1",
      generated_ms: endMS,
      scope: summary.scope,
      focus_window: { start_ms: startMS, end_ms: endMS },
      baseline_window: { start_ms: startMS - 300_000, end_ms: startMS },
      evidence_state: "partial",
      collapsed_card_count: 0,
      cards: [{
        card_id: "EC07",
        priority: 7,
        copy_template_id: "ec07_evidence_limits",
        scope: summary.scope,
        title: "Evidence limits",
        summary: "Passive request timing is unavailable. No request samples does not mean no inference traffic.",
        eligibility: "insufficient",
        reason_codes: ["passive_request_timing_unavailable"],
        requested_window: { start_ms: startMS, end_ms: endMS },
        effective_window: null,
        coverage_ratio: null,
        source_ids: [],
        definition_revisions: [],
        config_ids: [],
        inputs: [],
        gaps: [],
        referenced_event_ids: [],
        source_links: [{ scope_id: scopeID, metric: "host.cpu.busy_ratio", start_ms: startMS, end_ms: endMS }],
        next_check_code: "collect_reviewed_evidence",
        next_check_label: "Collect a reviewed observation.",
      }],
    },
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

it("restores saved manual evidence and follows bounded incident and note pages", async () => {
  const secondIncident = { ...summary, id: "10000000-0000-4000-8000-000000000011", title: "Older review" };
  const fetchMock = vi.fn().mockImplementation((path: string) => {
    if (path === "/api/v1/incidents") return json({ items: [summary], next_cursor: summary.id });
    if (path.includes(`/api/v1/incidents?cursor=${summary.id}`)) return json({ items: [secondIncident], next_cursor: null });
    if (path === `/api/v1/incidents/${incidentID}`) return json(detail([annotation()], annotationID));
    if (path.includes(`/api/v1/incidents/${incidentID}/annotations?cursor=${annotationID}`)) return json({ items: [annotation(secondAnnotationID, "Second retained note.")], next_cursor: null });
    throw new Error(`unexpected request ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  window.history.replaceState(null, "", `/?incident=${incidentID}`);
  render(<InvestigationWorkspace selection={selection} access={access} onSessionLost={() => {}} />);

  expect((await screen.findAllByText("Pressure review")).length).toBeGreaterThan(0);
  expect(await screen.findByText("Evidence limits")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Load more investigations" }));
  expect(await screen.findByText("Older review")).toBeTruthy();
  expect(screen.getByText("Manual · no alert state")).toBeTruthy();
  expect(screen.queryByText(/FIRING/)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Load more notes" }));
  expect(await screen.findByText("Second retained note.")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Open host.cpu.busy_ratio evidence" }).getAttribute("href")).toContain("metric=host.cpu.busy_ratio");
  fireEvent.click(screen.getByRole("button", { name: "Back to investigation list" }));
  expect(new URL(window.location.href).searchParams.get("incident")).toBeNull();
});

it("saves an absolute window and audits note revisions through typed mutations", async () => {
  const firstNote = annotation();
  const edited = annotation(annotationID, "Corrected operator observation.", 2);
  let currentIncident = detail();
  const fetchMock = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (path === "/api/v1/incidents" && !init?.method) return json({ items: [], next_cursor: null });
    if (path === "/api/v1/incidents" && init?.method === "POST") return json(currentIncident, 201);
    if (path === `/api/v1/incidents/${incidentID}` && !init?.method) return json(currentIncident);
    if (path === `/api/v1/incidents/${incidentID}` && init?.method === "PATCH") {
      const update = JSON.parse(String(init.body)) as { title?: string; workflow_state?: "open" | "closed" };
      currentIncident = { ...currentIncident, ...update, revision: currentIncident.revision + 1, updated_ms: currentIncident.updated_ms + 1 };
      return json(currentIncident);
    }
    if (path === "/api/v1/annotations" && init?.method === "POST") return json(firstNote, 201);
    if (path === `/api/v1/annotations/${annotationID}` && init?.method === "PATCH") return json(edited);
    throw new Error(`unexpected request ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<InvestigationWorkspace selection={selection} access={access} onSessionLost={() => {}} />);

  await screen.findByText("No investigation or alert has been saved.");
  fireEvent.click(screen.getByRole("button", { name: "Save selected range" }));
  expect(await screen.findByText("Evidence limits")).toBeTruthy();
  expect(new URL(window.location.href).searchParams.get("incident")).toBe(incidentID);
  fireEvent.change(screen.getByLabelText("Rename investigation"), { target: { value: "Renamed pressure review" } });
  fireEvent.click(screen.getByRole("button", { name: "Save title" }));
  expect(await screen.findByRole("heading", { name: "Renamed pressure review" })).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Close investigation" }));
  fireEvent.click(await screen.findByRole("button", { name: "Reopen investigation" }));
  expect(await screen.findByRole("button", { name: "Close investigation" })).toBeTruthy();
  fireEvent.change(screen.getByLabelText("Add a plain-text note"), { target: { value: firstNote.text } });
  fireEvent.click(screen.getByRole("button", { name: "Add note" }));
  expect(await screen.findByText(firstNote.text)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Edit note" }));
  fireEvent.change(screen.getByLabelText("Edit note"), { target: { value: edited.text } });
  fireEvent.click(screen.getByRole("button", { name: "Save note revision" }));
  expect(await screen.findByText(edited.text)).toBeTruthy();

  await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(`/api/v1/annotations/${annotationID}`, expect.objectContaining({ method: "PATCH" })));
  const create = fetchMock.mock.calls.find(([path, init]) => path === "/api/v1/incidents" && init?.method === "POST");
  expect(JSON.parse(String(create?.[1]?.body))).toMatchObject({ scope: { kind: "host", id: scopeID }, start: new Date(startMS).toISOString(), end: new Date(endMS).toISOString() });
  const metadataUpdates = fetchMock.mock.calls.filter(([path, init]) => path === `/api/v1/incidents/${incidentID}` && init?.method === "PATCH");
  expect(metadataUpdates.map(([, init]) => JSON.parse(String(init?.body)))).toEqual([
    { expected_revision: 1, title: "Renamed pressure review" },
    { expected_revision: 2, workflow_state: "closed" },
    { expected_revision: 3, workflow_state: "open" },
  ]);
});

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
}

it("keeps note drafts with their incident and ignores a late detail response", async () => {
  const otherID = "10000000-0000-4000-8000-000000000011";
  const other = { ...detail(), id: otherID, title: "Other investigation" };
  let delayed: ((response: Response) => void) | undefined;
  let delayFirst = false;
  const fetchMock = vi.fn().mockImplementation((path: string) => {
    if (path === "/api/v1/incidents") return json({ items: [summary, other], next_cursor: null });
    if (path === `/api/v1/incidents/${incidentID}`) {
      if (delayFirst) return new Promise<Response>((resolve) => { delayed = resolve; });
      return json(detail([annotation()]));
    }
    if (path === `/api/v1/incidents/${otherID}`) return json(other);
    throw new Error(`unexpected request ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<InvestigationWorkspace selection={selection} access={access} onSessionLost={() => {}} />);
  fireEvent.click((await screen.findAllByRole("button", { name: "View" }))[0]);
  fireEvent.click(await screen.findByRole("button", { name: "Edit note" }));
  fireEvent.change(screen.getByLabelText("Edit note"), { target: { value: "Draft for first incident" } });
  fireEvent.click(screen.getAllByRole("button", { name: "View" })[1]);
  await screen.findByRole("heading", { name: "Other investigation" });
  expect(screen.queryByRole("button", { name: "Save note revision" })).toBeNull();
  fireEvent.click(screen.getAllByRole("button", { name: "View" })[0]);
  await screen.findByLabelText("Edit note");
  expect((screen.getByLabelText("Edit note") as HTMLTextAreaElement).value).toBe("Draft for first incident");
  delayFirst = true;
  fireEvent.click(screen.getAllByRole("button", { name: "View" })[0]);
  fireEvent.click(screen.getAllByRole("button", { name: "View" })[1]);
  await screen.findByRole("heading", { name: "Other investigation" });
  await act(async () => { delayed?.(new Response(JSON.stringify(detail([annotation()])))); });
  expect(screen.getByRole("heading", { name: "Other investigation" })).toBeTruthy();
  expect(new URL(window.location.href).searchParams.get("incident")).toBe(otherID);
  expect(fetchMock.mock.calls.some(([, init]) => init?.method === "PATCH")).toBe(false);
});

it("retries lost incident and note responses with the same exact request", async () => {
  let creates = 0;
  let notes = 0;
  const fetchMock = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (path === "/api/v1/incidents" && !init?.method) return json({ items: [], next_cursor: null });
    if (path === "/api/v1/incidents" && init?.method === "POST") {
      if (++creates === 1) return Promise.reject(new TypeError("response lost after commit"));
      return json(summary, 201);
    }
    if (path === `/api/v1/incidents/${incidentID}`) return json(detail());
    if (path === "/api/v1/annotations") {
      if (++notes === 1) return Promise.reject(new TypeError("response lost after commit"));
      return json(annotation(), 201);
    }
    throw new Error(`unexpected request ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<InvestigationWorkspace selection={selection} access={access} onSessionLost={() => {}} />);
  await screen.findByText("No investigation or alert has been saved.");
  fireEvent.click(screen.getByRole("button", { name: "Save selected range" }));
  await screen.findByRole("alert");
  fireEvent.click(screen.getByRole("button", { name: "Save selected range" }));
  await screen.findByText("Evidence limits");
  fireEvent.change(screen.getByLabelText("Add a plain-text note"), { target: { value: annotation().text } });
  fireEvent.click(screen.getByRole("button", { name: "Add note" }));
  await screen.findByRole("alert");
  fireEvent.click(screen.getByRole("button", { name: "Add note" }));
  await screen.findByText(annotation().text);
  for (const path of ["/api/v1/incidents", "/api/v1/annotations"]) {
    const writes = fetchMock.mock.calls.filter(([url, init]) => url === path && init?.method === "POST");
    expect(writes).toHaveLength(2);
    expect(writes[0][1]?.body).toBe(writes[1][1]?.body);
    expect(new Headers(writes[0][1]?.headers).get("Idempotency-Key")).toBe(new Headers(writes[1][1]?.headers).get("Idempotency-Key"));
  }
});

it("blocks A to B to A navigation while a note save is pending, then allows navigation", async () => {
  const otherID = "10000000-0000-4000-8000-000000000011";
  const other = { ...detail(), id: otherID, title: "Other investigation" };
  let completeNote: ((response: Response) => void) | undefined;
  vi.stubGlobal("fetch", vi.fn().mockImplementation((path: string) => {
    if (path === "/api/v1/incidents") return json({ items: [summary, other], next_cursor: null });
    if (path === `/api/v1/incidents/${incidentID}`) return json(detail());
    if (path === `/api/v1/incidents/${otherID}`) return json(other);
    if (path === "/api/v1/annotations") return new Promise<Response>((resolve) => { completeNote = resolve; });
    throw new Error(`unexpected request ${path}`);
  }));
  render(<InvestigationWorkspace selection={selection} access={access} onSessionLost={() => {}} />);
  fireEvent.click((await screen.findAllByRole("button", { name: "View" }))[0]);
  fireEvent.change(await screen.findByLabelText("Add a plain-text note"), { target: { value: annotation().text } });
  fireEvent.click(screen.getByRole("button", { name: "Add note" }));
  for (const button of screen.getAllByRole("button", { name: "View" })) expect((button as HTMLButtonElement).disabled).toBe(true);
  expect((screen.getByRole("button", { name: "Back to investigation list" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getAllByRole("button", { name: "View" })[1]);
  fireEvent.click(screen.getAllByRole("button", { name: "View" })[0]);
  expect(screen.getByRole("heading", { name: "Pressure review" })).toBeTruthy();
  await act(async () => { completeNote?.(new Response(JSON.stringify(annotation()), { status: 201 })); });
  expect(await screen.findByText(annotation().text)).toBeTruthy();
  expect((screen.getByLabelText("Add a plain-text note") as HTMLTextAreaElement).value).toBe("");
  expect((screen.getByRole("button", { name: "Add note" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(screen.getAllByRole("button", { name: "View" })[1]);
  await screen.findByRole("heading", { name: "Other investigation" });
  expect(screen.queryByText(annotation().text)).toBeNull();
});

it("retains committed edit identities and distinguishes saved evidence from failed detail loading", async () => {
  let loads = 0;
  const attempts = new Map<string, number>();
  const fetchMock = vi.fn().mockImplementation((path: string, init?: RequestInit) => {
    if (path === "/api/v1/incidents" && !init?.method) return json({ items: [], next_cursor: null });
    if (path === "/api/v1/incidents" && init?.method === "POST") return json(summary, 201);
    if (path === `/api/v1/incidents/${incidentID}` && !init?.method) {
      if (++loads === 1) return Promise.reject(new TypeError("detail read failed"));
      return json(detail([annotation()]));
    }
    if (init?.method === "PATCH") {
      const count = (attempts.get(path) ?? 0) + 1;
      attempts.set(path, count);
      if (count === 1) return Promise.reject(new TypeError("edit committed, response lost"));
      const body = JSON.parse(String(init.body));
      return path.includes("annotations") ? json(annotation(annotationID, body.text, 2)) : json({ ...summary, title: body.title, revision: 2 });
    }
    throw new Error(`unexpected request ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  render(<InvestigationWorkspace selection={selection} access={access} onSessionLost={() => {}} />);
  await screen.findByText("No investigation or alert has been saved.");
  fireEvent.click(screen.getByRole("button", { name: "Save selected range" }));
  expect((await screen.findByRole("alert")).textContent).toContain("Investigation saved.");
  fireEvent.click(screen.getByRole("button", { name: "Save selected range" }));
  await screen.findByText("Evidence limits");
  fireEvent.change(screen.getByLabelText("Rename investigation"), { target: { value: "Retried rename" } });
  fireEvent.click(screen.getByRole("button", { name: "Save title" }));
  await screen.findByRole("alert");
  fireEvent.click(screen.getByRole("button", { name: "Save title" }));
  await screen.findByRole("heading", { name: "Retried rename" });
  fireEvent.click(screen.getByRole("button", { name: "Edit note" }));
  fireEvent.change(screen.getByLabelText("Edit note"), { target: { value: "Retried note edit" } });
  fireEvent.click(screen.getByRole("button", { name: "Save note revision" }));
  await screen.findByRole("alert");
  fireEvent.click(screen.getByRole("button", { name: "Save note revision" }));
  await screen.findByText("Retried note edit");
  for (const [path, method] of [["/api/v1/incidents", "POST"], [`/api/v1/incidents/${incidentID}`, "PATCH"], [`/api/v1/annotations/${annotationID}`, "PATCH"]]) {
    const writes = fetchMock.mock.calls.filter(([url, init]) => url === path && init?.method === method);
    expect(writes).toHaveLength(2);
    expect(writes[0][1]?.body).toBe(writes[1][1]?.body);
    expect(new Headers(writes[0][1]?.headers).get("Idempotency-Key")).toBe(new Headers(writes[1][1]?.headers).get("Idempotency-Key"));
  }
});

function alertDetail(): IncidentDetail {
  return {
    ...detail(), origin: "alert", end_ms: null,
    alert_state: {
      incident_id: incidentID, instance_id: annotationID, rule_id: scopeID, rule_version: 2,
      condition: "FIRING", data_state: "stale", acknowledged_by: scopeID, acknowledged_ms: endMS,
      muted_until_ms: null, transition_seq: 1, active_generation: 1,
      delivery: { total: 1, pending: 0, leased: 0, sent: 0, failed: 1, expired: 0, superseded_before_delivery: 0, muted: 0 },
      deliveries: [{ id: "10000000-0000-4000-8000-000000000030", destination_id: "10000000-0000-4000-8000-000000000031", destination_revision: 1, state: "failed", status: "terminal_failure", attempts: 1, next_attempt_ms: null, safe_error_code: "webhook_receiver_rejected", receiver_ack_ms: null, accepted_unknown: false }],
    },
    capsule: {
      schema_revision: "alert-trigger-capsule-1", card_revision: "ec01-ec07-mac-1", incident_id: incidentID, instance_id: annotationID,
      rule: { id: scopeID, version: 2, evaluator_type: "heavy_cpu", scope_id: scopeID, scope_fingerprint: "a".repeat(64), incarnation_policy: "stable_scope" },
      evaluation: { event_ms: endMS, input_cursor_ordinal: 12, input_sha256: "b".repeat(64), previous_state: "PENDING", new_state: "FIRING", data_state: "valid", predicate: "match", reason: "cpu_high", observed_dwell_ms: 60000, evidence_sha256: "b".repeat(64) },
      evidence: { metric_id: "host.cpu.busy_ratio", unit: "ratio", window_start_ms: startMS, window_end_ms: endMS, observed_ms: endMS - 1, quality: "measured", number_value: 0.95, state_value: null, boolean_value: null, valid_n: null, completed_n: null, source_samples: [], source_sample_count: 17, source_samples_truncated: true, request_sample_ids: [], request_sample_count: 0, request_samples_truncated: false, definition_revision: "mac-ollama-1", method_revision: "fixture-1", gaps: [], unavailable_reasons: [] },
    },
  };
}

it("renders an ongoing alert's original trigger without offering manual resolution", async () => {
  const alert = alertDetail();
  vi.stubGlobal("fetch", vi.fn((path: string) => path === "/api/v1/incidents" ? json({ items: [alert], next_cursor: null }) : json(alert)));
  window.history.replaceState(null, "", `/?incident=${incidentID}`);
  render(<InvestigationWorkspace selection={null} access={access} onSessionLost={() => {}} />);
  expect(await screen.findByRole("heading", { name: "Original trigger evidence" })).toBeTruthy();
  expect(screen.getByText(/identity list truncated/)).toBeTruthy();
  expect(screen.getByText("60 seconds")).toBeTruthy();
  expect(screen.getByText("FIRING")).toBeTruthy();
  expect(screen.getByText("stale")).toBeTruthy();
  expect(screen.getByText(/Acknowledged at/)).toBeTruthy();
  expect(screen.getByText(/notification did not complete successfully/)).toBeTruthy();
  expect(screen.getByLabelText("Notification delivery records").textContent).toContain("Terminal failure");
  expect(screen.getByLabelText("Notification delivery records").textContent).toContain("webhook_receiver_rejected");
  expect(screen.queryByRole("button", { name: "Close investigation" })).toBeNull();
  expect(screen.queryByLabelText("Rename investigation")).toBeNull();
  expect(screen.queryByText("Manual · no alert state")).toBeNull();
});

it("preserves a delivery-mute retry and refreshes state without resolving the condition", async () => {
  let current = alertDetail();
  const writes: RequestInit[] = [];
  let complete: ((value: Response) => void) | undefined;
  vi.stubGlobal("fetch", vi.fn((path: string, init?: RequestInit) => {
    if (path.endsWith("/mute") && init?.method === "POST") {
      writes.push(init);
      if (writes.length === 1) return Promise.reject(new TypeError("response lost"));
      return new Promise<Response>(resolve => { complete = resolve; });
    }
    return path === "/api/v1/incidents" ? json({ items: [current], next_cursor: null }) : json(current);
  }));
  window.history.replaceState(null, "", `/?incident=${incidentID}`);
  render(<InvestigationWorkspace selection={null} access={access} onSessionLost={() => {}} />);
  fireEvent.change(await screen.findByLabelText("Mute reason"), { target: { value: "Planned maintenance" } });
  fireEvent.click(screen.getByRole("button", { name: "Mute delivery" }));
  await screen.findByRole("alert");
  fireEvent.click(screen.getByRole("button", { name: "Mute delivery" }));
  await waitFor(() => expect(writes).toHaveLength(2));
  expect(writes[0].body).toBe(writes[1].body);
  expect(new Headers(writes[0].headers).get("Idempotency-Key")).toBe(new Headers(writes[1].headers).get("Idempotency-Key"));
  expect(screen.getByRole("button", { name: "Back to investigation list" }).matches(":disabled")).toBe(true);
  const expires = JSON.parse(String(writes[1].body)).expires_ms as number;
  current = { ...current, alert_state: { ...current.alert_state!, muted_until_ms: expires } };
  await act(async () => { complete?.(new Response(JSON.stringify({ alert_state: current.alert_state, notification_may_be_in_flight: true }), { status: 200 })); });
  expect(await screen.findByText(/Alert action saved. One notification may still arrive/)).toBeTruthy();
  expect(screen.getByText("FIRING")).toBeTruthy();
  expect(screen.getByText(/Muted until/)).toBeTruthy();
  expect(screen.getByRole("button", { name: "Unmute delivery" }).matches(":disabled")).toBe(false);
});
