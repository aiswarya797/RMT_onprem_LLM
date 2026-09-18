export type BootstrapState = {
  schema_version: "1.0";
  state: "required" | "expired" | "configured";
  expires_ms: number | null;
};

export type BootstrapToken = {
  token: string;
  expires_ms: number;
};

export type EnrollmentToken = {
  host_id: string;
  token: string;
  expires_ms: number;
  hub_url: string;
  hub_ca_fingerprint_sha256: string;
};

export type EnrollmentStatus = {
  schema_version: "1.0";
  host_id: string;
  display_name: string;
  state: "waiting" | "connected" | "expired";
  created_ms: number;
  expires_ms: number;
  connected_ms?: number;
};

export type User = {
  id: string;
  revision: number;
  name: string;
  role: "admin" | "viewer";
  disabled: boolean;
  trust_generation: string;
  historical_restored: boolean;
};

export type Session = {
  user: User;
  expires_ms: number;
  csrf_token: string;
};

export type DeploymentState = {
  schema_version: "1.0";
  deployment_id: string;
  deployment_generation: string;
  recovery_state:
    | "normal"
    | "maintenance_pre_activation"
    | "restore_requires_bootstrap"
    | "recovery_blocked";
  recovery_point_ms: number | null;
  mutations_allowed: boolean;
};

export type EvaluatorStatus = { started: boolean; last_attempt_ms: number | null; last_success_ms: number | null; lag_ms: number; last_pass_failed: boolean };

export type FoundationStatus = {
  experimental_features?: boolean;
  schema_version: "1.0";
  generated_ms: number;
  deployment_state: DeploymentState;
  hub_state: "configured";
  collector_state: "not_registered" | "registered_not_observed" | "observing" | "stale_or_disconnected";
  target_state: "none" | "reachable" | "unreachable" | "partial_or_unknown";
  host_count: number;
  target_count: number;
  source_count: number;
  collection_started: boolean;
  inference_started: boolean;
  evaluator?: EvaluatorStatus;
  storage_state: "normal" | "warning" | "optional_jobs_stopped" | "bulk_ingest_paused" | "read_only_enospc";
};

export type SourceState = "not_observed" | "fresh" | "stale" | "disconnected" | "unavailable" | "incompatible" | "partial";

export type Provenance = {
  source: string;
  method_revision: string;
  verification: "direct_capture" | "operator_imported_unverified" | "declared_unverified" | "synthetic_fixture";
  observed_at_ms?: number;
  source_artifact_sha256?: string;
};

export type MissingCapability = { id: string; reason: string; detail_code: string | null };

export type MetricReading = {
  metric: string;
  unit: "ratio" | "state" | "bytes" | "boolean" | "milliseconds" | "tokens";
  scope_id: string;
  source_id: string | null;
  observed_ms: number | null;
  age_ms: number | null;
  value: number | boolean | string | null;
  quality: string;
  missing_reason: string | null;
  method_revision: string;
  provenance: Provenance;
};

export type ProcessSummary = {
  eligible_pid_count: number;
  examined_pid_count: number;
  permission_denied_count: number;
  retained_process_count: number;
  enumeration_truncated: boolean;
  coverage: "complete" | "partial";
  method_revision: string;
  sample_interval_ms: number;
  scan_duration_ms: number;
};

export type ProcessObservation = {
	host_id: string;
	boot_id: string;
	pid: number;
	process_start_identity: string;
  process_key: string;
  display_basename: string | null;
  category: "selected_ollama" | "rmt" | "other_same_user";
  association_quality: "verified" | "declared_unverified" | "none";
  cpu_busy_ratio: number | null;
  physical_footprint_bytes: string | null;
	target_id: string | null;
	missing: MissingCapability[];
	provenance: Provenance;
};

export type NetworkObservation = {
	interface_id: string;
	boot_id: string;
	counter_epoch_id: string;
	loopback: boolean;
	received_bytes_total: string | null;
	sent_bytes_total: string | null;
	missing: MissingCapability[];
	provenance: Provenance;
};

export type HostOverview = {
  id: string;
  display_name: string;
  local?: boolean;
  state: "active" | "retired" | "revoked" | "not_reporting";
  source_state: SourceState;
  collector_version: string | null;
	current_session_generation: number;
	updated_ms: number;
  heartbeat_ms: number | null;
  heartbeat_age_ms: number | null;
  metrics: MetricReading[];
  network_observed_ms: number | null;
  network_age_ms: number | null;
	network_observations: NetworkObservation[];
  process_observed_ms: number | null;
  process_age_ms: number | null;
  process_summary: ProcessSummary | null;
  process_observations: ProcessObservation[];
  capabilities_missing: MissingCapability[];
};

export type ModelOverview = {
  id: string;
  alias?: string | null;
  digest: string | null;
  loaded: boolean;
  load_state?: "reported_loaded" | "reported_not_loaded" | "unavailable" | string;
  reported_size_bytes: string | null;
  reported_size_vram_bytes: string | null;
  provenance: Provenance;
};

export type TargetOverview = {
  id: string;
  host_id: string;
  host_local?: boolean;
  display_name: string;
  adapter_id: "ollama";
  association_state: "verified" | "declared_unverified" | "ambiguous";
  retired: boolean;
  source_state: SourceState;
  reachable: MetricReading;
  models_state: SourceState;
  models_observed_ms: number | null;
  models_age_ms: number | null;
  models: ModelOverview[];
  capabilities_missing: MissingCapability[];
};

export type Overview = {
  generated_ms: number;
  deployment_state: DeploymentState;
  state: SourceState;
  host_count: number;
  target_count: number;
  open_incident_count: number;
  observed_request_population: "present" | "absent" | "partial" | "expired";
  history_available: boolean;
  hosts: HostOverview[];
  targets: TargetOverview[];
  capabilities_missing: MissingCapability[];
};

export type Series = {
  schema_version: "1.0";
  metric: string;
  definition_revision: string;
  unit: string;
  requested_range: SeriesRange;
  effective_range: SeriesRange | null;
  population: string;
  host_id: string | null;
  source_id: string | null;
  resolution_tier: "raw" | "minute" | "hour" | null;
  method_revision: string | null;
  epoch_id: string | null;
  clock_method: "single_host_monotonic_aligned" | "cross_host_aligned" | "alignment_unavailable" | "monotonic" | null;
  coverage_ratio: number | null;
  population_key: unknown;
  completed_count: number;
  cancelled_count: number;
  failed_count: number;
  incomplete_count: number;
  summary: unknown;
  points: Array<{ time_ms: number; value: number | boolean | string | null; quality: string; missing_reason: string | null; epoch_id: string | null }>;
  gaps: Array<{ start_ms: number; end_ms: number; reason: string }>;
  warnings: string[];
};

export type SeriesRange = {
  start: string;
  end: string;
  start_ms: number;
  end_ms: number;
  inclusive_start_exclusive_end: true;
};

export type HistoryScope = {
  id: string;
  kind: "host" | "runtime" | "model" | "process";
  display_name: string;
  retired: boolean;
  host_id: string;
  target_id: string | null;
  earliest_retained_ms: number;
  latest_retained_ms: number;
  metrics: string[];
};

export type HistoryCatalog = {
  schema_version: "1.0";
  generated_ms: number;
  earliest_retained_ms: number | null;
  latest_retained_ms: number | null;
  scopes: HistoryScope[];
  truncated: boolean;
};

export type InvestigationScope = Pick<HistoryScope, "id" | "kind">;

export type InvestigationWindow = { start_ms: number; end_ms: number };

export type EvidenceCard = {
  card_id: "EC01" | "EC02" | "EC03" | "EC04" | "EC05" | "EC06" | "EC07";
  priority: number;
  copy_template_id: string;
  scope: InvestigationScope;
  title: string;
  summary: string;
  eligibility: "eligible" | "insufficient" | "not_observed";
  reason_codes: string[];
  requested_window: InvestigationWindow;
  effective_window: InvestigationWindow | null;
  coverage_ratio: number | null;
  source_ids: string[];
  definition_revisions: string[];
  config_ids: string[];
  inputs: Array<{ name: string; value: number | boolean | string | null; unit: string; observed_ms: number | null; quality: string; missing_reason: string | null; provenance: Provenance }>;
  gaps: Array<{ start_ms: number; end_ms: number; reason: string }>;
  referenced_event_ids: string[];
  source_links: Array<{ scope_id: string; metric: string; start_ms: number; end_ms: number }>;
  next_check_code: string;
  next_check_label: string;
};

export type IncidentCapsule = {
  schema_revision: "incident-capsule-1";
  catalogue_revision: "ec01-ec07-mac-1";
  generated_ms: number;
  scope: InvestigationScope;
  focus_window: InvestigationWindow;
  baseline_window: InvestigationWindow;
  evidence_state: "complete" | "partial";
  cards: EvidenceCard[];
  collapsed_card_count: number;
};

export type IncidentAnnotation = {
  id: string;
  revision: number;
  incident_id: string;
  declared_time_ms: number;
  text: string;
  author_user_id: string;
  edited_ms: number | null;
  created_ms: number;
  provenance: "operator_declared";
};

export type IncidentSummary = {
  schema_version: "1.0";
  id: string;
  revision: number;
  title: string;
  origin: "manual" | "alert";
  scope: InvestigationScope | { kind: "deployment"; id: string };
  start_ms: number;
  end_ms: number | null;
  workflow_state: "open" | "closed";
  owner_user_id: string | null;
  evidence_status: "available" | "partial" | "expired";
  capsule_sha256: string;
  created_ms: number;
  updated_ms: number;
  alert_state?: AlertIncidentState;
};

export type IncidentDetail = IncidentSummary & {
  capsule: IncidentCapsule | AlertTriggerCapsule | null;
  annotations: IncidentAnnotation[];
  annotations_next_cursor: string | null;
  comparisons?: ComparisonReference[];
};

export type IncidentList = { items: IncidentSummary[]; next_cursor: string | null };
export type IncidentAnnotationList = { items: IncidentAnnotation[]; next_cursor: string | null };

export type MutationAccess = {
  role: "admin" | "viewer";
  csrfToken: string;
  generation: string;
  mutationsAllowed: boolean;
};

export type RequestPopulationKey = RuleRequestPopulation;
export type RequestSummaryStats = {
  valid_n: number;
  minimum: number;
  median: number;
  maximum: number;
  p95: number | null;
  algorithm: string;
};
export type RequestSummary = {
  schema_version: "1.0";
  aggregation_revision: string;
  population_key: RequestPopulationKey;
  population_status: "complete" | "partial" | "expired";
  run_ids: string[];
  metric_id: string;
  completed_count: number;
  valid_count: number;
  failed_count: number;
  cancelled_count: number;
  incomplete_count: number;
  provenance_key: Record<string, string>;
  summary: RequestSummaryStats | null;
  warnings: string[];
};
export type DeclaredIntervention = {
  type: "runtime_version" | "config_revision" | "generation_option";
  field: string;
  before_value_sha256: string;
  after_value_sha256: string;
  declaration_id: string;
  declared_time_ms: number;
};
export type RequestComparison = {
  comparison_kind: "request_run";
  scope_id: string;
  metric_id: string;
  before_run_id: string;
  after_run_id: string;
  declared_intervention: DeclaredIntervention | null;
};

export type RequestOffsets = {
  submit: string;
  headers: string | null;
  first_byte: string | null;
  first_thinking: string | null;
  first_content: string | null;
  end: string;
};
export type RequestMetrics = {
  "request.client.first_byte_ms": number | null;
  "request.client.first_content_ms": number | null;
  "request.client.total_ms": number | null;
  "request.runtime.total_duration_ms": number | null;
  "request.runtime.load_duration_ms": number | null;
  "request.runtime.prompt_eval_duration_ms": number | null;
  "request.runtime.eval_duration_ms": number | null;
  "request.runtime.prompt_tokens": number | null;
  "request.runtime.output_tokens": number | null;
};
export type RequestFieldProvenance = { source: string; verification: string; missing_reason: string | null };
export type RequestSample = {
  schema_version: "1.0";
  sample_id: string;
  run_id: string;
  source_kind: "deliberate_probe";
  verification_state: "direct_capture";
  observation_scope: "explicit_observed_request";
  deployment_id: string;
  host_id: string;
  source_id: string;
  target_id: string;
  model_id: string;
  config_snapshot_id: string;
  population_key: RequestPopulationKey;
  runtime_source_pin_id: string;
  runtime_operation: "generate";
  terminal_record_observed: boolean;
  submitted_at_ms: number;
  offsets_ns: RequestOffsets;
  http_status: number | null;
  terminal_status: "completed" | "failed" | "cancelled" | "incomplete";
  done_reason: string | null;
  safe_error_category: string | null;
  metrics: RequestMetrics;
  field_provenance: Record<string, RequestFieldProvenance>;
  content_persistence: "none";
};
export type RequestRun = {
  schema_version: "1.0";
  run_id: string;
  deployment_id: string;
  host_id: string;
  source_id: string;
  target_id: string;
  model_id: string;
  config_snapshot_id: string;
  source_kind: "deliberate_probe";
  verification_state: "direct_capture";
  population_key: RequestPopulationKey;
  expected_count: 1;
  submitted_count: number;
  completed_count: number;
  failed_count: number;
  cancelled_count: number;
  incomplete_count: number;
  decoded_size_bytes: number;
  finalization_state: "finalized";
  partial_reason: string | null;
  content_persistence: "none";
  samples: RequestSample[];
};
export type LocalProbeRequest = {
  target_id: string;
  profile_id: "short_text_v1";
  count: 1;
  load_confirmation: { confirmation: "confirm_load"; profile_sha256: string; displayed_budget_sha256: string };
  confirm_deployment_id: string;
};
export type LocalProbeReceipt = {
  status: "succeeded" | "partial" | "failed" | "cancelled" | "blocked";
  run_id: string | null;
  requested_count: 1;
  submitted_count: 0 | 1;
  safe_code: string;
  reasons: string[];
};
export type ComparisonResult = {
  schema_version: "1.0";
  comparison_kind: "request_run";
  result_id: string | null;
  persisted: boolean;
  status: "insufficient_evidence" | "observed_change_with_confounds" | "observed_change_similar_recorded_conditions" | "no_clear_observed_change";
  metric_id: string;
  before: RequestSummary;
  after: RequestSummary;
  declared_intervention: DeclaredIntervention | null;
  confounds: string[];
  blocked_reasons: string[];
  claim_scope: "explicit_observed_requests_only_no_causal_claim";
};
export type ComparisonReference = {
  comparison_id: string;
  metric_id: string;
  status: ComparisonResult["status"] | "expired";
  before_run_id: string;
  after_run_id: string;
  created_ms: number;
  expires_ms: number;
};
export type ComparisonJob = {
  schema_version: "1.0";
  job_id: string;
  deployment_generation: string;
  type: "comparison" | "probe_import";
  state: "succeeded" | "failed" | "queued" | "running" | "cancelled";
  progress_ratio: number;
  created_ms: number;
  updated_ms: number;
  result: { resource_id: string; resource_type: "comparison" | "probe_run"; download_expires_ms: number | null } | null;
  error: { code: string; message: string; recovery_action: string } | null;
  cancel_state: string;
};

export type NotificationDestination = {
  id: string;
  revision: number;
  type: "webhook" | "smtp";
  display_name: string;
  enabled: boolean;
  secret_configured: boolean;
  configuration: {
    webhook: { https_url: string; hmac_enabled: boolean } | null;
    smtp: unknown | null;
  };
  last_test_ms: number | null;
  last_test_result: "succeeded" | "failed" | null;
  last_test_job_id: string | null;
};

export type WebhookDestinationDefinition = {
  expected_revision: number | null;
  type: "webhook";
  display_name: string;
  webhook: { https_url: string; hmac_enabled: boolean };
  smtp: null;
  secret_input: string | null;
};

export type NotificationTestJob = {
  schema_version: "1.0";
  job_id: string;
  deployment_generation: string;
  type: "destination_test";
  state: "queued" | "running" | "succeeded" | "failed" | "cancelled";
  progress_ratio: number;
  created_ms: number;
  updated_ms: number;
  result: { resource_id: string; resource_type: "notification_delivery"; download_expires_ms: number | null } | null;
  error: { code: string; message: string; recovery_action: string } | null;
  cancel_state: string;
  receiver_ack_ms?: number | null;
};

export type RuleType = "ollama_unreachable" | "host_not_reporting" | "source_missing" | "memory_pressure" | "heavy_cpu" | "observed_request_duration" | "disk_monitor_health";
export type RuleRequestPopulation = {
  target_id: string;
  model_digest: string;
  runtime_version: string;
  runtime_build: string | null;
  config_revision: string;
  profile_id: string;
  profile_sha256: string;
  options: {
    num_ctx: number;
    num_predict: number;
    temperature: number | null;
    seed: number | null;
    think: boolean | null;
    stream: boolean;
    cold_warm_policy: string;
  };
  concurrency: number;
  vantage_id: string;
  clock_method: string;
  source_kind: string;
  verification_state: string;
};
export type RuleDefinition = {
  expected_revision: number | null;
  evaluator_type: RuleType;
  scope_id: string;
  enabled: boolean;
  metric_id: string | null;
  request_population: RuleRequestPopulation | null;
  aggregation: "median" | "p95" | null;
  threshold: number | "warning" | null;
  dwell_ms: number;
  recovery_ms: number;
};
export type RuleRecord = {
  id: string;
  revision: number;
  definition: RuleDefinition;
  created_ms: number;
  updated_ms: number;
};

export type AlertCondition = "OK" | "PENDING" | "FIRING" | "RECOVERING" | "RESOLVED" | "superseded";
export type NotificationDeliveryStatus = "queued" | "attempted" | "acknowledged" | "retrying" | "suppressed" | "terminal_failure";
export type NotificationDelivery = {
  id: string;
  destination_id: string;
  destination_revision: number;
  state: "pending" | "leased" | "sent" | "failed" | "expired" | "superseded_before_delivery" | "muted";
  status: NotificationDeliveryStatus;
  attempts: number;
  next_attempt_ms: number | null;
  safe_error_code: string | null;
  receiver_ack_ms: number | null;
  accepted_unknown: boolean;
};
export type AlertIncidentState = {
  incident_id: string; instance_id: string; rule_id: string; rule_version: number;
  condition: AlertCondition; data_state: "valid" | "unknown" | "stale" | "incompatible";
  acknowledged_by: string | null; acknowledged_ms: number | null; muted_until_ms: number | null;
  transition_seq: number; active_generation: number;
  delivery: { total: number; pending: number; leased: number; sent: number; failed: number; expired: number; superseded_before_delivery: number; muted: number };
  deliveries: NotificationDelivery[];
};
export type AlertControlResult = { alert_state: AlertIncidentState; notification_may_be_in_flight: boolean };
export type AlertTriggerCapsule = {
  schema_revision: "alert-trigger-capsule-1";
  card_revision: "ec01-ec07-mac-1";
  incident_id: string;
  instance_id: string;
  rule: { id: string; version: number; evaluator_type: RuleType; scope_id: string; scope_fingerprint: string; incarnation_policy: string };
  evaluation: {
    event_ms: number; input_cursor_ordinal: number; input_sha256: string;
    previous_state: AlertCondition; new_state: "FIRING";
    data_state: "valid" | "unknown" | "stale" | "incompatible";
    predicate: "match" | "clear" | "hold"; reason: string;
    observed_dwell_ms: number; evidence_sha256: string;
  };
  evidence: {
    metric_id: string; unit: string; window_start_ms: number; window_end_ms: number; observed_ms: number;
    quality: string; number_value: number | null; state_value: string | null; boolean_value: boolean | null;
    valid_n: number | null; completed_n: number | null;
    source_samples: Array<{ collector_boot_id: string; source_id: string; sequence: number; config_ids: string[] }>;
    source_sample_count: number; source_samples_truncated: boolean;
    status_sample?: { host_id: string; collector_boot_id: string; session_generation: number; sequence: number; payload_sha256: string; observed_ms: number; admitted_ms: number };
    status_absence?: { host_id: string; collector_boot_id: string | null; session_generation: number; checked_ms: number };
    request_sample_ids: string[]; request_sample_count: number; request_samples_truncated: boolean;
    definition_revision: string; method_revision: string;
    gaps: Array<{ start_ms: number; end_ms: number; reason: string }>;
    unavailable_reasons: string[];
  };
};

type ErrorBody = {
  code?: string;
  message?: string;
  recovery_action?: string;
};

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly recoveryAction?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit, timeoutMS = 15_000): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body !== undefined) {
    headers.set("Content-Type", "application/json");
  }
  const controller = new AbortController();
	const externalSignal = init?.signal;
	const cancelFromCaller = () => controller.abort();
	if (externalSignal?.aborted) controller.abort();
	externalSignal?.addEventListener("abort", cancelFromCaller, { once: true });
  let timedOut = false;
  const timeout = window.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMS);
  try {
    const response = await fetch(path, {
      ...init,
      credentials: "same-origin",
      headers,
      signal: controller.signal,
    });
    if (!response.ok) {
      let body: ErrorBody = {};
      try {
        body = (await response.json()) as ErrorBody;
      } catch {
        // The UI still presents a bounded local error if a proxy changes the body.
      }
      throw new ApiError(
        response.status,
        body.code ?? "request_failed",
        body.message ?? "The local monitor could not complete this request.",
        body.recovery_action,
      );
    }
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (externalSignal?.aborted) {
      throw new ApiError(0, "request_cancelled", "The superseded local request was cancelled.");
    }
    if (timedOut) {
      throw new ApiError(0, "hub_timeout", "The local monitor took too long to respond.", "retry_later");
    }
    throw new ApiError(0, "hub_unreachable", "The local monitor did not respond.", "retry_later");
  } finally {
    window.clearTimeout(timeout);
		externalSignal?.removeEventListener("abort", cancelFromCaller);
  }
}

export const api = {
  acknowledgeIncident: (access: MutationAccess, id: string, observedTransitionSeq: number, retryKey: string) =>
    request<AlertControlResult>(`/api/v1/incidents/${encodeURIComponent(id)}/acknowledgements`, {
      method: "POST", headers: mutationHeaders(access, retryKey), body: JSON.stringify({ observed_transition_seq: observedTransitionSeq }),
    }),
  muteIncident: (access: MutationAccess, id: string, reason: string, expiresMS: number, retryKey: string) =>
    request<AlertControlResult>(`/api/v1/incidents/${encodeURIComponent(id)}/mute`, {
      method: "POST", headers: mutationHeaders(access, retryKey), body: JSON.stringify({ reason, expires_ms: expiresMS }),
    }),
  unmuteIncident: (access: MutationAccess, id: string, retryKey: string) =>
    request<AlertControlResult>(`/api/v1/incidents/${encodeURIComponent(id)}/mute`, {
      method: "DELETE", headers: mutationHeaders(access, retryKey),
    }),
  rules: (signal?: AbortSignal) => request<{ items: RuleRecord[] }>("/api/v1/rules", { signal }),
  rule: (id: string, signal?: AbortSignal) => request<RuleRecord>(`/api/v1/rules/${encodeURIComponent(id)}`, { signal }),
  createRule: (access: MutationAccess, definition: RuleDefinition, retryKey: string) =>
    request<RuleRecord>("/api/v1/rules", {
      method: "POST", headers: mutationHeaders(access, retryKey), body: JSON.stringify(definition),
    }),
	updateRule: (access: MutationAccess, id: string, definition: RuleDefinition, retryKey: string) =>
		request<RuleRecord>(`/api/v1/rules/${encodeURIComponent(id)}`, {
			method: "PUT", headers: mutationHeaders(access, retryKey), body: JSON.stringify(definition),
		}),
	destinations: (signal?: AbortSignal) => request<{ items: NotificationDestination[] }>("/api/v1/destinations", { signal }),
	createDestination: (access: MutationAccess, definition: WebhookDestinationDefinition, retryKey: string) =>
		request<NotificationDestination>("/api/v1/destinations", {
			method: "POST", headers: mutationHeaders(access, retryKey), body: JSON.stringify(definition),
		}),
	updateDestination: (access: MutationAccess, id: string, definition: WebhookDestinationDefinition, retryKey: string) =>
		request<NotificationDestination>(`/api/v1/destinations/${encodeURIComponent(id)}`, {
			method: "PUT", headers: mutationHeaders(access, retryKey), body: JSON.stringify(definition),
		}),
	testDestination: (access: MutationAccess, id: string, revision: number, retryKey: string) =>
		request<NotificationTestJob>(`/api/v1/destinations/${encodeURIComponent(id)}/tests`, {
			method: "POST", headers: { ...mutationHeaders(access, retryKey), "If-Match": String(revision) },
		}),
	notificationJob: (id: string, signal?: AbortSignal) => request<NotificationTestJob>(`/api/v1/jobs/${encodeURIComponent(id)}`, { signal }),
	notificationDelivery: (id: string, signal?: AbortSignal) => request<NotificationDelivery>(`/api/v1/deliveries/${encodeURIComponent(id)}`, { signal }),
	retryNotificationDelivery: (access: MutationAccess, id: string, retryKey: string) =>
		request<NotificationDelivery>(`/api/v1/deliveries/${encodeURIComponent(id)}/retry`, {
			method: "POST", headers: mutationHeaders(access, retryKey),
		}),
	bootstrapState: () => request<BootstrapState>("/api/v1/auth/bootstrap"),
	bootstrapToken: () => request<BootstrapToken>("/api/v1/auth/bootstrap/token"),
  bootstrapAdmin: (bootstrapToken: string, username: string, password: string) =>
    request<Session>("/api/v1/auth/bootstrap", {
      method: "POST",
      body: JSON.stringify({ bootstrap_token: bootstrapToken, username, password }),
    }),
  login: (username: string, password: string) =>
    request<Session>("/api/v1/auth/sessions", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  session: () => request<Session>("/api/v1/auth/session"),
  logout: (csrfToken: string) =>
    request<void>("/api/v1/auth/session", {
      method: "DELETE",
      headers: { "X-CSRF-Token": csrfToken },
    }),
  deploymentState: () => request<DeploymentState>("/api/v1/deployment-state"),
	createEnrollment: (access: MutationAccess, hostDisplayName: string, retryKey: string) =>
		request<EnrollmentToken>("/api/v1/enrollments", {
			method: "POST",
			headers: mutationHeaders(access, retryKey),
			body: JSON.stringify({ host_display_name: hostDisplayName, expires_in_seconds: 600 }),
		}),
	enrollmentStatus: (hostID: string, signal?: AbortSignal) =>
		request<EnrollmentStatus>(`/api/v1/enrollments/${encodeURIComponent(hostID)}/status`, { signal }),
	status: (signal?: AbortSignal) => request<FoundationStatus>("/api/v1/status", { signal }),
	overview: (signal?: AbortSignal) => request<Overview>("/api/v1/overview", { signal }),
	historyCatalog: (signal?: AbortSignal) => request<HistoryCatalog>("/api/v1/history/catalog", { signal }),
	series: (scope: string, metric: string, startMS: number, endMS: number, signal?: AbortSignal) => {
		const parameters = new URLSearchParams({
			scope,
			metric,
			start: new Date(startMS).toISOString(),
			end: new Date(endMS).toISOString(),
			resolution: "auto",
		});
		return request<Series>(`/api/v1/series?${parameters}`, { signal });
	},
	incidents: (signal?: AbortSignal, cursor?: string) => request<IncidentList>(`/api/v1/incidents${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ""}`, { signal }),
	incident: (id: string, signal?: AbortSignal) => request<IncidentDetail>(`/api/v1/incidents/${encodeURIComponent(id)}`, { signal }),
	incidentAnnotations: (id: string, cursor: string, signal?: AbortSignal) => request<IncidentAnnotationList>(`/api/v1/incidents/${encodeURIComponent(id)}/annotations?cursor=${encodeURIComponent(cursor)}`, { signal }),
	previewComparison: (value: Omit<RequestComparison, "declared_intervention">, signal?: AbortSignal) => {
		const parameters = new URLSearchParams({ comparison_kind: value.comparison_kind, scope_id: value.scope_id, metric_id: value.metric_id, before_run_id: value.before_run_id, after_run_id: value.after_run_id });
		return request<ComparisonResult>(`/api/v1/comparisons/preview?${parameters}`, { signal });
	},
	importProbe: (access: MutationAccess, input: unknown, retryKey: string) =>
		request<ComparisonJob>("/api/v1/probes", {
			method: "POST", headers: mutationHeaders(access, retryKey), body: JSON.stringify(input),
		}),
	runLocalProbe: (access: MutationAccess, input: LocalProbeRequest, retryKey: string) =>
		request<LocalProbeReceipt>("/api/v1/probes/run", {
			method: "POST", headers: mutationHeaders(access, retryKey), body: JSON.stringify(input),
		}, 75_000),
	probeRun: (id: string, signal?: AbortSignal) => request<RequestRun>(`/api/v1/probes/runs/${encodeURIComponent(id)}`, { signal }),
	createComparison: (access: MutationAccess, value: RequestComparison, retryKey: string) =>
		request<ComparisonJob>("/api/v1/comparisons", {
			method: "POST", headers: mutationHeaders(access, retryKey), body: JSON.stringify(value),
		}),
	comparison: (id: string, signal?: AbortSignal) => request<ComparisonResult>(`/api/v1/comparisons/${encodeURIComponent(id)}`, { signal }),
	comparisonJob: (id: string, signal?: AbortSignal) => request<ComparisonJob>(`/api/v1/jobs/${encodeURIComponent(id)}`, { signal }),
	attachComparison: (access: MutationAccess, incidentID: string, comparisonID: string, retryKey: string) =>
		request<IncidentDetail>(`/api/v1/incidents/${encodeURIComponent(incidentID)}/comparisons`, {
			method: "POST", headers: mutationHeaders(access, retryKey), body: JSON.stringify({ resource_id: comparisonID }),
		}),
	createIncident: (access: MutationAccess, title: string, scope: InvestigationScope, startMS: number, endMS: number, retryKey?: string) =>
		request<IncidentSummary>("/api/v1/incidents", {
			method: "POST",
			headers: mutationHeaders(access, retryKey),
			body: JSON.stringify({ title, scope, start: new Date(startMS).toISOString(), end: new Date(endMS).toISOString() }),
		}),
	updateIncident: (access: MutationAccess, incidentID: string, expectedRevision: number, update: { title?: string; workflow_state?: "open" | "closed" }, retryKey?: string) =>
		request<IncidentSummary>(`/api/v1/incidents/${encodeURIComponent(incidentID)}`, {
			method: "PATCH",
			headers: mutationHeaders(access, retryKey),
			body: JSON.stringify({ expected_revision: expectedRevision, ...update }),
		}),
	createAnnotation: (access: MutationAccess, incidentID: string, declaredTimeMS: number, text: string, retryKey?: string) =>
		request<IncidentAnnotation>("/api/v1/annotations", {
			method: "POST",
			headers: mutationHeaders(access, retryKey),
			body: JSON.stringify({ incident_id: incidentID, declared_time_ms: declaredTimeMS, text }),
		}),
	editAnnotation: (access: MutationAccess, annotationID: string, expectedRevision: number, text: string, retryKey?: string) =>
		request<IncidentAnnotation>(`/api/v1/annotations/${encodeURIComponent(annotationID)}`, {
			method: "PATCH",
			headers: mutationHeaders(access, retryKey),
			body: JSON.stringify({ expected_revision: expectedRevision, text }),
		}),
};

function mutationHeaders(access: MutationAccess, retryKey: string = crypto.randomUUID()) {
	return {
		"X-CSRF-Token": access.csrfToken,
		"If-Deployment-Generation": access.generation,
		"Idempotency-Key": retryKey,
	};
}
