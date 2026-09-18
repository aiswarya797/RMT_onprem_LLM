PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA busy_timeout = 2000;

CREATE TABLE deployments (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
  schema_version INTEGER NOT NULL CHECK(schema_version>=1),
  registry_revision TEXT NOT NULL CHECK(registry_revision='mac-ollama-1'),
  installation_uuid TEXT NOT NULL UNIQUE CHECK(length(installation_uuid)=36),
  deployment_generation TEXT NOT NULL CHECK(length(deployment_generation)=36),
  recovery_state TEXT NOT NULL CHECK(recovery_state IN ('normal','maintenance_pre_activation','restore_requires_bootstrap','recovery_blocked')),
  created_ms INTEGER NOT NULL CHECK(created_ms>=0),
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  UNIQUE(id,deployment_generation)
) STRICT;

CREATE TABLE deployment_generations (
  deployment_id TEXT NOT NULL,
  generation TEXT NOT NULL CHECK(length(generation)=36),
  reason TEXT NOT NULL CHECK(reason IN ('install','trust_reset','restore_bootstrap')),
  activated_ms INTEGER NOT NULL CHECK(activated_ms>=0),
  PRIMARY KEY(deployment_id,generation),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
) STRICT;

CREATE TABLE hosts (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL CHECK(length(deployment_id)=36),
  display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
  installation_uuid TEXT NOT NULL CHECK(length(installation_uuid)=36),
  current_session_generation INTEGER NOT NULL DEFAULT 0 CHECK(current_session_generation>=0),
  last_boot_id TEXT CHECK(last_boot_id IS NULL OR length(last_boot_id)=36),
  collector_version TEXT CHECK(collector_version IS NULL OR length(collector_version)<=128),
  capabilities_json TEXT NOT NULL CHECK(json_valid(capabilities_json) AND length(capabilities_json)<=65536),
  retired_ms INTEGER CHECK(retired_ms IS NULL OR retired_ms>=0),
  created_ms INTEGER NOT NULL CHECK(created_ms>=0),
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  UNIQUE(deployment_id,id),
  UNIQUE(deployment_id,installation_uuid),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
) STRICT;
CREATE INDEX hosts_deployment_retired ON hosts(deployment_id,retired_ms);

CREATE TABLE targets (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  adapter_id TEXT NOT NULL CHECK(adapter_id='ollama'),
  local_selector_hash TEXT NOT NULL CHECK(length(local_selector_hash)=64),
  display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
  endpoint_alias TEXT NOT NULL CHECK(length(endpoint_alias) BETWEEN 1 AND 128),
  retired_ms INTEGER CHECK(retired_ms IS NULL OR retired_ms>=0),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  UNIQUE(deployment_id,host_id,id),
  UNIQUE(deployment_id,host_id,local_selector_hash),
  FOREIGN KEY(deployment_id,host_id) REFERENCES hosts(deployment_id,id)
) STRICT;
CREATE INDEX targets_owner_retired ON targets(deployment_id,host_id,retired_ms);

CREATE TABLE sources (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('host','runtime','observed_request')),
  target_id TEXT,
  admitted_capability_revision TEXT NOT NULL CHECK(admitted_capability_revision='mac-ollama-1'),
  retired_ms INTEGER CHECK(retired_ms IS NULL OR retired_ms>=0),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  CHECK((kind='host' AND target_id IS NULL) OR (kind IN ('runtime','observed_request') AND target_id IS NOT NULL)),
  UNIQUE(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id) REFERENCES hosts(deployment_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id)
) STRICT;
CREATE INDEX sources_owner_kind_retired ON sources(deployment_id,host_id,kind,retired_ms);

CREATE TABLE collector_sessions (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  session_generation INTEGER NOT NULL CHECK(session_generation>=1),
  security_generation TEXT NOT NULL CHECK(length(security_generation)=36),
  activation_request_id TEXT NOT NULL CHECK(length(activation_request_id)=36),
  collector_boot_id TEXT NOT NULL CHECK(length(collector_boot_id)=36),
  predecessor_generation INTEGER NOT NULL CHECK(predecessor_generation>=0 AND predecessor_generation<session_generation),
  activated_ms INTEGER NOT NULL CHECK(activated_ms>=0),
  superseded_ms INTEGER CHECK(superseded_ms IS NULL OR superseded_ms>=activated_ms),
  activation_result_json TEXT NOT NULL CHECK(json_valid(activation_result_json) AND length(activation_result_json)<=65536),
  PRIMARY KEY(deployment_id,host_id,session_generation),
  UNIQUE(deployment_id,host_id,activation_request_id),
  UNIQUE(deployment_id,host_id,session_generation,collector_boot_id),
  UNIQUE(deployment_id,host_id,security_generation,session_generation,collector_boot_id),
  FOREIGN KEY(deployment_id,host_id) REFERENCES hosts(deployment_id,id)
) STRICT;
CREATE UNIQUE INDEX collector_one_current_session ON collector_sessions(deployment_id,host_id) WHERE superseded_ms IS NULL;

CREATE TABLE collector_credentials (
  serial TEXT PRIMARY KEY NOT NULL CHECK(length(serial) BETWEEN 1 AND 128),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  cert_fingerprint_sha256 TEXT NOT NULL CHECK(length(cert_fingerprint_sha256)=64),
  issued_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>issued_ms),
  revoked_ms INTEGER CHECK(revoked_ms IS NULL OR revoked_ms>=issued_ms),
  UNIQUE(deployment_id,cert_fingerprint_sha256),
  FOREIGN KEY(deployment_id,host_id) REFERENCES hosts(deployment_id,id)
) STRICT;

CREATE TABLE collector_enrollments (
  token_hash TEXT PRIMARY KEY NOT NULL CHECK(length(token_hash)=64),
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  reserved_host_id TEXT NOT NULL CHECK(length(reserved_host_id)=36),
  created_by TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms=created_ms+600000),
  consumed_ms INTEGER,
  result_host_id TEXT,
  result_cert_fingerprint_sha256 TEXT CHECK(result_cert_fingerprint_sha256 IS NULL OR length(result_cert_fingerprint_sha256)=64),
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation),
  FOREIGN KEY(deployment_id,created_by) REFERENCES users(deployment_id,id),
  FOREIGN KEY(deployment_id,result_host_id) REFERENCES hosts(deployment_id,id)
) STRICT;

CREATE TABLE incarnations (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  boot_id TEXT NOT NULL CHECK(length(boot_id)=36),
  pid INTEGER NOT NULL CHECK(pid BETWEEN 1 AND 2147483647),
  process_start_identity TEXT NOT NULL CHECK(length(process_start_identity) BETWEEN 1 AND 20),
  process_key_sha256 TEXT NOT NULL CHECK(length(process_key_sha256)=64),
  sanitized_basename TEXT CHECK(sanitized_basename IN ('ollama','llm-monitor','llm-monitor-collector') OR sanitized_basename IS NULL),
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms>=first_seen_ms),
  UNIQUE(deployment_id,host_id,target_id,id),
  UNIQUE(deployment_id,host_id,boot_id,pid,process_start_identity),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id)
) STRICT;
CREATE INDEX incarnations_target_first ON incarnations(deployment_id,host_id,target_id,first_seen_ms);

CREATE TABLE endpoint_associations (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  incarnation_id TEXT NOT NULL,
  checked_ms INTEGER NOT NULL,
  endpoint_hash TEXT NOT NULL CHECK(length(endpoint_hash)=64),
  local_network_evidence_json TEXT NOT NULL CHECK(json_valid(local_network_evidence_json) AND length(local_network_evidence_json)<=65536),
  state TEXT NOT NULL CHECK(state IN ('verified','declared_unverified','ambiguous')),
  reason TEXT NOT NULL CHECK(length(reason)<=128),
  identity_revision TEXT NOT NULL CHECK(length(identity_revision)=64),
  PRIMARY KEY(deployment_id,host_id,target_id,incarnation_id,checked_ms),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id,incarnation_id) REFERENCES incarnations(deployment_id,host_id,target_id,id)
) STRICT;

CREATE TABLE reachability_episodes (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  episode_id TEXT NOT NULL CHECK(length(episode_id)=36),
  start_ms INTEGER NOT NULL,
  startup_deadline_ms INTEGER NOT NULL CHECK(startup_deadline_ms>=start_ms),
  last_reachable_ms INTEGER,
  ever_reachable INTEGER NOT NULL CHECK(ever_reachable IN (0,1)),
  exit_count INTEGER NOT NULL DEFAULT 0 CHECK(exit_count>=0),
  ended_ms INTEGER CHECK(ended_ms IS NULL OR ended_ms>=start_ms),
  PRIMARY KEY(deployment_id,host_id,target_id,episode_id),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id)
) STRICT;

CREATE TABLE process_observations (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT,
  incarnation_id TEXT,
  source_id TEXT NOT NULL,
  process_key_sha256 TEXT NOT NULL CHECK(length(process_key_sha256)=64),
  observed_ms INTEGER NOT NULL,
  cpu_busy_ratio REAL CHECK(cpu_busy_ratio IS NULL OR cpu_busy_ratio BETWEEN 0.0 AND 1.0),
  physical_footprint_bytes TEXT CHECK(physical_footprint_bytes IS NULL OR (length(physical_footprint_bytes) BETWEEN 1 AND 20 AND physical_footprint_bytes NOT GLOB '*[^0-9]*' AND (physical_footprint_bytes='0' OR physical_footprint_bytes NOT LIKE '0%') AND (length(physical_footprint_bytes)<20 OR physical_footprint_bytes<='18446744073709551615'))),
  association_quality TEXT NOT NULL CHECK(association_quality IN ('verified','declared_unverified','none')),
  method_revision TEXT NOT NULL CHECK(length(method_revision)<=128),
  provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json) AND length(provenance_json)<=8192),
  PRIMARY KEY(deployment_id,host_id,source_id,process_key_sha256,observed_ms),
  FOREIGN KEY(deployment_id,host_id,source_id) REFERENCES sources(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id,incarnation_id) REFERENCES incarnations(deployment_id,host_id,target_id,id)
) STRICT;
CREATE INDEX process_observations_target_time ON process_observations(deployment_id,host_id,target_id,observed_ms);

CREATE TABLE model_revisions (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  served_alias TEXT NOT NULL CHECK(length(served_alias) BETWEEN 1 AND 256),
  digest TEXT CHECK(digest IS NULL OR length(digest)=64),
  format TEXT CHECK(format IS NULL OR length(format)<=64),
  family TEXT CHECK(family IS NULL OR length(family)<=128),
  quantization TEXT CHECK(quantization IS NULL OR length(quantization)<=64),
  context_length INTEGER CHECK(context_length IS NULL OR context_length BETWEEN 1 AND 131072),
  config_hash TEXT NOT NULL CHECK(length(config_hash)=64),
  created_ms INTEGER NOT NULL,
  UNIQUE(deployment_id,host_id,target_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id)
) STRICT;
CREATE UNIQUE INDEX model_revision_digest_config ON model_revisions(deployment_id,host_id,target_id,digest,config_hash) WHERE digest IS NOT NULL;

CREATE TABLE model_load_observations (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  observed_ms INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('reported_loaded','not_reported_loaded','unknown','inventory_incompatible')),
  reported_size_bytes TEXT CHECK(reported_size_bytes IS NULL OR (length(reported_size_bytes) BETWEEN 1 AND 20 AND reported_size_bytes NOT GLOB '*[^0-9]*' AND (reported_size_bytes='0' OR reported_size_bytes NOT LIKE '0%') AND (length(reported_size_bytes)<20 OR reported_size_bytes<='18446744073709551615'))),
  reported_size_vram_bytes TEXT CHECK(reported_size_vram_bytes IS NULL OR (length(reported_size_vram_bytes) BETWEEN 1 AND 20 AND reported_size_vram_bytes NOT GLOB '*[^0-9]*' AND (reported_size_vram_bytes='0' OR reported_size_vram_bytes NOT LIKE '0%') AND (length(reported_size_vram_bytes)<20 OR reported_size_vram_bytes<='18446744073709551615'))),
  provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json) AND length(provenance_json)<=8192),
  PRIMARY KEY(deployment_id,host_id,target_id,model_id,observed_ms),
  FOREIGN KEY(deployment_id,host_id,target_id,model_id) REFERENCES model_revisions(deployment_id,host_id,target_id,id)
) STRICT;
CREATE INDEX model_load_target_time ON model_load_observations(deployment_id,host_id,target_id,observed_ms);

CREATE TABLE config_snapshots (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  incarnation_id TEXT,
  config_hash TEXT NOT NULL CHECK(length(config_hash)=64),
  observed_ms INTEGER NOT NULL,
  preceding_observed_ms INTEGER CHECK(preceding_observed_ms IS NULL OR preceding_observed_ms<=observed_ms),
  fields_json TEXT NOT NULL CHECK(json_valid(fields_json) AND length(fields_json)<=65536),
  provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json) AND length(provenance_json)<=65536),
  UNIQUE(deployment_id,host_id,target_id,id),
  UNIQUE(deployment_id,host_id,target_id,config_hash),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id,incarnation_id) REFERENCES incarnations(deployment_id,host_id,target_id,id)
) STRICT;
CREATE INDEX config_snapshots_target_time ON config_snapshots(deployment_id,host_id,target_id,observed_ms);

CREATE TABLE metric_definitions (
  revision TEXT NOT NULL,
  metric_id TEXT NOT NULL,
  unit TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('gauge','cumulative_counter','request_sample')),
  population TEXT NOT NULL,
  definition_json TEXT NOT NULL CHECK(json_valid(definition_json) AND length(definition_json)<=65536),
  PRIMARY KEY(revision,metric_id)
) STRICT;

CREATE TABLE request_runs (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  source_kind TEXT NOT NULL CHECK(source_kind IN ('deliberate_probe','imported_test')),
  verification_state TEXT NOT NULL CHECK(verification_state IN ('direct_capture','operator_imported_unverified')),
  population_key_sha256 TEXT NOT NULL CHECK(length(population_key_sha256)=64),
  population_key_json TEXT NOT NULL CHECK(json_valid(population_key_json) AND length(population_key_json)<=65536),
  expected_count INTEGER NOT NULL CHECK(expected_count BETWEEN 1 AND 10000),
  submitted_count INTEGER NOT NULL CHECK(submitted_count BETWEEN 0 AND expected_count),
  completed_count INTEGER NOT NULL CHECK(completed_count>=0),
  failed_count INTEGER NOT NULL CHECK(failed_count>=0),
  cancelled_count INTEGER NOT NULL CHECK(cancelled_count>=0),
  incomplete_count INTEGER NOT NULL CHECK(incomplete_count>=0),
  finalization_state TEXT NOT NULL CHECK(finalization_state IN ('active','finalized','partial')),
  reserved_records INTEGER NOT NULL CHECK(reserved_records BETWEEN 1 AND 10000),
  reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes BETWEEN 1 AND 8388608),
  created_ms INTEGER NOT NULL,
  finalized_ms INTEGER,
  CHECK(completed_count+failed_count+cancelled_count+incomplete_count<=submitted_count),
  CHECK((source_kind='deliberate_probe' AND verification_state='direct_capture') OR (source_kind='imported_test' AND verification_state='operator_imported_unverified')),
  UNIQUE(deployment_id,host_id,id),
  UNIQUE(deployment_id,host_id,id,source_id,target_id,population_key_sha256),
  FOREIGN KEY(deployment_id,host_id,source_id) REFERENCES sources(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id)
) STRICT;
CREATE UNIQUE INDEX request_runs_deployment_id ON request_runs(deployment_id,id);
CREATE INDEX request_runs_finalized ON request_runs(deployment_id,finalization_state,finalized_ms);

CREATE TABLE request_samples (
  sample_id TEXT PRIMARY KEY NOT NULL CHECK(length(sample_id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  config_id TEXT NOT NULL,
  observation_scope TEXT NOT NULL CHECK(observation_scope='explicit_observed_request'),
  runtime_source_pin_id TEXT NOT NULL CHECK(runtime_source_pin_id IN ('ollama-0.34.0-source','ollama-0.12.10-source','operator-import-unverified')),
  terminal_record_observed INTEGER NOT NULL CHECK(terminal_record_observed IN (0,1)),
  population_key_sha256 TEXT NOT NULL CHECK(length(population_key_sha256)=64),
  submitted_at_ms INTEGER NOT NULL,
  submit_offset_ns TEXT NOT NULL CHECK(submit_offset_ns='0'),
  headers_offset_ns TEXT,
  first_byte_offset_ns TEXT,
  first_thinking_offset_ns TEXT,
  first_content_offset_ns TEXT,
  end_offset_ns TEXT NOT NULL,
  http_status INTEGER CHECK(http_status IS NULL OR http_status BETWEEN 100 AND 599),
  terminal_status TEXT NOT NULL CHECK(terminal_status IN ('completed','cancelled','failed','incomplete')),
  done_reason TEXT CHECK(done_reason IS NULL OR done_reason IN ('stop','length','load','unload','error')),
  safe_error_category TEXT CHECK(safe_error_category IS NULL OR length(safe_error_category)<=64),
  client_first_byte_ms REAL CHECK(client_first_byte_ms IS NULL OR client_first_byte_ms>=0),
  client_first_content_ms REAL CHECK(client_first_content_ms IS NULL OR client_first_content_ms>=0),
  client_total_ms REAL CHECK(client_total_ms IS NULL OR client_total_ms>=0),
  runtime_total_duration_ms REAL CHECK(runtime_total_duration_ms IS NULL OR runtime_total_duration_ms>=0),
  runtime_load_duration_ms REAL CHECK(runtime_load_duration_ms IS NULL OR runtime_load_duration_ms>=0),
  runtime_prompt_eval_duration_ms REAL CHECK(runtime_prompt_eval_duration_ms IS NULL OR runtime_prompt_eval_duration_ms>=0),
  runtime_eval_duration_ms REAL CHECK(runtime_eval_duration_ms IS NULL OR runtime_eval_duration_ms>=0),
  runtime_prompt_tokens INTEGER CHECK(runtime_prompt_tokens IS NULL OR runtime_prompt_tokens>=0),
  runtime_output_tokens INTEGER CHECK(runtime_output_tokens IS NULL OR runtime_output_tokens>=0),
  field_provenance_json TEXT NOT NULL CHECK(json_valid(field_provenance_json) AND length(field_provenance_json)<=65536),
  CHECK(terminal_status!='completed' OR (http_status IS NOT NULL AND http_status BETWEEN 200 AND 299 AND done_reason IS NOT NULL AND done_reason IN ('stop','length') AND client_total_ms IS NOT NULL AND safe_error_category IS NULL)),
  CHECK(terminal_status='completed' OR safe_error_category IS NOT NULL),
  CHECK(client_first_byte_ms IS NULL OR client_total_ms IS NULL OR client_first_byte_ms<=client_total_ms),
  CHECK(client_first_content_ms IS NULL OR client_total_ms IS NULL OR client_first_content_ms<=client_total_ms),
  UNIQUE(deployment_id,host_id,sample_id),
  FOREIGN KEY(deployment_id,host_id,run_id) REFERENCES request_runs(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,run_id,source_id,target_id,population_key_sha256) REFERENCES request_runs(deployment_id,host_id,id,source_id,target_id,population_key_sha256),
  FOREIGN KEY(deployment_id,host_id,source_id) REFERENCES sources(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id,model_id) REFERENCES model_revisions(deployment_id,host_id,target_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id,config_id) REFERENCES config_snapshots(deployment_id,host_id,target_id,id)
) STRICT;
CREATE INDEX request_samples_target_end ON request_samples(deployment_id,host_id,target_id,submitted_at_ms);

-- The reviewed request-run row predates the normalized import envelope and
-- intentionally keeps only the population identity. This sidecar retains the
-- remaining run-level provenance without widening the immutable population
-- row or storing request content.
CREATE TABLE request_run_metadata (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  config_id TEXT NOT NULL,
  decoded_size_bytes INTEGER NOT NULL CHECK(decoded_size_bytes BETWEEN 1 AND 8388608),
  original_artifact_sha256 TEXT CHECK(original_artifact_sha256 IS NULL OR length(original_artifact_sha256)=64),
  partial_reason TEXT CHECK(partial_reason IS NULL OR partial_reason IN ('source_loss','import_interrupted','population_expired_or_partial')),
  content_persistence TEXT NOT NULL CHECK(content_persistence='none'),
  PRIMARY KEY(deployment_id,host_id,run_id),
  FOREIGN KEY(deployment_id,host_id,run_id) REFERENCES request_runs(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id,model_id) REFERENCES model_revisions(deployment_id,host_id,target_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id,config_id) REFERENCES config_snapshots(deployment_id,host_id,target_id,id)
) STRICT;

CREATE TABLE comparisons (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  schema_version TEXT NOT NULL CHECK(schema_version='1.0'),
  comparison_kind TEXT NOT NULL CHECK(comparison_kind='request_run'),
  scope_id TEXT NOT NULL CHECK(length(scope_id)=36),
  metric_id TEXT NOT NULL CHECK(length(metric_id) BETWEEN 3 AND 96),
  before_run_id TEXT NOT NULL CHECK(length(before_run_id)=36),
  after_run_id TEXT NOT NULL CHECK(length(after_run_id)=36),
  request_json TEXT NOT NULL CHECK(json_valid(request_json) AND length(CAST(request_json AS BLOB))<=65536),
  result_json TEXT NOT NULL CHECK(json_valid(result_json) AND length(CAST(result_json AS BLOB))<=524288),
  input_sha256 TEXT NOT NULL CHECK(length(input_sha256)=64),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
  created_by TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>created_ms),
  UNIQUE(deployment_id,id),
  UNIQUE(deployment_id,input_sha256),
  FOREIGN KEY(deployment_id,before_run_id) REFERENCES request_runs(deployment_id,id),
  FOREIGN KEY(deployment_id,after_run_id) REFERENCES request_runs(deployment_id,id),
  FOREIGN KEY(deployment_id,created_by) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX comparisons_expiry ON comparisons(deployment_id,expires_ms);
CREATE INDEX comparisons_scope_created ON comparisons(deployment_id,scope_id,created_ms,id);

CREATE TABLE source_frames (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  security_generation TEXT NOT NULL CHECK(length(security_generation)=36),
  session_generation INTEGER NOT NULL CHECK(session_generation>=1),
  collector_boot_id TEXT NOT NULL CHECK(length(collector_boot_id)=36),
  source_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence BETWEEN 0 AND 9007199254740991),
  delivery_mode TEXT NOT NULL CHECK(delivery_mode IN ('current','replay','restored_replay')),
  incarnation_id TEXT,
  original_wall_ms INTEGER NOT NULL,
  aligned_ms INTEGER,
  uncertainty_ms INTEGER CHECK(uncertainty_ms IS NULL OR uncertainty_ms BETWEEN 0 AND 60000),
  duration_ms INTEGER NOT NULL CHECK(duration_ms BETWEEN 0 AND 5000),
  quality TEXT NOT NULL CHECK(quality IN ('measured','runtime_reported','derived','estimated','declared','inferred','unavailable')),
  definition_revision TEXT NOT NULL CHECK(definition_revision='mac-ollama-1'),
  codec TEXT NOT NULL CHECK(codec='cbor-zstd-v1'),
  payload BLOB NOT NULL CHECK(length(payload)<=262144),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
  original_security_generation TEXT NOT NULL CHECK(length(original_security_generation)=36),
  original_collector_boot_id TEXT NOT NULL CHECK(length(original_collector_boot_id)=36),
  original_source_id TEXT NOT NULL CHECK(length(original_source_id)=36),
  original_sequence INTEGER NOT NULL CHECK(original_sequence BETWEEN 0 AND 9007199254740991),
  original_payload_sha256 TEXT NOT NULL CHECK(length(original_payload_sha256)=64),
  recovery_grant_id TEXT,
  recovery_grant_hash TEXT CHECK(recovery_grant_hash IS NULL OR length(recovery_grant_hash)=64),
  admitted_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,host_id,original_collector_boot_id,original_source_id,original_sequence),
  FOREIGN KEY(deployment_id,host_id,security_generation,session_generation,collector_boot_id) REFERENCES collector_sessions(deployment_id,host_id,security_generation,session_generation,collector_boot_id),
  FOREIGN KEY(deployment_id,host_id,source_id) REFERENCES sources(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,original_source_id) REFERENCES sources(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,recovery_grant_id,recovery_grant_hash,original_security_generation,original_collector_boot_id) REFERENCES recovery_grant_tombstones(deployment_id,host_id,grant_id,grant_sha256,original_security_generation,original_collector_boot_id),
  CHECK((delivery_mode!='restored_replay' AND recovery_grant_id IS NULL AND recovery_grant_hash IS NULL) OR (delivery_mode='restored_replay' AND recovery_grant_id IS NOT NULL AND recovery_grant_hash IS NOT NULL))
) STRICT;
CREATE INDEX source_frames_source_aligned ON source_frames(deployment_id,host_id,source_id,aligned_ms);
CREATE INDEX source_frames_aligned ON source_frames(deployment_id,aligned_ms);

CREATE TABLE source_status (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  security_generation TEXT NOT NULL,
  session_generation INTEGER NOT NULL,
  collector_boot_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence>=0),
  observed_ms INTEGER NOT NULL,
  payload_json TEXT NOT NULL CHECK(json_valid(payload_json) AND length(CAST(payload_json AS BLOB))<=4096),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
  admitted_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,host_id,collector_boot_id,sequence),
  FOREIGN KEY(deployment_id,host_id,session_generation,collector_boot_id) REFERENCES collector_sessions(deployment_id,host_id,session_generation,collector_boot_id)
) STRICT;

CREATE TABLE counter_epochs (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  series_hash TEXT NOT NULL CHECK(length(series_hash)=64),
  epoch_id TEXT NOT NULL CHECK(length(epoch_id)=36),
  definition_revision TEXT NOT NULL CHECK(definition_revision='mac-ollama-1'),
  layout_hash TEXT CHECK(layout_hash IS NULL OR length(layout_hash)=64),
  first_ms INTEGER NOT NULL,
  last_ms INTEGER NOT NULL CHECK(last_ms>=first_ms),
  reason TEXT NOT NULL CHECK(reason IN ('boot','first_observation','reset','wrap','identity_change','method_revision')),
  PRIMARY KEY(deployment_id,host_id,source_id,series_hash,epoch_id),
  FOREIGN KEY(deployment_id,host_id,source_id) REFERENCES sources(deployment_id,host_id,id)
) STRICT;

CREATE TABLE rollup_minutes (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  minute_ms INTEGER NOT NULL CHECK(minute_ms%60000=0),
  revision INTEGER NOT NULL CHECK(revision>=1),
  definition_revision TEXT NOT NULL CHECK(definition_revision='mac-ollama-1'),
  codec TEXT NOT NULL CHECK(codec='cbor-zstd-v1'),
  payload BLOB NOT NULL CHECK(length(payload)<=262144),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  PRIMARY KEY(deployment_id,host_id,source_id,minute_ms),
  FOREIGN KEY(deployment_id,host_id,source_id) REFERENCES sources(deployment_id,host_id,id)
) STRICT;
CREATE INDEX rollup_minutes_time ON rollup_minutes(deployment_id,minute_ms);

CREATE TABLE rollup_hours (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  hour_ms INTEGER NOT NULL CHECK(hour_ms%3600000=0),
  revision INTEGER NOT NULL CHECK(revision>=1),
  definition_revision TEXT NOT NULL CHECK(definition_revision='mac-ollama-1'),
  codec TEXT NOT NULL CHECK(codec='cbor-zstd-v1'),
  payload BLOB NOT NULL CHECK(length(payload)<=262144),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  PRIMARY KEY(deployment_id,host_id,source_id,hour_ms),
  FOREIGN KEY(deployment_id,host_id,source_id) REFERENCES sources(deployment_id,host_id,id)
) STRICT;
CREATE INDEX rollup_hours_time ON rollup_hours(deployment_id,hour_ms);

CREATE TABLE events (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT,
  incarnation_id TEXT,
  occurred_start_ms INTEGER NOT NULL,
  occurred_end_ms INTEGER NOT NULL CHECK(occurred_end_ms>=occurred_start_ms),
  detected_ms INTEGER NOT NULL,
  code TEXT NOT NULL CHECK(length(code) BETWEEN 1 AND 64),
  severity TEXT NOT NULL CHECK(severity IN ('info','warning','critical','unknown')),
  allowlisted_fields_json TEXT NOT NULL CHECK(json_valid(allowlisted_fields_json) AND length(allowlisted_fields_json)<=65536),
  source TEXT NOT NULL CHECK(source IN ('collector','runtime_api','operator','hub')),
  provenance_json TEXT NOT NULL CHECK(json_valid(provenance_json) AND length(provenance_json)<=8192),
  repeat_count INTEGER NOT NULL DEFAULT 1 CHECK(repeat_count>=1),
  UNIQUE(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id) REFERENCES hosts(deployment_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id,incarnation_id) REFERENCES incarnations(deployment_id,host_id,target_id,id)
) STRICT;
CREATE INDEX events_target_time ON events(deployment_id,host_id,target_id,occurred_start_ms);
CREATE INDEX events_code_detected ON events(deployment_id,code,detected_ms);

CREATE TABLE coverage_gaps (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  start_ms INTEGER NOT NULL,
  end_ms INTEGER NOT NULL CHECK(end_ms>start_ms),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 64),
  lost_count INTEGER NOT NULL CHECK(lost_count>=0),
  detected_ms INTEGER NOT NULL,
  UNIQUE(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,source_id) REFERENCES sources(deployment_id,host_id,id)
) STRICT;
CREATE INDEX coverage_gaps_source_time ON coverage_gaps(deployment_id,host_id,source_id,start_ms);

CREATE TABLE users (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 128),
  argon2_hash TEXT NOT NULL CHECK(length(argon2_hash) BETWEEN 32 AND 1024),
  role TEXT NOT NULL CHECK(role IN ('admin','viewer')),
  disabled INTEGER NOT NULL CHECK(disabled IN (0,1)),
  trust_generation TEXT NOT NULL CHECK(length(trust_generation)=36),
  historical_restored INTEGER NOT NULL DEFAULT 0 CHECK(historical_restored IN (0,1)),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version>=1),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  UNIQUE(deployment_id,id),
  UNIQUE(deployment_id,name),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id),
  FOREIGN KEY(deployment_id,trust_generation) REFERENCES deployment_generations(deployment_id,generation),
  CHECK(historical_restored=0 OR disabled=1)
) STRICT;

CREATE TABLE restore_bootstrap_transitions (
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  installing_user_uid INTEGER NOT NULL CHECK(installing_user_uid>=0),
  hub_stopped INTEGER NOT NULL CHECK(hub_stopped=1),
  state TEXT NOT NULL CHECK(state IN ('archiving_restored_users','bootstrap_complete')),
  archived_user_count INTEGER NOT NULL DEFAULT 0 CHECK(archived_user_count BETWEEN 0 AND 1000),
  started_ms INTEGER NOT NULL,
  completed_ms INTEGER CHECK(completed_ms IS NULL OR completed_ms>=started_ms),
  PRIMARY KEY(deployment_id,deployment_generation),
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation)
) STRICT;

-- T01/R15 prerequisite: one-use local-owner bootstrap and password-reset tokens.
-- Only SHA-256 token digests are stored; plaintext stays in a user-owned 0600 file.
CREATE TABLE auth_bootstrap_tokens (
  token_hash TEXT PRIMARY KEY NOT NULL CHECK(length(token_hash)=64),
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  purpose TEXT NOT NULL CHECK(purpose IN ('first_admin','password_reset')),
  user_id TEXT,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>created_ms),
  consumed_ms INTEGER CHECK(consumed_ms IS NULL OR consumed_ms>=created_ms),
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation),
  FOREIGN KEY(deployment_id,user_id) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX auth_bootstrap_expiry ON auth_bootstrap_tokens(deployment_id,purpose,expires_ms);

CREATE TABLE user_sessions (
  token_hash TEXT PRIMARY KEY NOT NULL CHECK(length(token_hash)=64),
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  user_id TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>created_ms),
  absolute_expires_ms INTEGER NOT NULL CHECK(absolute_expires_ms>=expires_ms),
  last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms>=created_ms),
  revoked_ms INTEGER,
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation),
  FOREIGN KEY(deployment_id,user_id) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX user_sessions_user ON user_sessions(deployment_id,user_id,expires_ms);

CREATE TABLE api_tokens (
  token_hash TEXT PRIMARY KEY NOT NULL CHECK(length(token_hash)=64),
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  user_id TEXT NOT NULL,
  display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
  scope TEXT NOT NULL CHECK(scope IN ('admin','viewer')),
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>created_ms),
  revoked_ms INTEGER,
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation),
  FOREIGN KEY(deployment_id,user_id) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX api_tokens_user ON api_tokens(deployment_id,user_id,expires_ms);

CREATE TABLE rule_revisions (
  deployment_id TEXT NOT NULL,
  rule_id TEXT NOT NULL CHECK(length(rule_id)=36),
  version INTEGER NOT NULL CHECK(version>=1),
  scope_json TEXT NOT NULL CHECK(json_valid(scope_json) AND length(scope_json)<=65536),
  evaluator_type TEXT NOT NULL CHECK(evaluator_type IN ('ollama_unreachable','host_not_reporting','source_missing','memory_pressure','heavy_cpu','observed_request_duration','disk_monitor_health')),
  threshold_json TEXT NOT NULL CHECK(json_valid(threshold_json) AND length(threshold_json)<=65536),
  enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
  updated_by TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,rule_id,version),
  FOREIGN KEY(deployment_id,updated_by) REFERENCES users(deployment_id,id)
) STRICT;

CREATE TABLE rules (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  current_version INTEGER NOT NULL CHECK(current_version>=1),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id,id,current_version) REFERENCES rule_revisions(deployment_id,rule_id,version)
) STRICT;

CREATE TABLE alert_instances (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_version INTEGER NOT NULL,
  scope_fingerprint TEXT NOT NULL CHECK(length(scope_fingerprint)=64),
  active_generation INTEGER NOT NULL CHECK(active_generation>=1),
  state TEXT NOT NULL CHECK(state IN ('OK','PENDING','FIRING','RECOVERING','RESOLVED','superseded')),
  data_state TEXT NOT NULL CHECK(data_state IN ('valid','unknown','stale','incompatible')),
  dwell_ms INTEGER NOT NULL CHECK(dwell_ms>=0),
  last_eval_ms INTEGER NOT NULL,
  last_valid_ms INTEGER,
  opened_ms INTEGER,
  resolved_ms INTEGER,
  acknowledged_by TEXT,
  acknowledged_ms INTEGER,
  muted_until_ms INTEGER,
  transition_seq INTEGER NOT NULL DEFAULT 0 CHECK(transition_seq>=0),
  UNIQUE(deployment_id,id),
  UNIQUE(deployment_id,rule_id,scope_fingerprint,active_generation),
  FOREIGN KEY(deployment_id,rule_id,rule_version) REFERENCES rule_revisions(deployment_id,rule_id,version),
  FOREIGN KEY(deployment_id,acknowledged_by) REFERENCES users(deployment_id,id)
) STRICT;

CREATE TABLE alert_transitions (
  deployment_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  transition_seq INTEGER NOT NULL CHECK(transition_seq>=1),
  previous_state TEXT NOT NULL,
  new_state TEXT NOT NULL,
  event_ms INTEGER NOT NULL,
  evidence_hash TEXT NOT NULL CHECK(length(evidence_hash)=64),
  PRIMARY KEY(deployment_id,instance_id,transition_seq),
  FOREIGN KEY(deployment_id,instance_id) REFERENCES alert_instances(deployment_id,id)
) STRICT;

CREATE TABLE snapshots (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('incident_detail','comparison','export_preview','probe_run','recovery_report')),
  schema_version TEXT NOT NULL CHECK(length(schema_version)<=32),
  revision INTEGER NOT NULL CHECK(revision>=1),
  query_json TEXT NOT NULL CHECK(json_valid(query_json) AND length(query_json)<=65536),
  effective_range_json TEXT NOT NULL CHECK(json_valid(effective_range_json) AND length(effective_range_json)<=65536),
  payload_hash TEXT NOT NULL CHECK(length(payload_hash)=64),
  relative_blob_path TEXT NOT NULL CHECK(length(relative_blob_path) BETWEEN 1 AND 240 AND relative_blob_path NOT LIKE '/%' AND relative_blob_path NOT LIKE '%..%'),
  size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 0 AND 104857600),
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>created_ms),
  UNIQUE(deployment_id,id),
  UNIQUE(deployment_id,type,payload_hash),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
) STRICT;
CREATE INDEX snapshots_expiry ON snapshots(deployment_id,type,expires_ms);

CREATE TABLE incidents (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  target_scope_json TEXT NOT NULL CHECK(json_valid(target_scope_json) AND length(target_scope_json)<=65536),
  title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 256),
  origin TEXT NOT NULL CHECK(origin IN ('manual','alert')),
  start_ms INTEGER NOT NULL,
  end_ms INTEGER CHECK(end_ms IS NULL OR end_ms>start_ms),
  alert_instance_id TEXT,
  workflow_state TEXT NOT NULL CHECK(workflow_state IN ('open','closed')),
  owner_user_id TEXT,
  snapshot_id TEXT,
  evidence_expiry_reason TEXT CHECK(evidence_expiry_reason IS NULL OR evidence_expiry_reason IN ('evidence_expired_quota','evidence_expired_age')),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version>=1),
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id,alert_instance_id) REFERENCES alert_instances(deployment_id,id),
  FOREIGN KEY(deployment_id,owner_user_id) REFERENCES users(deployment_id,id),
  FOREIGN KEY(deployment_id,snapshot_id) REFERENCES snapshots(deployment_id,id)
) STRICT;
CREATE INDEX incidents_state_start ON incidents(deployment_id,workflow_state,start_ms);

CREATE TABLE incident_comparisons (
  deployment_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  comparison_id TEXT NOT NULL,
  attached_by TEXT NOT NULL,
  attached_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,incident_id,comparison_id),
  FOREIGN KEY(deployment_id,incident_id) REFERENCES incidents(deployment_id,id),
  FOREIGN KEY(deployment_id,comparison_id) REFERENCES comparisons(deployment_id,id),
  FOREIGN KEY(deployment_id,attached_by) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX incident_comparisons_comparison ON incident_comparisons(deployment_id,comparison_id,attached_ms);

CREATE TABLE incident_capsules (
  deployment_id TEXT NOT NULL,
  incident_id TEXT NOT NULL,
  schema_revision TEXT NOT NULL CHECK(length(schema_revision)<=32),
  card_revision TEXT NOT NULL CHECK(length(card_revision)<=32),
  rule_revision INTEGER,
  payload BLOB CHECK(payload IS NULL OR length(payload)<=65536),
  payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64),
  physical_reservation_bytes INTEGER NOT NULL CHECK(physical_reservation_bytes BETWEEN 0 AND 65536),
  evidence_state TEXT NOT NULL CHECK(evidence_state IN ('complete','partial','evidence_expired_quota','evidence_expired_age')),
  expires_ms INTEGER,
  resolved_ms INTEGER,
  PRIMARY KEY(deployment_id,incident_id),
  FOREIGN KEY(deployment_id,incident_id) REFERENCES incidents(deployment_id,id),
  CHECK((evidence_state IN ('complete','partial') AND payload IS NOT NULL) OR (evidence_state LIKE 'evidence_expired_%' AND payload IS NULL))
) STRICT;
CREATE INDEX incident_capsules_resolved_expiry ON incident_capsules(deployment_id,resolved_ms,expires_ms);

CREATE TABLE annotations (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  incident_id TEXT,
  host_id TEXT,
  target_id TEXT,
  declared_time_ms INTEGER NOT NULL,
  text TEXT NOT NULL CHECK(length(CAST(text AS BLOB)) BETWEEN 1 AND 2048 AND instr(text,char(0))=0),
  author_user_id TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1 CHECK(version>=1),
  edited_ms INTEGER,
  created_ms INTEGER NOT NULL,
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id,incident_id) REFERENCES incidents(deployment_id,id),
  FOREIGN KEY(deployment_id,author_user_id) REFERENCES users(deployment_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id),
  CHECK(incident_id IS NOT NULL OR target_id IS NOT NULL)
) STRICT;
CREATE INDEX annotations_incident ON annotations(deployment_id,incident_id,declared_time_ms);

CREATE TABLE destinations (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('webhook','smtp')),
  display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 128),
  secret_ref TEXT CHECK(secret_ref IS NULL OR length(secret_ref) BETWEEN 1 AND 256),
  configuration_json TEXT NOT NULL CHECK(json_valid(configuration_json) AND length(configuration_json)<=65536),
  version INTEGER NOT NULL DEFAULT 1 CHECK(version>=1),
  last_test_ms INTEGER,
  last_test_result TEXT CHECK(last_test_result IS NULL OR last_test_result IN ('succeeded','failed')),
  last_test_job_id TEXT,
  disabled_ms INTEGER,
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
) STRICT;

CREATE TABLE maintenance_windows (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  scope_json TEXT NOT NULL CHECK(json_valid(scope_json) AND length(scope_json)<=65536),
  reason TEXT NOT NULL CHECK(length(reason) BETWEEN 1 AND 256),
  starts_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>starts_ms AND expires_ms<=starts_ms+86400000),
  created_by TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  cancelled_ms INTEGER,
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id,created_by) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX maintenance_windows_expiry ON maintenance_windows(deployment_id,expires_ms);

CREATE TABLE outbox (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  instance_id TEXT,
  transition_seq INTEGER,
  destination_id TEXT NOT NULL,
  destination_revision INTEGER NOT NULL CHECK(destination_revision>=1),
  destination_secret_ref TEXT CHECK(destination_secret_ref IS NULL OR length(destination_secret_ref)=64),
  rule_revision INTEGER,
  incident_generation INTEGER NOT NULL CHECK(incident_generation>=1),
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
  payload_json TEXT NOT NULL CHECK(json_valid(payload_json) AND length(payload_json)<=65536),
  state TEXT NOT NULL CHECK(state IN ('pending','leased','sent','failed','expired','superseded_before_delivery','muted')),
  attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 1000),
  lease_token TEXT CHECK(lease_token IS NULL OR length(lease_token)=36),
  lease_until_ms INTEGER,
  next_attempt_ms INTEGER,
  last_error_code TEXT CHECK(last_error_code IS NULL OR length(last_error_code)<=64),
  send_started_ms INTEGER,
  sent_ms INTEGER,
  receiver_ack_ms INTEGER,
  completed_ms INTEGER,
  accepted_unknown INTEGER NOT NULL DEFAULT 0 CHECK(accepted_unknown IN (0,1)),
  job_id TEXT,
  expires_ms INTEGER NOT NULL,
  created_ms INTEGER NOT NULL,
  UNIQUE(deployment_id,id),
  UNIQUE(deployment_id,idempotency_key),
  FOREIGN KEY(deployment_id,instance_id,transition_seq) REFERENCES alert_transitions(deployment_id,instance_id,transition_seq),
  FOREIGN KEY(deployment_id,destination_id) REFERENCES destinations(deployment_id,id)
) STRICT;
CREATE INDEX outbox_state_next ON outbox(deployment_id,state,next_attempt_ms);
CREATE INDEX outbox_destination_history ON outbox(deployment_id,destination_id,created_ms,id);
CREATE UNIQUE INDEX outbox_one_inflight ON outbox(deployment_id,instance_id,destination_id) WHERE state='leased';

CREATE TABLE jobs (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('connectivity_check','comparison','export_preview','export_archive','destination_test','probe_import','backup')),
  state TEXT NOT NULL CHECK(state IN ('queued','running','succeeded','failed','cancelled')),
  progress REAL NOT NULL CHECK(progress BETWEEN 0.0 AND 1.0),
  request_json TEXT NOT NULL CHECK(json_valid(request_json) AND length(request_json)<=65536),
  actor_user_id TEXT NOT NULL,
  result_snapshot_id TEXT,
  error_code TEXT CHECK(error_code IS NULL OR length(error_code)<=64),
  lease_until_ms INTEGER,
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  expires_ms INTEGER NOT NULL,
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation),
  FOREIGN KEY(deployment_id,actor_user_id) REFERENCES users(deployment_id,id),
  FOREIGN KEY(deployment_id,result_snapshot_id) REFERENCES snapshots(deployment_id,id)
) STRICT;
CREATE INDEX jobs_state_lease ON jobs(deployment_id,state,lease_until_ms);

CREATE TABLE artifact_reservations (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  job_id TEXT NOT NULL,
  class TEXT NOT NULL CHECK(class IN ('comparison','export','capture')),
  reserved_physical_bytes INTEGER NOT NULL CHECK(reserved_physical_bytes>0),
  created_ms INTEGER NOT NULL,
  lease_until_ms INTEGER NOT NULL CHECK(lease_until_ms>created_ms),
  UNIQUE(deployment_id,job_id),
  FOREIGN KEY(deployment_id,job_id) REFERENCES jobs(deployment_id,id)
) STRICT;
CREATE INDEX artifact_reservation_lease ON artifact_reservations(deployment_id,class,lease_until_ms);

CREATE TABLE attachments (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  actor_user_id TEXT NOT NULL,
  filename TEXT NOT NULL CHECK(length(filename) BETWEEN 1 AND 128 AND filename NOT LIKE '%/%' AND filename NOT LIKE '%\\%'),
  media_type TEXT NOT NULL CHECK(length(media_type)<=128),
  relative_blob_path TEXT NOT NULL CHECK(length(relative_blob_path)<=240 AND relative_blob_path NOT LIKE '/%' AND relative_blob_path NOT LIKE '%..%'),
  size_bytes INTEGER NOT NULL CHECK(size_bytes BETWEEN 1 AND 10485760),
  sha256 TEXT NOT NULL CHECK(length(sha256)=64),
  verification_state TEXT NOT NULL CHECK(verification_state='operator_approved_unverified'),
  staged_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>staged_ms AND expires_ms<=staged_ms+86400000),
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id,actor_user_id) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX attachments_expiry ON attachments(deployment_id,expires_ms);

CREATE TABLE recovery_grants (
  id TEXT NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  host_id TEXT NOT NULL,
  original_security_generation TEXT NOT NULL CHECK(length(original_security_generation)=36),
  original_collector_boot_id TEXT NOT NULL CHECK(length(original_collector_boot_id)=36),
  manifest_hash TEXT NOT NULL CHECK(length(manifest_hash)=64),
  allowlist_json TEXT NOT NULL CHECK(json_valid(allowlist_json) AND length(CAST(allowlist_json AS BLOB))<=65536),
  approved_scope_sha256 TEXT NOT NULL CHECK(length(approved_scope_sha256)=64),
  grant_sha256 TEXT NOT NULL CHECK(length(grant_sha256)=64),
  max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 1 AND 268435456),
  max_frames INTEGER NOT NULL CHECK(max_frames BETWEEN 1 AND 1000000),
  reserved_receipt_bytes INTEGER NOT NULL CHECK(reserved_receipt_bytes>0),
  issued_by TEXT NOT NULL,
  issued_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms>issued_ms AND expires_ms<=issued_ms+3600000),
  receipt_detail_expires_ms INTEGER NOT NULL CHECK(receipt_detail_expires_ms=expires_ms+86400000),
  revoked_ms INTEGER,
  completed_ms INTEGER,
  PRIMARY KEY(deployment_id,host_id,id),
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation),
  FOREIGN KEY(deployment_id,host_id) REFERENCES hosts(deployment_id,id),
  FOREIGN KEY(deployment_id,issued_by) REFERENCES users(deployment_id,id)
) STRICT;
CREATE UNIQUE INDEX recovery_one_active_host ON recovery_grants(deployment_id,host_id) WHERE revoked_ms IS NULL AND completed_ms IS NULL;

CREATE TABLE recovery_grant_tombstones (
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  host_id TEXT NOT NULL,
  grant_id TEXT NOT NULL CHECK(length(grant_id)=36),
  grant_sha256 TEXT NOT NULL CHECK(length(grant_sha256)=64),
  original_security_generation TEXT NOT NULL CHECK(length(original_security_generation)=36),
  original_collector_boot_id TEXT NOT NULL CHECK(length(original_collector_boot_id)=36),
  manifest_hash TEXT NOT NULL CHECK(length(manifest_hash)=64),
  approved_scope_sha256 TEXT NOT NULL CHECK(length(approved_scope_sha256)=64),
  disposition_summary_json TEXT NOT NULL CHECK(json_valid(disposition_summary_json) AND length(CAST(disposition_summary_json AS BLOB))<=65536),
  receipt_detail_expires_ms INTEGER NOT NULL,
  compacted_ms INTEGER CHECK(compacted_ms IS NULL OR compacted_ms>=receipt_detail_expires_ms),
  created_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,host_id,grant_id),
  UNIQUE(deployment_id,host_id,grant_id,grant_sha256),
  UNIQUE(deployment_id,host_id,grant_id,grant_sha256,original_security_generation,original_collector_boot_id),
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation),
  FOREIGN KEY(deployment_id,host_id) REFERENCES hosts(deployment_id,id)
) STRICT;

CREATE TABLE recovery_grant_receipts (
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  original_collector_boot_id TEXT NOT NULL,
  original_source_id TEXT NOT NULL,
  original_sequence INTEGER NOT NULL CHECK(original_sequence>=0),
  original_payload_sha256 TEXT NOT NULL CHECK(length(original_payload_sha256)=64),
  disposition TEXT NOT NULL CHECK(disposition IN ('recovered','duplicate','expired','corrupt','incompatible','alignment_unavailable','missing_unrecoverable')),
  accepted_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,host_id,grant_id,original_collector_boot_id,original_source_id,original_sequence),
  FOREIGN KEY(deployment_id,host_id,grant_id) REFERENCES recovery_grants(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,original_source_id) REFERENCES sources(deployment_id,host_id,id)
) STRICT;

CREATE TABLE collector_requests (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  target_id TEXT NOT NULL,
  operation TEXT NOT NULL CHECK(operation='refresh_existing_target'),
  state TEXT NOT NULL CHECK(state IN ('pending','delivered','succeeded','failed','expired')),
  expires_ms INTEGER NOT NULL,
  result_job_id TEXT NOT NULL,
  created_ms INTEGER NOT NULL,
  updated_ms INTEGER NOT NULL CHECK(updated_ms>=created_ms),
  CHECK(expires_ms<=created_ms+60000),
  UNIQUE(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,host_id,target_id) REFERENCES targets(deployment_id,host_id,id),
  FOREIGN KEY(deployment_id,result_job_id) REFERENCES jobs(deployment_id,id)
) STRICT;
CREATE INDEX collector_requests_host_state ON collector_requests(deployment_id,host_id,state,expires_ms);

CREATE TABLE idempotency_receipts (
  deployment_id TEXT NOT NULL,
  deployment_generation TEXT NOT NULL,
  actor_user_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 16 AND 128),
  request_body_sha256 TEXT NOT NULL CHECK(length(request_body_sha256)=64),
  result_status INTEGER NOT NULL CHECK(result_status BETWEEN 200 AND 599),
  result_json TEXT NOT NULL CHECK(json_valid(result_json) AND length(result_json)<=65536),
  created_ms INTEGER NOT NULL,
  expires_ms INTEGER NOT NULL CHECK(expires_ms=created_ms+86400000),
  PRIMARY KEY(deployment_id,deployment_generation,actor_user_id,idempotency_key),
  FOREIGN KEY(deployment_id,deployment_generation) REFERENCES deployment_generations(deployment_id,generation),
  FOREIGN KEY(deployment_id,actor_user_id) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX idempotency_expiry ON idempotency_receipts(deployment_id,expires_ms);

CREATE TABLE audit (
  id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=36),
  deployment_id TEXT NOT NULL,
  actor_user_id TEXT,
  action TEXT NOT NULL CHECK(length(action) BETWEEN 1 AND 96),
  resource_id TEXT CHECK(resource_id IS NULL OR length(resource_id)<=128),
  time_ms INTEGER NOT NULL,
  allowlisted_detail_json TEXT NOT NULL CHECK(json_valid(allowlisted_detail_json) AND length(allowlisted_detail_json)<=65536),
  UNIQUE(deployment_id,id),
  FOREIGN KEY(deployment_id,actor_user_id) REFERENCES users(deployment_id,id)
) STRICT;
CREATE INDEX audit_time ON audit(deployment_id,time_ms);

CREATE TABLE retention_loss_ledger (
  deployment_id TEXT NOT NULL,
  class TEXT NOT NULL CHECK(class IN ('incident_capsule','snapshot','event','config','audit','annotation','request_run','source_frame')),
  reason TEXT NOT NULL CHECK(length(reason)<=64),
  first_ms INTEGER NOT NULL,
  last_ms INTEGER NOT NULL CHECK(last_ms>=first_ms),
  loss_count INTEGER NOT NULL CHECK(loss_count>=1),
  earliest_retained_ms INTEGER,
  updated_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,class,reason),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
) STRICT;

CREATE TABLE quota_classes (
  deployment_id TEXT NOT NULL,
  class TEXT NOT NULL CHECK(class IN ('live_total','bulk_database','detailed_snapshots','incident_ledger','control_ledger','metadata','saved_comparisons','completed_exports','transient','live_headroom','emergency_outside_live','request_samples','attachment_staging')),
  byte_limit INTEGER NOT NULL CHECK(byte_limit>0),
  count_limit INTEGER CHECK(count_limit IS NULL OR count_limit>0),
  warning_ratio REAL NOT NULL DEFAULT 0.8 CHECK(warning_ratio BETWEEN 0.0 AND 1.0),
  stop_ratio REAL NOT NULL DEFAULT 0.9 CHECK(stop_ratio BETWEEN warning_ratio AND 1.0),
  pause_ratio REAL NOT NULL DEFAULT 0.95 CHECK(pause_ratio BETWEEN stop_ratio AND 1.0),
  current_physical_bytes INTEGER NOT NULL DEFAULT 0 CHECK(current_physical_bytes>=0),
  reserved_physical_bytes INTEGER NOT NULL DEFAULT 0 CHECK(reserved_physical_bytes>=0),
  updated_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,class),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
) STRICT;

CREATE TABLE retention_policies (
  deployment_id TEXT NOT NULL,
  class TEXT NOT NULL CHECK(class IN ('raw_frames','minute_rollups','hour_rollups','request_runs','events_config_audit','resolved_capsules','saved_artifacts','attachment_staging')),
  retention_ms INTEGER NOT NULL CHECK(retention_ms>0),
  record_limit INTEGER CHECK(record_limit IS NULL OR record_limit>0),
  byte_limit INTEGER CHECK(byte_limit IS NULL OR byte_limit>0),
  version INTEGER NOT NULL CHECK(version>=1),
  updated_by TEXT NOT NULL,
  updated_ms INTEGER NOT NULL,
  PRIMARY KEY(deployment_id,class),
  FOREIGN KEY(deployment_id,updated_by) REFERENCES users(deployment_id,id)
) STRICT;

CREATE TABLE recovery_journal_summaries (
  deployment_id TEXT NOT NULL,
  transaction_id TEXT NOT NULL CHECK(length(transaction_id)=36),
  operation TEXT NOT NULL CHECK(operation IN ('upgrade','restore','backup','trust_reset')),
  state TEXT NOT NULL CHECK(state IN ('prepared','activated','rolled_back_pre_activation','failed','completed','ambiguous')),
  pre_activation INTEGER NOT NULL CHECK(pre_activation IN (0,1)),
  backup_manifest_sha256 TEXT CHECK(backup_manifest_sha256 IS NULL OR length(backup_manifest_sha256)=64),
  receipt_high_water_json TEXT NOT NULL CHECK(json_valid(receipt_high_water_json) AND length(receipt_high_water_json)<=65536),
  started_ms INTEGER NOT NULL,
  completed_ms INTEGER,
  summary_bytes INTEGER NOT NULL CHECK(summary_bytes BETWEEN 1 AND 16777216),
  PRIMARY KEY(deployment_id,transaction_id),
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
) STRICT;

CREATE TABLE maintenance (
  deployment_id TEXT PRIMARY KEY NOT NULL,
  retention_revision INTEGER NOT NULL CHECK(retention_revision>=1),
  rollup_watermark_ms INTEGER NOT NULL DEFAULT 0 CHECK(rollup_watermark_ms>=0),
  last_backup_ms INTEGER,
  storage_state TEXT NOT NULL CHECK(storage_state IN ('normal','warning','optional_jobs_stopped','bulk_ingest_paused','read_only_enospc')),
  recovery_journal_cursor TEXT,
  evaluator_cursor_json TEXT NOT NULL CHECK(json_valid(evaluator_cursor_json) AND length(evaluator_cursor_json)<=65536),
  updated_ms INTEGER NOT NULL,
  FOREIGN KEY(deployment_id) REFERENCES deployments(id)
) STRICT;

CREATE TRIGGER source_frame_original_identity_immutable
BEFORE UPDATE OF deployment_id,host_id,security_generation,session_generation,collector_boot_id,source_id,sequence,delivery_mode,incarnation_id,original_wall_ms,duration_ms,quality,definition_revision,codec,payload,payload_sha256,original_security_generation,original_collector_boot_id,original_source_id,original_sequence,original_payload_sha256,recovery_grant_id,recovery_grant_hash,admitted_ms ON source_frames
BEGIN
  SELECT RAISE(ABORT,'immutable_original_frame_identity');
END;

CREATE TRIGGER host_identity_immutable
BEFORE UPDATE OF id,deployment_id,installation_uuid,created_ms ON hosts
BEGIN SELECT RAISE(ABORT,'immutable_host_identity'); END;

CREATE TRIGGER target_identity_immutable
BEFORE UPDATE OF id,deployment_id,host_id,adapter_id,local_selector_hash,created_ms ON targets
BEGIN SELECT RAISE(ABORT,'immutable_target_identity'); END;

CREATE TRIGGER source_identity_immutable
BEFORE UPDATE OF id,deployment_id,host_id,kind,target_id,admitted_capability_revision,created_ms ON sources
BEGIN SELECT RAISE(ABORT,'immutable_source_identity'); END;

CREATE TRIGGER request_run_population_immutable
BEFORE UPDATE OF id,deployment_id,host_id,source_id,target_id,source_kind,verification_state,population_key_sha256,population_key_json,created_ms ON request_runs
BEGIN SELECT RAISE(ABORT,'immutable_request_population'); END;

CREATE TRIGGER process_observation_immutable
BEFORE UPDATE ON process_observations
BEGIN SELECT RAISE(ABORT,'immutable_process_observation'); END;

CREATE TRIGGER model_load_observation_immutable
BEFORE UPDATE ON model_load_observations
BEGIN SELECT RAISE(ABORT,'immutable_model_load_observation'); END;

CREATE TRIGGER config_snapshot_immutable
BEFORE UPDATE ON config_snapshots
BEGIN SELECT RAISE(ABORT,'immutable_config_snapshot'); END;

CREATE TRIGGER request_sample_immutable
BEFORE UPDATE ON request_samples
BEGIN
  SELECT RAISE(ABORT,'immutable_request_sample');
END;

CREATE TRIGGER comparison_immutable
BEFORE UPDATE ON comparisons
BEGIN SELECT RAISE(ABORT,'immutable_comparison'); END;

CREATE TRIGGER alert_transition_immutable
BEFORE UPDATE ON alert_transitions
BEGIN
  SELECT RAISE(ABORT,'immutable_alert_transition');
END;

CREATE TRIGGER snapshot_identity_immutable
BEFORE UPDATE OF deployment_id,type,schema_version,revision,query_json,effective_range_json,payload_hash,relative_blob_path,size_bytes,created_ms ON snapshots
BEGIN
  SELECT RAISE(ABORT,'immutable_snapshot');
END;

CREATE TRIGGER recovery_grant_epoch_immutable
BEFORE UPDATE OF deployment_id,deployment_generation,host_id,original_security_generation,original_collector_boot_id,manifest_hash,allowlist_json,approved_scope_sha256,grant_sha256,max_bytes,max_frames,issued_ms,expires_ms,receipt_detail_expires_ms ON recovery_grants
BEGIN
  SELECT RAISE(ABORT,'immutable_recovery_grant_scope');
END;

CREATE TRIGGER recovery_grant_create_tombstone
AFTER INSERT ON recovery_grants
BEGIN
  INSERT INTO recovery_grant_tombstones(
    deployment_id,deployment_generation,host_id,grant_id,grant_sha256,
    original_security_generation,original_collector_boot_id,manifest_hash,
    approved_scope_sha256,disposition_summary_json,receipt_detail_expires_ms,
    compacted_ms,created_ms
  ) VALUES(
    NEW.deployment_id,NEW.deployment_generation,NEW.host_id,NEW.id,NEW.grant_sha256,
    NEW.original_security_generation,NEW.original_collector_boot_id,NEW.manifest_hash,
    NEW.approved_scope_sha256,'{"state":"detail_retained"}',NEW.receipt_detail_expires_ms,
    NULL,NEW.issued_ms
  );
END;

CREATE TRIGGER recovery_grant_tombstone_identity_immutable
BEFORE UPDATE OF deployment_id,deployment_generation,host_id,grant_id,grant_sha256,original_security_generation,original_collector_boot_id,manifest_hash,approved_scope_sha256,receipt_detail_expires_ms,created_ms ON recovery_grant_tombstones
BEGIN SELECT RAISE(ABORT,'immutable_recovery_grant_tombstone_scope'); END;

CREATE TRIGGER recovery_grant_tombstone_compaction_guard
BEFORE UPDATE OF disposition_summary_json,compacted_ms ON recovery_grant_tombstones
WHEN OLD.compacted_ms IS NOT NULL OR NEW.compacted_ms IS NULL
 OR NEW.compacted_ms<NEW.receipt_detail_expires_ms
 OR NEW.disposition_summary_json='{}'
BEGIN SELECT RAISE(ABORT,'recovery_grant_compaction_invalid'); END;

CREATE TRIGGER recovery_grant_receipt_admission_guard
BEFORE INSERT ON recovery_grant_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM recovery_grants g
  WHERE g.deployment_id=NEW.deployment_id AND g.host_id=NEW.host_id AND g.id=NEW.grant_id
    AND NEW.accepted_ms<=g.expires_ms
)
BEGIN SELECT RAISE(ABORT,'recovery_receipt_outside_live_grant'); END;

CREATE TRIGGER recovery_grant_receipt_delete_after_compaction
BEFORE DELETE ON recovery_grant_receipts
WHEN NOT EXISTS (
  SELECT 1 FROM recovery_grant_tombstones t
  WHERE t.deployment_id=OLD.deployment_id AND t.host_id=OLD.host_id AND t.grant_id=OLD.grant_id
    AND t.compacted_ms IS NOT NULL
)
BEGIN SELECT RAISE(ABORT,'recovery_receipt_detail_not_compacted'); END;

CREATE TRIGGER recovery_grant_delete_after_compaction
BEFORE DELETE ON recovery_grants
WHEN EXISTS (
  SELECT 1 FROM recovery_grant_receipts r
  WHERE r.deployment_id=OLD.deployment_id AND r.host_id=OLD.host_id AND r.grant_id=OLD.id
) OR NOT EXISTS (
  SELECT 1 FROM recovery_grant_tombstones t
  WHERE t.deployment_id=OLD.deployment_id AND t.host_id=OLD.host_id AND t.grant_id=OLD.id
    AND t.compacted_ms IS NOT NULL
)
BEGIN SELECT RAISE(ABORT,'recovery_grant_detail_not_compacted'); END;

CREATE TRIGGER hosts_active_cap
BEFORE INSERT ON hosts
WHEN NEW.retired_ms IS NULL AND (SELECT count(*) FROM hosts WHERE deployment_id=NEW.deployment_id AND retired_ms IS NULL)>=2
BEGIN SELECT RAISE(ABORT,'active_host_cap_2'); END;

CREATE TRIGGER hosts_active_cap_on_unretire
BEFORE UPDATE OF retired_ms ON hosts
WHEN OLD.retired_ms IS NOT NULL AND NEW.retired_ms IS NULL AND (SELECT count(*) FROM hosts WHERE deployment_id=NEW.deployment_id AND retired_ms IS NULL)>=2
BEGIN SELECT RAISE(ABORT,'active_host_cap_2'); END;

CREATE UNIQUE INDEX targets_one_active_per_host ON targets(deployment_id,host_id) WHERE retired_ms IS NULL;

CREATE TRIGGER sources_active_cap
BEFORE INSERT ON sources
WHEN NEW.retired_ms IS NULL AND (SELECT count(*) FROM sources WHERE deployment_id=NEW.deployment_id AND host_id=NEW.host_id AND retired_ms IS NULL)>=8
BEGIN SELECT RAISE(ABORT,'active_source_cap_8'); END;

CREATE TRIGGER passive_sources_host_cap
BEFORE INSERT ON sources
WHEN NEW.retired_ms IS NULL AND NEW.kind IN ('host','runtime') AND (SELECT count(*) FROM sources WHERE deployment_id=NEW.deployment_id AND host_id=NEW.host_id AND kind IN ('host','runtime') AND retired_ms IS NULL)>=2
BEGIN SELECT RAISE(ABORT,'passive_source_host_cap_2'); END;

CREATE TRIGGER passive_sources_deployment_cap
BEFORE INSERT ON sources
WHEN NEW.retired_ms IS NULL AND NEW.kind IN ('host','runtime') AND (SELECT count(*) FROM sources WHERE deployment_id=NEW.deployment_id AND kind IN ('host','runtime') AND retired_ms IS NULL)>=4
BEGIN SELECT RAISE(ABORT,'passive_source_deployment_cap_4'); END;

CREATE TRIGGER sources_active_cap_on_unretire
BEFORE UPDATE OF retired_ms ON sources
WHEN OLD.retired_ms IS NOT NULL AND NEW.retired_ms IS NULL AND (
  (SELECT count(*) FROM sources WHERE deployment_id=NEW.deployment_id AND host_id=NEW.host_id AND retired_ms IS NULL)>=8 OR
  (NEW.kind IN ('host','runtime') AND (SELECT count(*) FROM sources WHERE deployment_id=NEW.deployment_id AND host_id=NEW.host_id AND kind IN ('host','runtime') AND retired_ms IS NULL)>=2) OR
  (NEW.kind IN ('host','runtime') AND (SELECT count(*) FROM sources WHERE deployment_id=NEW.deployment_id AND kind IN ('host','runtime') AND retired_ms IS NULL)>=4)
)
BEGIN SELECT RAISE(ABORT,'source_cap_on_unretire'); END;

CREATE TRIGGER users_cap
BEFORE INSERT ON users
WHEN NEW.historical_restored=0 AND (SELECT count(*) FROM users WHERE deployment_id=NEW.deployment_id AND historical_restored=0)>=10
BEGIN SELECT RAISE(ABORT,'user_cap_10'); END;

CREATE TRIGGER users_current_generation_required
BEFORE INSERT ON users
WHEN NEW.historical_restored!=0 OR NEW.trust_generation!=(SELECT deployment_generation FROM deployments WHERE id=NEW.deployment_id)
BEGIN SELECT RAISE(ABORT,'new_user_requires_current_trust_generation'); END;

CREATE TRIGGER users_historical_restored_cap
BEFORE UPDATE OF historical_restored ON users
WHEN OLD.historical_restored=0 AND NEW.historical_restored=1
 AND (SELECT count(*) FROM users WHERE deployment_id=NEW.deployment_id AND historical_restored=1)>=1000
BEGIN SELECT RAISE(ABORT,'historical_restored_user_cap_1000'); END;

CREATE TRIGGER users_restore_archive_transition
BEFORE UPDATE OF historical_restored,disabled ON users
WHEN OLD.historical_restored=0 AND NEW.historical_restored=1 AND (
  NEW.disabled!=1 OR
  OLD.trust_generation=(SELECT deployment_generation FROM deployments WHERE id=OLD.deployment_id) OR
  (SELECT recovery_state FROM deployments WHERE id=OLD.deployment_id)!='restore_requires_bootstrap' OR
  NOT EXISTS (
    SELECT 1 FROM restore_bootstrap_transitions t JOIN deployments d ON d.id=t.deployment_id
    WHERE t.deployment_id=OLD.deployment_id AND t.deployment_generation=d.deployment_generation
      AND t.hub_stopped=1 AND t.state='archiving_restored_users'
  )
)
BEGIN SELECT RAISE(ABORT,'restore_user_archive_requires_rotated_bootstrap_state'); END;

CREATE TRIGGER users_historical_identity_cannot_revive
BEFORE UPDATE OF historical_restored,disabled ON users
WHEN OLD.historical_restored=1 AND (NEW.historical_restored!=1 OR NEW.disabled!=1)
BEGIN SELECT RAISE(ABORT,'historical_restored_user_cannot_revive'); END;

CREATE TRIGGER user_identity_immutable
BEFORE UPDATE OF id,deployment_id,trust_generation,created_ms ON users
BEGIN SELECT RAISE(ABORT,'immutable_user_identity'); END;

CREATE TRIGGER users_keep_last_enabled_admin_update
BEFORE UPDATE OF role,disabled ON users
WHEN OLD.role='admin' AND OLD.disabled=0 AND (NEW.role!='admin' OR NEW.disabled!=0)
 AND NOT EXISTS (SELECT 1 FROM users WHERE deployment_id=OLD.deployment_id AND id!=OLD.id AND role='admin' AND disabled=0)
 AND NOT (NEW.disabled=1 AND NEW.historical_restored=1 AND (SELECT recovery_state FROM deployments WHERE id=OLD.deployment_id)='restore_requires_bootstrap')
BEGIN SELECT RAISE(ABORT,'last_enabled_admin'); END;

CREATE TRIGGER users_keep_last_enabled_admin_delete
BEFORE DELETE ON users
WHEN OLD.role='admin' AND OLD.disabled=0
 AND NOT EXISTS (SELECT 1 FROM users WHERE deployment_id=OLD.deployment_id AND id!=OLD.id AND role='admin' AND disabled=0)
BEGIN SELECT RAISE(ABORT,'last_enabled_admin'); END;

CREATE TRIGGER rules_cap
BEFORE INSERT ON rules
WHEN (SELECT count(*) FROM rules WHERE deployment_id=NEW.deployment_id)>=64
BEGIN SELECT RAISE(ABORT,'rule_cap_64'); END;

CREATE TRIGGER incidents_open_insert_cap
BEFORE INSERT ON incidents
WHEN NEW.workflow_state='open' AND (SELECT count(*) FROM incidents WHERE deployment_id=NEW.deployment_id AND workflow_state='open')>=1000
BEGIN SELECT RAISE(ABORT,'open_incident_cap_1000'); END;

CREATE TRIGGER incidents_open_update_cap
BEFORE UPDATE OF workflow_state ON incidents
WHEN OLD.workflow_state!='open' AND NEW.workflow_state='open' AND (SELECT count(*) FROM incidents WHERE deployment_id=NEW.deployment_id AND workflow_state='open')>=1000
BEGIN SELECT RAISE(ABORT,'open_incident_cap_1000'); END;

CREATE TRIGGER process_observation_cap
BEFORE INSERT ON process_observations
WHEN (SELECT count(*) FROM process_observations WHERE deployment_id=NEW.deployment_id AND host_id=NEW.host_id AND source_id=NEW.source_id AND observed_ms=NEW.observed_ms)>=32
BEGIN SELECT RAISE(ABORT,'process_observation_cap_32'); END;

CREATE TRIGGER model_loaded_observation_cap
BEFORE INSERT ON model_load_observations
WHEN NEW.state='reported_loaded' AND (SELECT count(*) FROM model_load_observations WHERE deployment_id=NEW.deployment_id AND host_id=NEW.host_id AND target_id=NEW.target_id AND observed_ms=NEW.observed_ms AND state='reported_loaded')>=2
BEGIN SELECT RAISE(ABORT,'loaded_model_cap_2'); END;

CREATE TRIGGER recovery_active_deployment_cap
BEFORE INSERT ON recovery_grants
WHEN (SELECT count(*) FROM recovery_grants WHERE deployment_id=NEW.deployment_id AND revoked_ms IS NULL AND completed_ms IS NULL)>=4
BEGIN SELECT RAISE(ABORT,'active_recovery_grant_cap_4'); END;

CREATE TRIGGER attachment_staging_byte_cap
BEFORE INSERT ON attachments
WHEN coalesce((SELECT sum(size_bytes) FROM attachments WHERE deployment_id=NEW.deployment_id),0)+NEW.size_bytes>52428800
BEGIN SELECT RAISE(ABORT,'attachment_staging_cap_50mib'); END;

CREATE TRIGGER host_current_session_exists
BEFORE UPDATE OF current_session_generation,last_boot_id ON hosts
WHEN NEW.current_session_generation>0 AND NOT EXISTS (
  SELECT 1 FROM collector_sessions s
  WHERE s.deployment_id=NEW.deployment_id AND s.host_id=NEW.id
    AND s.session_generation=NEW.current_session_generation AND s.collector_boot_id=NEW.last_boot_id
)
BEGIN SELECT RAISE(ABORT,'collector_session_pointer_missing'); END;

CREATE TRIGGER source_frame_current_session_required
BEFORE INSERT ON source_frames
WHEN NEW.delivery_mode='current' AND NOT EXISTS (
  SELECT 1 FROM hosts h JOIN collector_sessions s
    ON s.deployment_id=h.deployment_id AND s.host_id=h.id
   AND s.session_generation=h.current_session_generation
  WHERE h.deployment_id=NEW.deployment_id AND h.id=NEW.host_id
    AND NEW.session_generation=h.current_session_generation
    AND h.last_boot_id=NEW.collector_boot_id
    AND s.security_generation=NEW.security_generation
    AND s.superseded_ms IS NULL
)
BEGIN SELECT RAISE(ABORT,'current_frame_from_noncurrent_session'); END;

CREATE TRIGGER deployment_seed_quota_contract
AFTER INSERT ON deployments
BEGIN
  INSERT INTO deployment_generations(deployment_id,generation,reason,activated_ms)
    VALUES(NEW.id,NEW.deployment_generation,'install',NEW.created_ms);
  INSERT INTO quota_classes(deployment_id,class,byte_limit,count_limit,updated_ms) VALUES
    (NEW.id,'live_total',17179869184,NULL,NEW.created_ms),
    (NEW.id,'bulk_database',12884901888,NULL,NEW.created_ms),
    (NEW.id,'detailed_snapshots',1073741824,NULL,NEW.created_ms),
    (NEW.id,'incident_ledger',268435456,3000,NEW.created_ms),
    (NEW.id,'control_ledger',33554432,NULL,NEW.created_ms),
    (NEW.id,'metadata',805306368,NULL,NEW.created_ms),
    (NEW.id,'saved_comparisons',134217728,256,NEW.created_ms),
    (NEW.id,'completed_exports',402653184,8,NEW.created_ms),
    (NEW.id,'transient',1073741824,NULL,NEW.created_ms),
    (NEW.id,'live_headroom',503316480,NULL,NEW.created_ms),
    (NEW.id,'emergency_outside_live',134217728,NULL,NEW.created_ms),
    (NEW.id,'request_samples',536870912,250000,NEW.created_ms),
    (NEW.id,'attachment_staging',52428800,NULL,NEW.created_ms);
END;

CREATE TRIGGER deployment_generation_must_be_registered
BEFORE UPDATE OF deployment_generation ON deployments
WHEN NEW.deployment_generation!=OLD.deployment_generation AND NOT EXISTS (
  SELECT 1 FROM deployment_generations g
  WHERE g.deployment_id=NEW.id AND g.generation=NEW.deployment_generation
)
BEGIN SELECT RAISE(ABORT,'deployment_generation_not_registered'); END;

CREATE TRIGGER deployment_restore_exit_requires_new_admin
BEFORE UPDATE OF recovery_state ON deployments
WHEN OLD.recovery_state='restore_requires_bootstrap' AND NEW.recovery_state!='restore_requires_bootstrap' AND (
  NOT EXISTS (
    SELECT 1 FROM users u WHERE u.deployment_id=NEW.id AND u.role='admin' AND u.disabled=0
      AND u.historical_restored=0 AND u.trust_generation=NEW.deployment_generation
  ) OR NOT EXISTS (
    SELECT 1 FROM restore_bootstrap_transitions t WHERE t.deployment_id=NEW.id
      AND t.deployment_generation=NEW.deployment_generation AND t.state='bootstrap_complete'
      AND t.hub_stopped=1 AND t.completed_ms IS NOT NULL
  )
)
BEGIN SELECT RAISE(ABORT,'restore_bootstrap_admin_required'); END;

CREATE TRIGGER restore_bootstrap_transition_start_guard
BEFORE INSERT ON restore_bootstrap_transitions
WHEN NOT EXISTS (
  SELECT 1 FROM deployments d WHERE d.id=NEW.deployment_id
    AND d.deployment_generation=NEW.deployment_generation
    AND d.recovery_state='restore_requires_bootstrap'
) OR NEW.state!='archiving_restored_users' OR NEW.completed_ms IS NOT NULL
BEGIN SELECT RAISE(ABORT,'offline_restore_bootstrap_state_required'); END;

CREATE TRIGGER restore_bootstrap_transition_complete_guard
BEFORE UPDATE OF state,completed_ms,archived_user_count ON restore_bootstrap_transitions
WHEN NEW.state='bootstrap_complete' AND (
  OLD.state!='archiving_restored_users' OR NEW.completed_ms IS NULL OR
  NEW.archived_user_count!=(SELECT count(*) FROM users WHERE deployment_id=NEW.deployment_id AND historical_restored=1) OR
  EXISTS (
    SELECT 1 FROM users u WHERE u.deployment_id=NEW.deployment_id
      AND u.trust_generation!=NEW.deployment_generation AND u.historical_restored=0
  ) OR
  NOT EXISTS (
    SELECT 1 FROM users u WHERE u.deployment_id=NEW.deployment_id AND u.role='admin' AND u.disabled=0
      AND u.historical_restored=0 AND u.trust_generation=NEW.deployment_generation
  )
)
BEGIN SELECT RAISE(ABORT,'restore_bootstrap_completion_invalid'); END;

CREATE TRIGGER deployment_generation_identity_immutable
BEFORE UPDATE OF deployment_id,generation ON deployment_generations
BEGIN SELECT RAISE(ABORT,'immutable_deployment_generation'); END;
