package store

// ensureComparisonStorage is the additive bridge for databases created before
// the normalized request-evidence comparison tables were reviewed. It never
// rewrites an existing run or infers provenance from a mutable inventory row.
func (s *Store) ensureComparisonStorage() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE UNIQUE INDEX IF NOT EXISTS request_runs_deployment_id ON request_runs(deployment_id,id)`,
		`CREATE TABLE IF NOT EXISTS request_run_metadata (
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
		) STRICT`,
		`CREATE TABLE IF NOT EXISTS comparisons (
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
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS comparisons_expiry ON comparisons(deployment_id,expires_ms)`,
		`CREATE INDEX IF NOT EXISTS comparisons_scope_created ON comparisons(deployment_id,scope_id,created_ms,id)`,
		`CREATE TABLE IF NOT EXISTS incident_comparisons (
			deployment_id TEXT NOT NULL,
			incident_id TEXT NOT NULL,
			comparison_id TEXT NOT NULL,
			attached_by TEXT NOT NULL,
			attached_ms INTEGER NOT NULL,
			PRIMARY KEY(deployment_id,incident_id,comparison_id),
			FOREIGN KEY(deployment_id,incident_id) REFERENCES incidents(deployment_id,id),
			FOREIGN KEY(deployment_id,comparison_id) REFERENCES comparisons(deployment_id,id),
			FOREIGN KEY(deployment_id,attached_by) REFERENCES users(deployment_id,id)
		) STRICT`,
		`CREATE INDEX IF NOT EXISTS incident_comparisons_comparison ON incident_comparisons(deployment_id,comparison_id,attached_ms)`,
		`CREATE TRIGGER IF NOT EXISTS comparison_immutable BEFORE UPDATE ON comparisons BEGIN SELECT RAISE(ABORT,'immutable_comparison'); END`,
	}
	for _, column := range []struct{ table, name, declaration string }{
		{"request_samples", "observation_scope", "TEXT NOT NULL DEFAULT 'explicit_observed_request' CHECK(observation_scope='explicit_observed_request')"},
		{"request_samples", "runtime_source_pin_id", "TEXT NOT NULL DEFAULT 'operator-import-unverified' CHECK(runtime_source_pin_id IN ('ollama-0.34.0-source','ollama-0.12.10-source','operator-import-unverified'))"},
		{"request_samples", "terminal_record_observed", "INTEGER NOT NULL DEFAULT 1 CHECK(terminal_record_observed IN (0,1))"},
	} {
		exists, err := sqliteColumnExists(tx, column.table, column.name)
		if err != nil {
			return err
		}
		if !exists {
			if _, err := tx.Exec("ALTER TABLE " + column.table + " ADD COLUMN " + column.name + " " + column.declaration); err != nil {
				return err
			}
		}
	}
	for _, statement := range statements {
		if _, err := tx.Exec(statement); err != nil {
			return err
		}
	}
	return tx.Commit()
}
