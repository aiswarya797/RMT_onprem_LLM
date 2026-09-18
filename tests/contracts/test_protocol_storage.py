from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).parent))

from contract_oracles import (  # noqa: E402
    ContractError,
    load_bounded_json,
    uint64_decimal,
    validate_action_inventory,
    validate_activation_pair,
    validate_batch_semantics,
    validate_bundle_manifest,
    validate_comparison,
    validate_host_window_comparison,
    validate_local_target_manifest,
    recovery_scope_sha256,
    validate_recovery_contract,
    validate_static_readme,
)


def load(path: str):
    return json.loads((ROOT / path).read_text())


def schema_registry() -> Registry:
    registry = Registry()
    for path in (ROOT / "contracts").rglob("*.schema.json"):
        document = json.loads(path.read_text())
        if "$id" in document:
            registry = registry.with_resource(document["$id"], Resource.from_contents(document))
    return registry


REGISTRY = schema_registry()


def validate(schema_path: str, instance) -> None:
    schema = load(schema_path)
    Draft202012Validator(schema, registry=REGISTRY, format_checker=FormatChecker()).validate(instance)


class SchemaContractTests(unittest.TestCase):
    def test_every_owned_schema_is_valid_draft_2020_12(self):
        owned = ["collector", "api", "bundle", "storage"]
        paths = [path for name in owned for path in (ROOT / "contracts" / name / "v1").glob("*.schema.json")]
        self.assertGreaterEqual(len(paths), 30)
        for path in paths:
            with self.subTest(path=path.relative_to(ROOT)):
                Draft202012Validator.check_schema(json.loads(path.read_text()))

    def test_valid_collector_batch_and_semantics(self):
        batch = load("fixtures/contracts/valid/collector-batch.json")
        validate("contracts/collector/v1/batch.schema.json", batch)
        validate_batch_semantics(batch)
        validate("contracts/collector/v1/batch-ack.schema.json", load("fixtures/contracts/valid/collector-batch-response.json"))

    def test_batch_rejects_unknown_content_and_missing_reason_mismatch(self):
        batch = load("fixtures/contracts/valid/collector-batch.json")
        hostile = copy.deepcopy(batch)
        hostile["frames"][0]["prompt"] = "secret raw prompt"
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/batch.schema.json", hostile)
        missing = copy.deepcopy(batch)
        observation = next(iter(missing["frames"][0]["gauges"].values()))
        observation["value"] = None
        observation["quality"] = "unavailable"
        observation["missing_reason"] = None
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/batch.schema.json", missing)

    def test_config_observation_is_closed_and_preserves_old_frame_compatibility(self):
        batch = load("fixtures/contracts/valid/collector-batch.json")
        config_frame = batch["frames"][2]
        self.assertEqual(config_frame["config_observation"]["fields"]["server_version"], "0.34.0")
        validate("contracts/collector/v1/batch.schema.json", batch)

        old_batch = copy.deepcopy(batch)
        old_batch["frames"] = old_batch["frames"][:2]
        validate("contracts/collector/v1/batch.schema.json", old_batch)

        unknown = copy.deepcopy(batch)
        unknown["frames"][2]["config_observation"]["fields"]["arguments"] = ["--secret"]
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/batch.schema.json", unknown)

        omitted = copy.deepcopy(batch)
        del omitted["frames"][2]["config_observation"]["field_provenance"]["server_version"]
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/batch.schema.json", omitted)

    def test_endpoint_association_is_closed_and_optional_for_retained_frames(self):
        batch = load("fixtures/contracts/valid/collector-batch.json")
        validate("contracts/collector/v1/batch.schema.json", batch)
        frame = batch["frames"][0]
        frame["gauges"] = {}
        frame["network_observations"] = []
        frame["endpoint_association"] = {
            "target_id": frame["process_observations"][0]["target_id"],
            "endpoint_hash": "e" * 64,
            "target_revision": 3,
            "manifest_revision": 2,
            "manifest_sha256": "f" * 64,
            "selector_sha256": "e" * 64,
            "identity_revision": "a" * 64,
            "runtime_version": "0.12.10",
            "runtime_source_pin_id": "ollama-0.12.10-source",
            "pid": frame["process_observations"][0]["pid"],
            "process_start_identity": frame["process_observations"][0]["process_start_identity"],
            "process_key": frame["process_observations"][0]["process_key"],
            "quality": "verified",
            "reason": None,
            "verified_exit": None,
            "provenance": frame["process_observations"][0]["provenance"],
        }
        validate("contracts/collector/v1/batch.schema.json", batch)

        unknown = copy.deepcopy(batch)
        unknown["frames"][0]["endpoint_association"]["executable_path"] = "/private/path"
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/batch.schema.json", unknown)
        missing_pin = copy.deepcopy(batch)
        missing_pin["frames"][0]["endpoint_association"]["runtime_source_pin_id"] = None
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/batch.schema.json", missing_pin)

    def test_batch_has_per_interface_epochs_and_finite_model_cardinality(self):
        batch = load("fixtures/contracts/valid/collector-batch.json")
        frame = batch["frames"][0]
        extra = copy.deepcopy(frame["network_observations"][0])
        extra["interface_id"] = "f" * 64
        extra["counter_epoch_id"] = "90000000-0000-4000-8000-000000000002"
        frame["network_observations"].append(extra)
        validate("contracts/collector/v1/batch.schema.json", batch)
        validate_batch_semantics(batch)
        model = {
            "model_id": "90000000-0000-4000-8000-000000000001", "digest": "a" * 64,
            "loaded": True, "reported_size_bytes": "429000000", "reported_size_vram_bytes": "429000000",
            "missing": [], "provenance": frame["provenance"],
        }
        frame["model_observations"] = [copy.deepcopy(model) for _ in range(3)]
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/batch.schema.json", batch)

    def test_uint64_decimal_preserves_above_javascript_integer_and_rejects_overflow(self):
        self.assertEqual(uint64_decimal("9007199254740993"), 9_007_199_254_740_993)
        self.assertEqual(uint64_decimal("18446744073709551615"), 18_446_744_073_709_551_615)
        with self.assertRaisesRegex(ContractError, "uint64_overflow"):
            uint64_decimal("18446744073709551616")
        with self.assertRaises(ContractError):
            uint64_decimal("09007199254740993")

    def test_bounded_json_rejects_duplicates_nonfinite_and_oversize(self):
        with self.assertRaisesRegex(ContractError, "duplicate_key"):
            load_bounded_json(b'{"a":1,"a":2}', 100)
        with self.assertRaisesRegex(ContractError, "nonfinite"):
            load_bounded_json(b'{"a":NaN}', 100)
        with self.assertRaisesRegex(ContractError, "too_large"):
            load_bounded_json(b"{}", 1)

    def test_control_lane_forbids_arbitrary_url_command_and_path(self):
        valid = load("fixtures/contracts/valid/control-request.json")
        validate("contracts/collector/v1/control-request.schema.json", valid)
        invalid = load("fixtures/contracts/invalid/control-request-url.json")
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/control-request.schema.json", invalid)
        for field in ("command", "path", "url"):
            candidate = copy.deepcopy(valid)
            candidate[field] = "https://example.invalid" if field == "url" else "arbitrary"
            with self.assertRaises(Exception):
                validate("contracts/collector/v1/control-request.schema.json", candidate)

    def test_activation_result_is_bound_to_request_and_compare_and_swap(self):
        request = {
            "protocol": "1.0", "deployment_id": "00000000-0000-4000-8000-000000000001",
            "host_id": "00000000-0000-4000-8000-000000000002",
            "security_generation": "00000000-0000-4000-8000-000000000003",
            "activation_request_id": "00000000-0000-4000-8000-000000000004",
            "collector_boot_id": "00000000-0000-4000-8000-000000000005", "expected_previous_generation": 4,
        }
        result = {
            "activation_request_id": request["activation_request_id"], "security_generation": request["security_generation"],
            "session_generation": 5, "collector_boot_id": request["collector_boot_id"], "activated_ms": 10, "current": True,
        }
        validate("contracts/collector/v1/session.schema.json", request)
        validate("contracts/collector/v1/session-result.schema.json", result)
        validate_activation_pair(request, result)
        result["session_generation"] = 7
        validate_activation_pair(request, result)
        result["session_generation"] = 4
        with self.assertRaisesRegex(ContractError, "compare_and_swap"):
            validate_activation_pair(request, result)

    def test_recovery_manifest_grant_and_replay_preserve_original_identity(self):
        manifest = load("fixtures/contracts/valid/recovery-manifest.json")
        grant = load("fixtures/contracts/valid/recovery-grant.json")
        replay = load("fixtures/contracts/valid/recovery-replay.json")
        ack = load("fixtures/contracts/valid/recovery-ack.json")
        validate("contracts/collector/v1/recovery-manifest.schema.json", manifest)
        validate("contracts/collector/v1/recovery-grant.schema.json", grant)
        validate("contracts/collector/v1/recovery-replay.schema.json", replay)
        validate("contracts/collector/v1/recovery-ack.schema.json", ack)
        validate_recovery_contract(manifest, grant, replay, ack)
        altered = copy.deepcopy(manifest)
        altered["total_bytes"] += 1
        with self.assertRaisesRegex(ContractError, "canonical_hash"):
            validate_recovery_contract(altered, grant, replay, ack)
        swapped = copy.deepcopy(ack)
        swapped["receipts"][0]["original_sequence"] += 1
        with self.assertRaisesRegex(ContractError, "receipt_mismatch"):
            validate_recovery_contract(manifest, grant, replay, swapped)
        swapped_counts = copy.deepcopy(ack)
        swapped_counts["accepted"], swapped_counts["rejected"] = 0, 1
        with self.assertRaisesRegex(ContractError, "count_mismatch"):
            validate_recovery_contract(manifest, grant, replay, swapped_counts)
        altered_payload = copy.deepcopy(replay)
        altered_payload["frames"][0]["original_payload_sha256"] = "9" * 64
        altered_payload["scope_sha256"] = recovery_scope_sha256(altered_payload)
        with self.assertRaisesRegex(ContractError, "segment_hash_mismatch"):
            validate_recovery_contract(manifest, grant, altered_payload)
        active_definition = copy.deepcopy(manifest)
        active_definition["historical_definitions"]["sources"][0]["active"] = True
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/recovery-manifest.schema.json", active_definition)
        null_array = copy.deepcopy(manifest)
        null_array["loss_intervals"] = None
        with self.assertRaises(Exception):
            validate("contracts/collector/v1/recovery-manifest.schema.json", null_array)
        replay["host_id"] = "a0000000-0000-4000-8000-000000000099"
        replay["scope_sha256"] = recovery_scope_sha256(replay)
        with self.assertRaisesRegex(ContractError, "owner_mismatch"):
            validate_recovery_contract(manifest, grant, replay, ack)

    def test_bundle_payload_schemas_manifest_and_path_safety(self):
        manifest = load("fixtures/contracts/valid/bundle-manifest.json")
        validate("contracts/bundle/v1/manifest.schema.json", manifest)
        validate_bundle_manifest(manifest)
        mapping = {
            "bundle-incident.json": "incident.schema.json", "bundle-inventory.json": "inventory.schema.json",
            "bundle-configuration.json": "configuration.schema.json", "bundle-series-record.json": "series-record.schema.json",
            "bundle-coverage.json": "coverage.schema.json",
        }
        for fixture, schema in mapping.items():
            validate(f"contracts/bundle/v1/{schema}", load(f"fixtures/contracts/valid/{fixture}"))
        invalid = load("fixtures/contracts/invalid/bundle-path-traversal.json")
        with self.assertRaises(Exception):
            validate("contracts/bundle/v1/manifest.schema.json", invalid)

    def test_manifest_has_no_self_hash_and_counts_manifest_bytes(self):
        manifest = load("fixtures/contracts/valid/bundle-manifest.json")
        self.assertNotIn("manifest.json", {entry["path"] for entry in manifest["entries"]})
        self.assertEqual(manifest["payload_uncompressed_bytes"] + manifest["manifest_size_bytes"], manifest["total_archive_decoded_bytes"])
        bad = copy.deepcopy(manifest)
        bad["total_archive_decoded_bytes"] += 1
        with self.assertRaisesRegex(ContractError, "archive_size"):
            validate_bundle_manifest(bad)

    def test_readme_static_screen_rejects_active_and_remote_variants(self):
        validate_static_readme("<!doctype html><meta charset=utf-8><h1>Offline report</h1>")
        for hostile in ("<script>alert(1)</script>", '<img src="https://x.invalid/x">', '<a href="javascript:alert(1)">x</a>', "<SCRIPT src=x></SCRIPT>"):
            with self.subTest(hostile=hostile):
                with self.assertRaises(ContractError):
                    validate_static_readme(hostile)

    def _summary(self):
        key = {
            "target_id": "00000000-0000-4000-8000-000000000010", "model_digest": "a" * 64,
            "runtime_version": "0.34.0", "runtime_build": "go1.26.0+modified", "config_revision": "b" * 64,
            "profile_id": "small_direct", "profile_sha256": "c" * 64,
            "options": {"num_ctx": 1024, "num_predict": 64, "temperature": 0, "seed": 1, "think": False, "stream": True, "cold_warm_policy": "not_controlled"},
            "concurrency": 1, "vantage_id": "same_host", "clock_method": "monotonic",
            "source_kind": "deliberate_probe", "verification_state": "direct_capture",
        }
        return {"metric_id": "request.client.total_ms", "provenance_key": {"source_kind": "deliberate_probe", "verification_state": "direct_capture", "metric_source": "client_monotonic"}, "population_key": key}

    def test_comparison_exact_or_one_declared_intervention(self):
        before = self._summary(); after = copy.deepcopy(before)
        validate_comparison(before, after, None, "no_clear_observed_change")
        after["population_key"]["runtime_version"] = "0.34.1"
        after["population_key"]["runtime_build"] = "go1.26.0+clean"
        canonical = lambda v: hashlib.sha256(json.dumps(v, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        intervention = {"type": "runtime_version", "field": "runtime_version", "before_value_sha256": canonical("0.34.0"), "after_value_sha256": canonical("0.34.1")}
        validate_comparison(before, after, intervention, "observed_change_with_confounds")
        after["population_key"]["model_digest"] = "d" * 64
        with self.assertRaisesRegex(ContractError, "population_mismatch"):
            validate_comparison(before, after, intervention, "observed_change_with_confounds")

    def test_comparison_blocks_added_key_multiple_options_and_bad_hash(self):
        before = self._summary(); after = copy.deepcopy(before)
        after["population_key"]["options"]["num_ctx"] = 2048
        after["population_key"]["options"]["num_predict"] = 128
        intervention = {"type": "generation_option", "field": "num_ctx", "before_value_sha256": "0" * 64, "after_value_sha256": "1" * 64}
        with self.assertRaisesRegex(ContractError, "multiple_generation"):
            validate_comparison(before, after, intervention, "observed_change_with_confounds")
        after = copy.deepcopy(before); after["population_key"]["new_option"] = 1
        with self.assertRaisesRegex(ContractError, "uncontrolled"):
            validate_comparison(before, after, None, "no_clear_observed_change")

    def test_no_request_host_window_comparison_supports_pressure_state_duration(self):
        request = load("fixtures/contracts/valid/host-window-comparison-request.json")
        result = load("fixtures/contracts/valid/host-window-comparison-result.json")
        validate_host_window_comparison(request, result)
        request_schema = load("contracts/api/v1/action-request.schema.json")
        Draft202012Validator({"$ref": request_schema["$id"] + "#/$defs/comparison"}, registry=REGISTRY).validate(request)
        validate("contracts/api/v1/comparison.schema.json", result)
        validate("contracts/bundle/v1/comparison.schema.json", load("fixtures/contracts/valid/bundle-host-window-comparison.json"))
        query_schema = load("contracts/api/v1/query.schema.json")
        self.assertTrue({"host_id", "source_id", "resolution_tier", "method_revision", "epoch_id", "clock_method", "coverage_ratio"} <= set(query_schema["required"]))
        preview = load("contracts/api/v1/openapi.json")["paths"]["/api/v1/comparisons/preview"]["get"]
        self.assertEqual(preview["x-query-contract"]["$ref"], "action-request.schema.json#/$defs/comparison")
        preview_names = {parameter["name"] for parameter in preview["parameters"]}
        self.assertTrue({"comparison_kind", "host_id", "source_id", "resolution_tier", "method_revision", "epoch_id", "clock_method", "before_start_ms", "before_end_ms", "after_start_ms", "after_end_ms"} <= preview_names)
        self.assertNotIn("before_run_id", request)
        self.assertEqual(result["before"]["state_durations_ms"]["warning"], 270000)

    def test_host_window_comparison_rejects_unequal_overlap_low_coverage_and_epoch_loss(self):
        valid = load("fixtures/contracts/valid/host-window-comparison-request.json")
        cases = []
        unequal = copy.deepcopy(valid); unequal["after"]["end_ms"] += 1; cases.append(unequal)
        overlap = copy.deepcopy(valid); overlap["after"]["start_ms"] -= 1; overlap["after"]["end_ms"] -= 1; cases.append(overlap)
        low = copy.deepcopy(valid); low["before"]["coverage_ratio"] = 0.89; cases.append(low)
        epoch = copy.deepcopy(valid); epoch["epoch_id"] = ""; cases.append(epoch)
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises(ContractError): validate_host_window_comparison(candidate)

    def test_pressure_observed_duration_uses_exact_ninety_percent_eligibility(self):
        request = load("fixtures/contracts/valid/host-window-comparison-request.json")
        exact = load("fixtures/contracts/valid/host-window-comparison-result.json")
        validate_host_window_comparison(request, exact)
        self.assertEqual(sum(exact["before"]["state_durations_ms"].values()) * 10, 300_000 * 9)

        one_millisecond_below = copy.deepcopy(exact)
        one_millisecond_below["before"]["state_durations_ms"] = {
            "normal": 0, "warning": 269_999, "critical": 0,
        }
        with self.assertRaisesRegex(ContractError, "pressure_observed_coverage_insufficient"):
            validate_host_window_comparison(request, one_millisecond_below)

        reproduced_round_two_case = copy.deepcopy(exact)
        reproduced_round_two_case["before"]["state_durations_ms"] = {
            "normal": 0, "warning": 267_001, "critical": 0,
        }
        self.assertEqual(reproduced_round_two_case["before"]["coverage_ratio"], 0.9)
        with self.assertRaisesRegex(ContractError, "pressure_observed_coverage_insufficient"):
            validate_host_window_comparison(request, reproduced_round_two_case)

        inconsistent_display_ratio = copy.deepcopy(exact)
        inconsistent_request = copy.deepcopy(request)
        inconsistent_request["before"]["coverage_ratio"] = 0.92
        inconsistent_display_ratio["before"]["coverage_ratio"] = 0.92
        with self.assertRaisesRegex(ContractError, "pressure_duration_coverage_mismatch"):
            validate_host_window_comparison(inconsistent_request, inconsistent_display_ratio)

    def test_action_inventory_openapi_parity_typed_success_and_bootstrap(self):
        inventory = load("contracts/api/v1/action-inventory.json")
        validate("contracts/api/v1/action-inventory.schema.json", inventory)
        openapi = load("contracts/api/v1/openapi.json")
        validate_action_inventory(inventory["actions"], openapi)
        for action in inventory["actions"]:
            if action["method"] is None:
                continue
            op = openapi["paths"][action["path"]][action["method"].lower()]
            success = {code: value for code, value in op["responses"].items() if code != "default"}
            self.assertEqual(len(success), 1)
            code, response = next(iter(success.items()))
            if code != "204": self.assertIn("content", response)
            if action["surface"] == "collector_api" and action["id"] != "collector.enrollment.exchange":
                self.assertEqual(op["security"], [{"mutualTLS": []}])
        enrollment = openapi["paths"]["/collector/v1/enrollments"]["post"]
        self.assertEqual(enrollment["security"], [{"enrollmentToken": []}])
        self.assertIn("200", enrollment["responses"]); self.assertNotIn("202", enrollment["responses"])
        self.assertEqual(openapi["servers"][0]["url"], "http://127.0.0.1:9443")

    def test_enrollment_create_distinguishes_ordinary_from_reviewed_replacement(self):
        schema = load("contracts/api/v1/action-request.schema.json")
        validator = Draft202012Validator(
            {"$ref": schema["$id"] + "#/$defs/enrollmentCreate"},
            registry=REGISTRY,
            format_checker=FormatChecker(),
        )
        validator.validate({"host_display_name": "Second Mac", "expires_in_seconds": 600})
        validator.validate({
            "host_display_name": "Restored Mac",
            "expires_in_seconds": 600,
            "replacement_host_id": "00000000-0000-4000-8000-000000000001",
        })
        with self.assertRaises(Exception):
            validator.validate({
                "host_display_name": "Restored Mac",
                "expires_in_seconds": 600,
                "replacement_host_id": None,
            })

    def test_api_token_wire_uses_public_hash_identity_and_typed_mutation_results(self):
        response_schema = load("contracts/api/v1/response.schema.json")
        response_validator = lambda name, value: Draft202012Validator(
            {"$ref": response_schema["$id"] + f"#/$defs/{name}"},
            registry=REGISTRY, format_checker=FormatChecker()).validate(value)
        record = {
            "id": "a" * 64,
            "user_id": "00000000-0000-4000-8000-000000000001",
            "username": "smoke-admin",
            "display_name": "Integration child",
            "scope": "admin",
            "created_ms": 1_789_500_000_000,
            "expires_ms": 1_789_503_600_000,
            "revoked_ms": None,
        }
        response_validator("tokenOnce", {"token": "secret-value-with-at-least-32-bytes-0001", "record": record})
        response_validator("tokenList", {"items": [record]})
        response_validator("tokenRevocation", {"id": record["id"], "revoked_ms": 1_789_500_001_000})
        self.assertEqual(response_schema["$defs"]["tokenList"]["properties"]["items"]["maxItems"], 100)

        uuid_identifier = copy.deepcopy(record)
        uuid_identifier["id"] = "00000000-0000-4000-8000-000000000002"
        with self.assertRaises(Exception):
            response_validator("tokenList", {"items": [uuid_identifier]})
        missing_scope = copy.deepcopy(record)
        missing_scope.pop("scope")
        with self.assertRaises(Exception):
            response_validator("tokenList", {"items": [missing_scope]})
        leaked_bearer = copy.deepcopy(record)
        leaked_bearer["token"] = "must-not-appear"
        with self.assertRaises(Exception):
            response_validator("tokenList", {"items": [leaked_bearer]})

        openapi = load("contracts/api/v1/openapi.json")
        create = openapi["paths"]["/api/v1/auth/tokens"]["post"]
        revoke = openapi["paths"]["/api/v1/auth/tokens/{token_id}"]["delete"]
        self.assertEqual(set(create["responses"]), {"201", "default"})
        self.assertEqual(set(revoke["responses"]), {"200", "default"})
        self.assertEqual(revoke["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                         "response.schema.json#/$defs/tokenRevocation")
        self.assertEqual(revoke["parameters"][0]["schema"]["pattern"], "^[0-9a-f]{64}$")
        inventory = {item["id"]: item for item in load("contracts/api/v1/action-inventory.json")["actions"]}
        self.assertEqual(inventory["auth.tokens.revoke"]["response_contract"], "TokenRevocation")

    def test_every_openapi_schema_reference_resolves(self):
        openapi = load("contracts/api/v1/openapi.json")
        resolver = REGISTRY.resolver("https://llm-monitor.local/contracts/api/v1/openapi.json")
        refs = []
        def walk(value):
            if isinstance(value, dict):
                if "$ref" in value: refs.append(value["$ref"])
                for child in value.values(): walk(child)
            elif isinstance(value, list):
                for child in value: walk(child)
        walk(openapi["paths"])
        self.assertGreaterEqual(len(refs), 100)
        for ref in refs:
            with self.subTest(ref=ref): resolver.lookup(ref)

    def test_api_requests_are_concrete_for_manual_incident_rule_comparison_and_upload(self):
        request_schema = load("contracts/api/v1/action-request.schema.json")
        validator = lambda name, value: Draft202012Validator({"$ref": request_schema["$id"] + f"#/$defs/{name}"}, registry=REGISTRY, format_checker=FormatChecker()).validate(value)
        incident = {"title": "Memory pressure", "scope": {"kind": "host", "id": "00000000-0000-4000-8000-000000000001"}, "start": "2026-09-15T00:00:00Z", "end": "2026-09-15T00:05:00Z"}
        validator("incidentCreate", incident)
        comparison = {"comparison_kind": "request_run", "scope_id": incident["scope"]["id"], "metric_id": "request.client.total_ms", "before_run_id": "00000000-0000-4000-8000-000000000002", "after_run_id": "00000000-0000-4000-8000-000000000003", "declared_intervention": None}
        validator("comparison", comparison)
        incomplete = copy.deepcopy(comparison); incomplete.pop("metric_id")
        with self.assertRaises(Exception): validator("comparison", incomplete)
        upload = load("contracts/api/v1/openapi.json")["paths"]["/api/v1/attachments"]["post"]["requestBody"]["content"]["multipart/form-data"]["schema"]
        self.assertIn("file", upload["required"]); self.assertEqual(upload["properties"]["file"]["maxLength"], 10485760)

    def test_probe_import_cannot_preserve_direct_capture_provenance(self):
        direct = load("fixtures/contracts/probe/request-run-valid.json")
        envelope = {"original_artifact_sha256": "a" * 64, "normalization_revision": "probe-import-1", "run": direct}
        with self.assertRaises(Exception):
            validate("contracts/api/v1/probe-import.schema.json", envelope)
        imported = copy.deepcopy(direct)
        imported["source_kind"] = "imported_test"; imported["verification_state"] = "operator_imported_unverified"
        imported["population_key"]["source_kind"] = "imported_test"; imported["population_key"]["verification_state"] = "operator_imported_unverified"
        for sample in imported["samples"]:
            sample["source_kind"] = "imported_test"; sample["verification_state"] = "operator_imported_unverified"
            sample["runtime_source_pin_id"] = "operator-import-unverified"
            sample["population_key"]["source_kind"] = "imported_test"; sample["population_key"]["verification_state"] = "operator_imported_unverified"
            for field in sample["field_provenance"].values():
                field["source"] = "operator_import"; field["verification"] = "operator_imported_unverified"
        envelope["run"] = imported
        validate("contracts/api/v1/probe-import.schema.json", envelope)

    def test_local_action_contracts_are_finite_and_do_not_accept_helper_urls_or_commands(self):
        local = load("contracts/api/v1/local-action.schema.json")
        inventory = load("contracts/api/v1/action-inventory.json")
        contract_to_def = {
            "InstallCheck": "installCheck", "SetupLocal": "setupLocal", "UninstallPreview": "uninstallPreview",
            "TargetAdd": "targetAdd", "TargetEdit": "targetEdit", "TargetRemove": "targetRemove",
            "CredentialSet": "credentialSet", "CredentialTest": "credentialTest", "PermissionCheck": "permissionCheck",
            "LocalProbeRun": "probeRun", "BundleInspect": "bundleInspect", "BackupCreate": "backupCreate",
            "BackupVerify": "backupVerify", "Restore": "restore", "Upgrade": "upgrade",
            "UninstallKeep": "uninstallKeep", "UninstallPurge": "uninstallPurge",
            "RecoveryPreview": "recoveryPreview", "RecoveryApply": "recoveryApply",
        }
        used = {a["request_contract"] for a in inventory["actions"] if a["surface"] == "local_owner"}
        self.assertTrue(used - {"TypedConfirmation", "Empty"} <= contract_to_def.keys())
        for contract, name in contract_to_def.items():
            if contract not in used:
                continue
            schema = local["$defs"][name]
            self.assertFalse({"url", "command", "arguments"} & set(schema.get("properties", {})))
            Draft202012Validator.check_schema(schema)

    def test_setup_local_response_accepts_explicit_reenrollment_results(self):
        local = load("contracts/api/v1/local-response.schema.json")
        validator = Draft202012Validator(
            {"$ref": local["$id"] + "#/$defs/setupLocal"}, registry=REGISTRY
        )
        result = {
            "schema_version": "1.0",
            "status": "reenrolled",
            "deployment_id": "00000000-0000-4000-8000-000000000001",
            "deployment_generation": "00000000-0000-4000-8000-000000000002",
            "hub_state": "not_started",
            "collector_state": "not_started",
            "created": False,
        }
        validator.validate(result)
        retry = copy.deepcopy(result)
        retry["status"] = "already_reenrolled"
        validator.validate(retry)
        result["status"] = "restored"
        with self.assertRaises(Exception):
            validator.validate(result)

    def test_reviewed_local_target_manifest_allows_nondefault_loopback_port(self):
        raw = (ROOT / "fixtures/contracts/valid/local-target-manifest.json").read_bytes()
        manifest = json.loads(raw)
        action = {
            "manifest_path": "./target.json", "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "reviewed_manifest": manifest, "confirm_deployment_id": "00000000-0000-4000-8000-000000000001",
        }
        local = load("contracts/api/v1/local-action.schema.json")
        Draft202012Validator({"$ref": local["$id"] + "#/$defs/targetAdd"}, registry=REGISTRY).validate(action)
        validate_local_target_manifest(action, raw)
        self.assertEqual(manifest["endpoint"]["port"], 11435)
        hostile = copy.deepcopy(action); hostile["reviewed_manifest"]["endpoint"]["loopback_host"] = "192.0.2.1"
        with self.assertRaises(Exception):
            Draft202012Validator({"$ref": local["$id"] + "#/$defs/targetAdd"}, registry=REGISTRY).validate(hostile)
        remote_control = load("fixtures/contracts/valid/control-request.json"); remote_control["url"] = "http://127.0.0.1:11435"
        with self.assertRaises(Exception): validate("contracts/collector/v1/control-request.schema.json", remote_control)

    def test_backup_and_restore_local_actions_require_key_paths_and_reviewed_identity(self):
        local = load("contracts/api/v1/local-action.schema.json")
        deployment = "00000000-0000-4000-8000-000000000001"
        generation = "10000000-0000-4000-8000-000000000001"
        action = lambda name: Draft202012Validator(
            {"$ref": local["$id"] + f"#/$defs/{name}"}, registry=REGISTRY, format_checker=FormatChecker()
        )

        create = {
            "destination_path": "/private/var/tmp/monitor backup.age",
            "key_out_path": "/private/var/tmp/recovery key.txt",
            "confirm_deployment_id": deployment,
            "deployment_generation": generation,
        }
        action("backupCreate").validate(create)
        for invalid in (
            {**create, "key_file_path": "/private/var/tmp/existing.key"},
            {key: value for key, value in create.items() if key != "key_out_path"},
            {**create, "destination_path": "relative.age"},
            {key: value for key, value in create.items() if key != "deployment_generation"},
        ):
            with self.assertRaises(Exception):
                action("backupCreate").validate(invalid)

        action("backupVerify").validate({
            "backup_path": create["destination_path"], "key_file_path": create["key_out_path"],
            "confirm_deployment_id": deployment,
        })
        fresh_restore = {
            "backup_path": create["destination_path"], "key_file_path": create["key_out_path"],
            "confirm_deployment_id": deployment, "deployment_generation": generation,
            "confirm_recovery_point_ms": 1800000000000,
        }
        action("restore").validate(fresh_restore)
        action("restore").validate({
            "resume_transaction": "20000000-0000-4000-8000-000000000001",
            "confirm_deployment_id": deployment, "deployment_generation": generation,
            "confirm_recovery_point_ms": 1800000000000,
        })
        with self.assertRaises(Exception):
            action("restore").validate({**fresh_restore, "resume_transaction": "20000000-0000-4000-8000-000000000001"})

    def test_backup_and_restore_local_results_match_native_wire_shape(self):
        local = load("contracts/api/v1/local-response.schema.json")
        result = lambda name: Draft202012Validator(
            {"$ref": local["$id"] + f"#/$defs/{name}"}, registry=REGISTRY, format_checker=FormatChecker()
        )
        deployment = "00000000-0000-4000-8000-000000000001"
        generation = "10000000-0000-4000-8000-000000000001"
        backup = {
            "schema_version": "1.0", "status": "created_verified",
            "deployment_id": deployment, "deployment_generation": generation,
            "recovery_point_ms": 1800000000000, "manifest_sha256": "a" * 64,
            "high_water": {"source_frame_rowid": 4, "source_status_rowid": 3, "audit_rowid": 2},
            "backup_path": "/private/var/tmp/monitor.age",
            "recovery_key_path": "/private/var/tmp/recovery.key", "published": True,
        }
        result("backup").validate(backup)
        verify = copy.deepcopy(backup)
        verify["status"] = "verified"; verify["published"] = False; verify.pop("recovery_key_path")
        result("backup").validate(verify)
        restored = {
            "schema_version": "1.0", "status": "restore_requires_bootstrap",
            "transaction_id": "20000000-0000-4000-8000-000000000001",
            "deployment_id": deployment, "deployment_generation": "10000000-0000-4000-8000-000000000002",
            "recovery_point_ms": 1800000000000,
            "displaced_directory": "/private/var/tmp/recovery/displaced",
            "bootstrap_token_path": "/private/var/tmp/bootstrap.token",
            "reenrollment_required": True, "later_changes_unknown": True,
            "recovery_evidence": {
                "current_state_readable": True,
                "same_generation": True,
                "backup_high_water": {"source_frame_rowid": 100, "source_status_rowid": 20, "audit_rowid": 5},
                "displaced_high_water": {"source_frame_rowid": 104, "source_status_rowid": 21, "audit_rowid": 6},
                "known_later_records": [
                    {"class": "source_frames", "retained_rows": 4, "first_hub_time_ms": 1800000000001, "last_hub_time_ms": 1800000004000},
                ],
            },
        }
        result("restoreResult").validate(restored)
        with self.assertRaises(Exception):
            result("restoreResult").validate({**restored, "reenrollment_required": False})
        with self.assertRaises(Exception):
            result("restoreResult").validate({**restored, "recovery_evidence": {**restored["recovery_evidence"], "known_later_records": [{"class": "unknown", "retained_rows": 1, "first_hub_time_ms": None, "last_hub_time_ms": None}]}})

    def test_recovery_inspection_only_emits_resume_for_verified_prepared_state(self):
        local = load("contracts/api/v1/local-response.schema.json")
        schema = {"$ref": local["$id"] + "#/$defs/recoveryInspection"}
        validator = Draft202012Validator(schema, registry=REGISTRY)
        base = {"schema_version": "1.0", "state": "no_journal", "journal_path": "/private/active.json", "recovery_point_ms": None, "resume_argv": [], "later_changes_unknown": True}
        validator.validate(base)
        with self.assertRaises(Exception):
            validator.validate({**base, "resume_argv": ["llm-monitor"]})
        prepared = {**base, "state": "prepared", "transaction_id": "00000000-0000-4000-8000-000000000001", "deployment_id": "00000000-0000-4000-8000-000000000001", "previous_generation": "10000000-0000-4000-8000-000000000001", "deployment_generation": "20000000-0000-4000-8000-000000000001", "recovery_point_ms": 1000, "resume_argv": ["arg"] * 14}
        validator.validate(prepared)
        with self.assertRaises(Exception):
            validator.validate({**prepared, "resume_argv": []})
        validator.validate({**prepared, "state": "committed", "resume_argv": []})

    def test_current_local_status_resolves_deployment_state_contract(self):
        local = load("contracts/api/v1/local-response.schema.json")
        status = {
            "schema_version": "1.0",
            "deployment_state": {
                "schema_version": "1.0",
                "deployment_id": "00000000-0000-4000-8000-000000000001",
                "deployment_generation": "10000000-0000-4000-8000-000000000001",
                "recovery_state": "normal",
                "recovery_point_ms": None,
                "mutations_allowed": True,
            },
            "hub_state": "running",
            "collector_state": "stopped",
            "target_state": "none",
            "host_count": 0,
            "target_count": 0,
            "source_count": 0,
            "collection_started": False,
            "inference_started": False,
        }
        Draft202012Validator(
            {"$ref": local["$id"] + "#/$defs/foundationStatus"},
            registry=REGISTRY,
            format_checker=FormatChecker(),
        ).validate(status)

    def test_product_probe_is_one_explicitly_confirmed_request(self):
        local = load("contracts/api/v1/local-action.schema.json")
        validator = Draft202012Validator({"$ref": local["$id"] + "#/$defs/probeRun"}, registry=REGISTRY)
        valid = {
            "target_id": "00000000-0000-4000-8000-000000000001", "profile_id": "small_direct", "count": 1,
            "load_confirmation": {"confirmation": "confirm_load", "profile_sha256": "a" * 64, "displayed_budget_sha256": "b" * 64},
            "confirm_deployment_id": "00000000-0000-4000-8000-000000000002",
        }
        validator.validate(valid)
        for count in (2, 1000):
            candidate = copy.deepcopy(valid); candidate["count"] = count
            with self.assertRaises(Exception): validator.validate(candidate)
        missing = copy.deepcopy(valid); missing.pop("load_confirmation")
        with self.assertRaises(Exception): validator.validate(missing)


class StorageContractTests(unittest.TestCase):
    DEP = "00000000-0000-4000-8000-000000000001"
    GEN1 = "10000000-0000-4000-8000-000000000001"
    GEN2 = "10000000-0000-4000-8000-000000000002"
    HOST = "20000000-0000-4000-8000-000000000001"
    TARGET = "30000000-0000-4000-8000-000000000001"
    HOST_SOURCE = "40000000-0000-4000-8000-000000000001"
    REQUEST_SOURCE = "40000000-0000-4000-8000-000000000002"
    USER = "50000000-0000-4000-8000-000000000001"

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.executescript((ROOT / "contracts/storage/v1/schema.sql").read_text())
        self.db.execute("INSERT INTO deployments VALUES(?,?,?,?,?,?,?,?,?)", (self.DEP,"test",1,"mac-ollama-1","60000000-0000-4000-8000-000000000001",self.GEN1,"normal",1,1))
        self.db.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?,?)", (self.USER,self.DEP,"admin","x"*32,"admin",0,self.GEN1,0,1,1,1))

    def tearDown(self): self.db.close()

    def add_host(self, host=None, retired=None):
        host = host or self.HOST
        self.db.execute("INSERT INTO hosts VALUES(?,?,?,?,?,?,?,?,?,?,?)", (host,self.DEP,"mac","70000000-0000-4000-8000-"+host[-12:],0,None,None,"{}",retired,1,1))
        return host

    def add_target_and_sources(self):
        self.add_host()
        self.db.execute("INSERT INTO targets VALUES(?,?,?,?,?,?,?,?,?,?)", (self.TARGET,self.DEP,self.HOST,"ollama","a"*64,"ollama","local",None,1,1))
        self.db.execute("INSERT INTO sources VALUES(?,?,?,?,?,?,?,?,?)", (self.HOST_SOURCE,self.DEP,self.HOST,"host",None,"mac-ollama-1",None,1,1))
        self.db.execute("INSERT INTO sources VALUES(?,?,?,?,?,?,?,?,?)", (self.REQUEST_SOURCE,self.DEP,self.HOST,"observed_request",self.TARGET,"mac-ollama-1",None,1,1))

    def test_schema_is_strict_foreign_key_clean_and_seeds_exact_quotas(self):
        tables = self.db.execute("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
        self.assertGreaterEqual(tables, 50)
        self.assertEqual(self.db.execute("SELECT count(*) FROM quota_classes WHERE deployment_id=?", (self.DEP,)).fetchone()[0], 13)
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])
        with self.assertRaises(sqlite3.IntegrityError): self.db.execute("INSERT INTO deployments(id) VALUES(?)", ("bad",))

    def test_generation_rotation_retains_old_jobs_without_rewriting_epoch(self):
        self.db.execute("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ("80000000-0000-4000-8000-000000000001",self.DEP,self.GEN1,"backup","succeeded",1.0,"{}",self.USER,None,None,None,1,2,100))
        self.db.execute("INSERT INTO idempotency_receipts VALUES(?,?,?,?,?,?,?,?,?)", (self.DEP,self.GEN1,self.USER,"stable-key-000001","a"*64,200,"{}",1,86_400_001))
        self.db.execute("INSERT INTO user_sessions VALUES(?,?,?,?,?,?,?,?,?)", ("b"*64,self.DEP,self.GEN1,self.USER,1,100,200,1,None))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "generation_not_registered"):
            self.db.execute("UPDATE deployments SET deployment_generation=? WHERE id=?", (self.GEN2,self.DEP))
        self.db.execute("INSERT INTO deployment_generations VALUES(?,?,?,?)", (self.DEP,self.GEN2,"trust_reset",3))
        self.db.execute("UPDATE deployments SET deployment_generation=?,updated_ms=3 WHERE id=?", (self.GEN2,self.DEP))
        self.assertEqual(self.db.execute("SELECT deployment_generation FROM jobs").fetchone()[0], self.GEN1)
        self.assertEqual(self.db.execute("SELECT deployment_generation FROM idempotency_receipts").fetchone()[0], self.GEN1)
        self.assertEqual(self.db.execute("SELECT deployment_generation FROM user_sessions").fetchone()[0], self.GEN1)

    def test_active_host_caps_ignore_retired_insert_and_block_unretire(self):
        self.add_host()
        second = "20000000-0000-4000-8000-000000000002"; self.add_host(second)
        retired = "20000000-0000-4000-8000-000000000003"; self.add_host(retired, 9)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "active_host_cap_2"):
            self.db.execute("UPDATE hosts SET retired_ms=NULL WHERE id=?", (retired,))

    def test_last_enabled_admin_cannot_be_disabled_demoted_or_deleted(self):
        for sql in ("UPDATE users SET disabled=1 WHERE id=?", "UPDATE users SET role='viewer' WHERE id=?", "DELETE FROM users WHERE id=?"):
            with self.subTest(sql=sql):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "last_enabled_admin"):
                    self.db.execute(sql, (self.USER,))

    def _assert_restore_bootstrap_with_existing_users(self, total_users):
        user_ids = [self.USER]
        for index in range(1, total_users):
            user_id = f"50000000-0000-4000-8001-{index:012d}"
            user_ids.append(user_id)
            self.db.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?,?)", (user_id,self.DEP,f"viewer-{index}","x"*32,"viewer",0,self.GEN1,0,1,1,1))
        for index, user_id in enumerate(user_ids):
            audit_id = f"51000000-0000-4000-8000-{index:012d}"
            self.db.execute("INSERT INTO audit VALUES(?,?,?,?,?,?,?)", (audit_id,self.DEP,user_id,"user_created",user_id,1,"{}"))
        if total_users == 10:
            with self.assertRaisesRegex(sqlite3.IntegrityError, "user_cap_10"):
                self.db.execute(
                    "INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    ("50000000-0000-4000-8002-000000000001", self.DEP, "eleventh", "x" * 32, "viewer", 0, self.GEN1, 0, 1, 1, 1),
                )
        self.db.execute("INSERT INTO deployment_generations VALUES(?,?,?,?)", (self.DEP,self.GEN2,"restore_bootstrap",2))
        self.db.execute("UPDATE deployments SET deployment_generation=?,recovery_state='restore_requires_bootstrap',updated_ms=2 WHERE id=?", (self.GEN2,self.DEP))
        self.db.execute("INSERT INTO restore_bootstrap_transitions VALUES(?,?,?,?,?,?,?,?)", (self.DEP,self.GEN2,501,1,"archiving_restored_users",0,2,None))
        with self.assertRaisesRegex(sqlite3.IntegrityError, "completion_invalid"):
            self.db.execute(
                "UPDATE restore_bootstrap_transitions SET state='bootstrap_complete',archived_user_count=0,completed_ms=2 WHERE deployment_id=? AND deployment_generation=?",
                (self.DEP, self.GEN2),
            )
        self.db.execute("UPDATE users SET disabled=1,historical_restored=1,updated_ms=2 WHERE deployment_id=?", (self.DEP,))
        bootstrap = "52000000-0000-4000-8000-000000000001"
        self.db.execute("INSERT INTO users VALUES(?,?,?,?,?,?,?,?,?,?,?)", (bootstrap,self.DEP,"restored-admin","x"*32,"admin",0,self.GEN2,0,1,3,3))
        self.db.execute("UPDATE restore_bootstrap_transitions SET state='bootstrap_complete',archived_user_count=?,completed_ms=3 WHERE deployment_id=? AND deployment_generation=?", (total_users,self.DEP,self.GEN2))
        self.db.execute("UPDATE deployments SET recovery_state='normal',updated_ms=3 WHERE id=?", (self.DEP,))
        self.assertEqual(self.db.execute("SELECT count(*) FROM users WHERE deployment_id=?", (self.DEP,)).fetchone()[0], total_users+1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM users WHERE historical_restored=1 AND disabled=1", ()).fetchone()[0], total_users)
        self.assertEqual(self.db.execute("SELECT count(*) FROM audit WHERE actor_user_id IN (SELECT id FROM users WHERE historical_restored=1)").fetchone()[0], total_users)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot_revive"):
            self.db.execute("UPDATE users SET disabled=0 WHERE id=?", (user_ids[0],))

    def test_restore_bootstrap_preserves_one_historical_user_and_creates_new_admin(self):
        self._assert_restore_bootstrap_with_existing_users(1)

    def test_restore_bootstrap_preserves_ten_historical_users_and_creates_new_admin(self):
        self._assert_restore_bootstrap_with_existing_users(10)

    def test_passive_sources_are_two_per_host_and_four_per_deployment(self):
        self.add_target_and_sources()
        runtime = "40000000-0000-4000-8000-000000000003"
        self.db.execute("INSERT INTO sources VALUES(?,?,?,?,?,?,?,?,?)", (runtime,self.DEP,self.HOST,"runtime",self.TARGET,"mac-ollama-1",None,1,1))
        extra = "40000000-0000-4000-8000-000000000004"
        with self.assertRaisesRegex(sqlite3.IntegrityError, "passive_source_host_cap_2"):
            self.db.execute("INSERT INTO sources VALUES(?,?,?,?,?,?,?,?,?)", (extra,self.DEP,self.HOST,"runtime",self.TARGET,"mac-ollama-1",None,1,1))

    def test_request_sample_requires_run_source_target_population_and_completed_fields(self):
        self.add_target_and_sources()
        model="90000000-0000-4000-8000-000000000001"; config="90000000-0000-4000-8000-000000000002"; run="90000000-0000-4000-8000-000000000003"
        self.db.execute("INSERT INTO model_revisions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (model,self.DEP,self.HOST,self.TARGET,"qwen","a"*64,"gguf","qwen","q4",1024,"b"*64,1))
        self.db.execute("INSERT INTO config_snapshots VALUES(?,?,?,?,?,?,?,?,?,?)", (config,self.DEP,self.HOST,self.TARGET,None,"c"*64,1,None,"{}","{}"))
        self.db.execute("INSERT INTO request_runs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (run,self.DEP,self.HOST,self.REQUEST_SOURCE,self.TARGET,"deliberate_probe","direct_capture","d"*64,"{}",1,1,1,0,0,0,"finalized",1,1024,1,2))
        base=["90000000-0000-4000-8000-000000000004",self.DEP,self.HOST,run,self.REQUEST_SOURCE,self.TARGET,model,config,"d"*64,10,"0",None,None,None,None,"100",200,"completed","stop",None,None,None,None,None,None,None,None,None,None,"{}"]
        base[8:8] = ["explicit_observed_request", "ollama-0.34.0-source", 1]
        with self.assertRaises(sqlite3.IntegrityError): self.db.execute("INSERT INTO request_samples VALUES("+','.join('?'*len(base))+")", base)
        base[25]=1.0
        self.db.execute("INSERT INTO request_samples VALUES("+','.join('?'*len(base))+")", base)
        wrong=base.copy(); wrong[0]="90000000-0000-4000-8000-000000000005"; wrong[4]=self.HOST_SOURCE
        with self.assertRaises(sqlite3.IntegrityError): self.db.execute("INSERT INTO request_samples VALUES("+','.join('?'*len(wrong))+")", wrong)

    def test_current_frames_require_exact_current_session_and_replay_can_use_old_session(self):
        self.add_target_and_sources()
        sec="a0000000-0000-4000-8000-000000000001"; boot="a0000000-0000-4000-8000-000000000002"; act="a0000000-0000-4000-8000-000000000003"
        self.db.execute("INSERT INTO collector_sessions VALUES(?,?,?,?,?,?,?,?,?,?)", (self.DEP,self.HOST,1,sec,act,boot,0,1,None,"{}"))
        self.db.execute("UPDATE hosts SET current_session_generation=1,last_boot_id=? WHERE id=?", (boot,self.HOST))
        row=[self.DEP,self.HOST,sec,1,boot,self.HOST_SOURCE,1,"current",None,1,1,0,1,"measured","mac-ollama-1","cbor-zstd-v1",b"x","a"*64,sec,boot,self.HOST_SOURCE,1,"a"*64,None,None,2]
        self.db.execute("INSERT INTO source_frames VALUES("+','.join('?'*len(row))+")", row)
        self.db.execute("UPDATE collector_sessions SET superseded_ms=2 WHERE deployment_id=? AND host_id=? AND session_generation=1", (self.DEP,self.HOST))
        act2="a0000000-0000-4000-8000-000000000004"
        self.db.execute("INSERT INTO collector_sessions VALUES(?,?,?,?,?,?,?,?,?,?)", (self.DEP,self.HOST,2,sec,act2,boot,1,2,None,"{}"))
        self.db.execute("UPDATE hosts SET current_session_generation=2,last_boot_id=? WHERE id=?", (boot,self.HOST))
        wrong=row.copy(); wrong[6]=2; wrong[21]=2
        with self.assertRaises(sqlite3.IntegrityError): self.db.execute("INSERT INTO source_frames VALUES("+','.join('?'*len(wrong))+")", wrong)
        replay=wrong.copy(); replay[7]="replay"
        self.db.execute("INSERT INTO source_frames VALUES("+','.join('?'*len(replay))+")", replay)

    def test_recovery_receipt_detail_expires_but_retained_frame_keeps_grant_tombstone(self):
        self.add_target_and_sources()
        current_security = "a1000000-0000-4000-8000-000000000001"
        current_boot = "a1000000-0000-4000-8000-000000000002"
        activation = "a1000000-0000-4000-8000-000000000003"
        original_security = "a2000000-0000-4000-8000-000000000001"
        original_boot = "a2000000-0000-4000-8000-000000000002"
        grant_id = "a3000000-0000-4000-8000-000000000001"
        grant_hash = "9" * 64
        self.db.execute(
            "INSERT INTO collector_sessions VALUES(?,?,?,?,?,?,?,?,?,?)",
            (self.DEP, self.HOST, 1, current_security, activation, current_boot, 0, 1, None, "{}"),
        )
        self.db.execute(
            "UPDATE hosts SET current_session_generation=1,last_boot_id=? WHERE id=?",
            (current_boot, self.HOST),
        )
        self.db.execute(
            "INSERT INTO recovery_grants VALUES(" + ",".join("?" * 19) + ")",
            (
                grant_id, self.DEP, self.GEN1, self.HOST, original_security, original_boot,
                "a" * 64, "{}", "b" * 64, grant_hash, 1024, 1, 4096,
                self.USER, 100, 3_600_100, 90_000_100, None, None,
            ),
        )
        self.assertEqual(
            self.db.execute(
                "SELECT grant_sha256 FROM recovery_grant_tombstones WHERE deployment_id=? AND host_id=? AND grant_id=?",
                (self.DEP, self.HOST, grant_id),
            ).fetchone()[0],
            grant_hash,
        )
        self.db.execute(
            "INSERT INTO recovery_grant_receipts VALUES(?,?,?,?,?,?,?,?,?)",
            (self.DEP, self.HOST, grant_id, original_boot, self.HOST_SOURCE, 7, "c" * 64, "recovered", 200),
        )
        restored = [
            self.DEP, self.HOST, current_security, 1, current_boot, self.HOST_SOURCE, 7,
            "restored_replay", None, 50, None, None, 1, "measured", "mac-ollama-1",
            "cbor-zstd-v1", b"x", "c" * 64, original_security, original_boot,
            self.HOST_SOURCE, 7, "c" * 64, grant_id, grant_hash, 200,
        ]
        self.db.execute("INSERT INTO source_frames VALUES(" + ",".join("?" * len(restored)) + ")", restored)
        with self.assertRaisesRegex(sqlite3.IntegrityError, "detail_not_compacted"):
            self.db.execute(
                "DELETE FROM recovery_grant_receipts WHERE deployment_id=? AND host_id=? AND grant_id=?",
                (self.DEP, self.HOST, grant_id),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "compaction_invalid"):
            self.db.execute(
                "UPDATE recovery_grant_tombstones SET disposition_summary_json=?,compacted_ms=? WHERE deployment_id=? AND host_id=? AND grant_id=?",
                ('{"recovered":1}', 90_000_099, self.DEP, self.HOST, grant_id),
            )
        self.db.execute(
            "UPDATE recovery_grant_tombstones SET disposition_summary_json=?,compacted_ms=? WHERE deployment_id=? AND host_id=? AND grant_id=?",
            ('{"recovered":1}', 90_000_100, self.DEP, self.HOST, grant_id),
        )
        self.db.execute(
            "DELETE FROM recovery_grant_receipts WHERE deployment_id=? AND host_id=? AND grant_id=?",
            (self.DEP, self.HOST, grant_id),
        )
        self.db.execute(
            "DELETE FROM recovery_grants WHERE deployment_id=? AND host_id=? AND id=?",
            (self.DEP, self.HOST, grant_id),
        )
        self.assertEqual(self.db.execute("SELECT count(*) FROM recovery_grant_tombstones").fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute(
                "DELETE FROM recovery_grant_tombstones WHERE deployment_id=? AND host_id=? AND grant_id=?",
                (self.DEP, self.HOST, grant_id),
            )
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])


if __name__ == "__main__":
    unittest.main()
