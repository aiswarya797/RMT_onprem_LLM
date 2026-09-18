"""T12 contract oracles for the finite native Mac/Ollama metric boundary.

These tests validate schemas and deterministic contract fixtures. They do not
exercise Ollama, certify hardware, or stand in for T24 captures.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import statistics
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "contracts"
FIXTURES = ROOT / "fixtures" / "contracts"
UINT64_MAX = (1 << 64) - 1
CLIENT_TIMING_TOLERANCE_MS = 0.001


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def schema_registry() -> Registry:
    resources = []
    for path in CONTRACTS.rglob("*.schema.json"):
        schema = load_json(path)
        resources.append((schema["$id"], Resource.from_contents(schema)))
    return Registry().with_resources(resources)


REGISTRY = schema_registry()
FORMAT_CHECKER = FormatChecker()


def validate(schema_path: str, instance: Any) -> None:
    schema = load_json(CONTRACTS / schema_path)
    Draft202012Validator(
        schema, registry=REGISTRY, format_checker=FORMAT_CHECKER
    ).validate(instance)


def schema_errors(schema_path: str, instance: Any) -> list[Any]:
    schema = load_json(CONTRACTS / schema_path)
    validator = Draft202012Validator(
        schema, registry=REGISTRY, format_checker=FORMAT_CHECKER
    )
    return list(validator.iter_errors(instance))


def validate_definition(schema_path: str, definition: str, instance: Any) -> None:
    schema = copy.deepcopy(load_json(CONTRACTS / schema_path))
    schema["$ref"] = f"#/$defs/{definition}"
    Draft202012Validator(
        schema, registry=REGISTRY, format_checker=FORMAT_CHECKER
    ).validate(instance)


def exact_field_summary(values: list[int | float | None]) -> dict[str, Any] | None:
    """Frozen exact oracle: nulls are outside this selected field's population."""
    valid = sorted(value for value in values if value is not None)
    if not valid:
        return None
    count = len(valid)
    return {
        "valid_n": count,
        "minimum": valid[0],
        "median": statistics.median(valid),
        "maximum": valid[-1],
        "p95": valid[math.ceil(0.95 * count) - 1] if count >= 100 else None,
        "algorithm": "exact_median_empirical_nearest_rank_p95",
    }


def assert_summary_semantics(document: dict[str, Any]) -> None:
    """Enforce cross-field summary invariants JSON Schema cannot express."""
    valid_count = document["valid_count"]
    completed_count = document["completed_count"]
    summary = document["summary"]
    if valid_count > completed_count:
        raise ValueError("selected-field count exceeds completed population")
    if (valid_count == 0) != (summary is None):
        raise ValueError("summary presence does not match selected-field count")
    if summary is not None:
        if summary["valid_n"] != valid_count:
            raise ValueError("summary valid_n does not match selected-field count")
        if not summary["minimum"] <= summary["median"] <= summary["maximum"]:
            raise ValueError("summary order is invalid")
        p95 = summary["p95"]
        if valid_count < 100 and p95 is not None:
            raise ValueError("p95 requires at least 100 valid selected-field values")
        if valid_count >= 100 and (
            p95 is None or not summary["minimum"] <= p95 <= summary["maximum"]
        ):
            raise ValueError("eligible p95 is missing or outside the observed range")

    population = document["population_key"]
    provenance = document["provenance_key"]
    if provenance["source_kind"] != population["source_kind"]:
        raise ValueError("summary source kind does not match population")
    if provenance["verification_state"] != population["verification_state"]:
        raise ValueError("summary verification does not match population")
    expected_metric_source = (
        "operator_import"
        if provenance["source_kind"] == "imported_test"
        else "client_monotonic"
        if document["metric_id"].startswith("request.client.")
        else "ollama_terminal"
    )
    if provenance["metric_source"] != expected_metric_source:
        raise ValueError("summary metric source does not match population and metric")


def parse_uint64_decimal(value: Any) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        raise ValueError("not canonical decimal uint64")
    parsed = int(value)
    if parsed > UINT64_MAX:
        raise ValueError("decimal exceeds uint64")
    return parsed


def ns_to_ms(value: int) -> float:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("duration must be a nonnegative integer nanosecond value")
    return value / 1_000_000


def normalize_ollama_case(case: dict[str, Any]) -> dict[str, Any]:
    """Small independent grammar oracle for the synthetic raw canaries."""
    if case.get("client_cancelled"):
        return {"terminal_status": "cancelled", "safe_error_category": "cancelled"}
    objects = case["objects"]
    terminal_indexes = [
        index
        for index, obj in enumerate(objects)
        if obj.get("done") is True or "error" in obj
    ]
    if not terminal_indexes:
        return {"terminal_status": "incomplete", "safe_error_category": "incomplete_stream"}
    if len(terminal_indexes) != 1 or terminal_indexes[0] != len(objects) - 1:
        return {"terminal_status": "failed", "safe_error_category": "malformed_stream"}
    terminal = objects[-1]
    if "error" in terminal:
        return {"terminal_status": "failed", "safe_error_category": "runtime_error"}
    reason = terminal.get("done_reason")
    if reason in {"load", "unload"}:
        return {"terminal_status": "incomplete", "done_reason": reason}
    if reason not in {"stop", "length"}:
        return {"terminal_status": "failed", "safe_error_category": "malformed_stream"}
    metric_fields = {
        "total_duration": "request.runtime.total_duration_ms",
        "load_duration": "request.runtime.load_duration_ms",
        "prompt_eval_duration": "request.runtime.prompt_eval_duration_ms",
        "eval_duration": "request.runtime.eval_duration_ms",
    }
    try:
        metrics: dict[str, int | float | None] = {
            canonical: ns_to_ms(terminal[source]) if source in terminal else None
            for source, canonical in metric_fields.items()
        }
        for source, canonical in (
            ("prompt_eval_count", "request.runtime.prompt_tokens"),
            ("eval_count", "request.runtime.output_tokens"),
        ):
            value = terminal.get(source)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise ValueError("token count must be a nonnegative integer")
            metrics[canonical] = value
    except ValueError:
        return {"terminal_status": "failed", "safe_error_category": "malformed_stream"}
    return {"terminal_status": "completed", "done_reason": reason, "metrics": metrics}


def set_dotted(target: Any, path: str, value: Any) -> None:
    current = target
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value


def set_json_pointer(target: Any, pointer: str, value: Any) -> None:
    if not pointer.startswith("/"):
        raise ValueError("fixture mutation must use a JSON Pointer")
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = target
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = value


def compare_population(
    before: dict[str, Any],
    after: dict[str, Any],
    intervention: dict[str, Any] | None,
) -> str:
    if before == after:
        return "eligible_strict"

    invariant = {
        "target_id",
        "model_digest",
        "profile_id",
        "profile_sha256",
        "concurrency",
        "vantage_id",
        "clock_method",
        "source_kind",
        "verification_state",
    }
    if any(before.get(key) != after.get(key) for key in invariant):
        return "blocked"
    if intervention is None:
        return "blocked"

    top_differences = {
        key
        for key in set(before) | set(after)
        if key != "options" and before.get(key) != after.get(key)
    }
    option_differences = {
        key
        for key in set(before["options"]) | set(after["options"])
        if before["options"].get(key) != after["options"].get(key)
    }
    kind = intervention.get("type")
    if kind == "runtime_version":
        allowed = top_differences <= {"runtime_version", "runtime_build"}
        changed = (
            intervention.get("field") == "runtime_version"
            and "runtime_version" in top_differences
            and not option_differences
        )
    elif kind == "config_revision":
        allowed = top_differences == {"config_revision"}
        changed = intervention.get("field") == "config_revision" and not option_differences
    elif kind == "generation_option":
        field = intervention.get("field")
        allowed = (
            not top_differences
            and field in before["options"]
            and field in after["options"]
            and option_differences == {field}
        )
        changed = len(option_differences) == 1
    else:
        return "blocked"
    if not (allowed and changed):
        return "blocked"
    field = intervention["field"]
    before_value = before["options"][field] if kind == "generation_option" else before[field]
    after_value = after["options"][field] if kind == "generation_option" else after[field]
    canonical_hash = lambda value: hashlib.sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    ).hexdigest()
    if intervention.get("before_value_sha256") != canonical_hash(before_value):
        return "blocked"
    if intervention.get("after_value_sha256") != canonical_hash(after_value):
        return "blocked"
    return "eligible_observed_change_with_confounds"


def assert_sample_semantics(sample: dict[str, Any]) -> None:
    population = sample["population_key"]
    if sample["target_id"] != population["target_id"]:
        raise ValueError("target identity mismatch")
    if sample["source_kind"] != population["source_kind"]:
        raise ValueError("source kind mismatch")
    if sample["verification_state"] != population["verification_state"]:
        raise ValueError("verification mismatch")
    expected_version = {
        "ollama-0.34.0-source": "0.34.0",
        "ollama-0.12.10-source": "0.12.10",
    }.get(sample["runtime_source_pin_id"])
    if expected_version is not None and population["runtime_version"] != expected_version:
        raise ValueError("runtime source pin/version mismatch")

    offsets = sample["offsets_ns"]
    ordered = ["submit", "headers", "first_byte", "first_thinking", "first_content", "end"]
    parsed = {
        name: parse_uint64_decimal(offsets[name])
        for name in ordered
        if offsets[name] is not None
    }
    if parsed["submit"] > parsed["end"]:
        raise ValueError("end precedes submit")
    if "headers" in parsed and "first_byte" in parsed and parsed["headers"] > parsed["first_byte"]:
        raise ValueError("first byte precedes headers")
    if "first_byte" in parsed and parsed["first_byte"] > parsed["end"]:
        raise ValueError("first byte follows request end")
    for name in ("first_thinking", "first_content"):
        if name in parsed:
            if "first_byte" not in parsed or parsed[name] < parsed["first_byte"]:
                raise ValueError(f"{name} precedes first byte")
            if parsed[name] > parsed["end"]:
                raise ValueError(f"{name} follows request end")

    client_bindings = {
        "request.client.first_byte_ms": "first_byte",
        "request.client.first_content_ms": "first_content",
        "request.client.total_ms": "end",
    }
    for metric_id, boundary in client_bindings.items():
        value = sample["metrics"][metric_id]
        if value is None:
            continue
        if boundary not in parsed:
            raise ValueError(f"{metric_id} has no {boundary} boundary")
        expected_ms = parsed[boundary] / 1_000_000
        if abs(value - expected_ms) > CLIENT_TIMING_TOLERANCE_MS:
            raise ValueError(f"{metric_id} contradicts its monotonic boundary")

    for metric_id, value in sample["metrics"].items():
        provenance = sample["field_provenance"][metric_id]
        if (
            metric_id.startswith("request.runtime.")
            and value is not None
            and not sample["terminal_record_observed"]
        ):
            raise ValueError("runtime metric has no observed terminal record")
        if (value is None) != (provenance["missing_reason"] is not None):
            raise ValueError("value/missing provenance mismatch")
        expected_source = (
            "client_monotonic" if metric_id.startswith("request.client.") else "ollama_terminal"
        )
        if sample["source_kind"] == "imported_test":
            expected_source = "operator_import"
        if provenance["source"] != expected_source:
            raise ValueError("metric source provenance mismatch")
        if provenance["verification"] != sample["verification_state"]:
            raise ValueError("field verification mismatch")


def assert_run_semantics(run: dict[str, Any]) -> None:
    samples = run["samples"]
    if len(samples) != run["submitted_count"]:
        raise ValueError("submitted count does not match samples")
    sample_ids = [sample["sample_id"] for sample in samples]
    if len(sample_ids) != len(set(sample_ids)):
        raise ValueError("duplicate sample ID")
    status_counts = {
        status: sum(sample["terminal_status"] == status for sample in samples)
        for status in ("completed", "failed", "cancelled", "incomplete")
    }
    for status, count in status_counts.items():
        if run[f"{status}_count"] != count:
            raise ValueError(f"declared {status} count does not match samples")
    terminal_total = sum(run[key] for key in (
        "completed_count", "failed_count", "cancelled_count", "incomplete_count"
    ))
    if terminal_total != run["submitted_count"]:
        raise ValueError("terminal counts do not match submitted count")
    if run["finalization_state"] == "finalized" and run["submitted_count"] != run["expected_count"]:
        raise ValueError("finalized run count does not match expected")
    if run["source_kind"] != run["population_key"]["source_kind"]:
        raise ValueError("run source kind does not match population")
    if run["verification_state"] != run["population_key"]["verification_state"]:
        raise ValueError("run verification does not match population")
    for sample in samples:
        for key in (
            "run_id", "deployment_id", "host_id", "source_id", "target_id", "model_id", "config_snapshot_id"
        ):
            if sample[key] != run[key]:
                raise ValueError(f"sample {key} does not match run")
        if sample["population_key"] != run["population_key"]:
            raise ValueError("sample population does not match run")
        assert_sample_semantics(sample)


def assert_compatibility_semantics(
    manifest: dict[str, Any], registry: dict[str, Any]
) -> None:
    fields = {item["id"]: item for item in manifest["field_capabilities"]}
    supported = {item["id"] for item in registry["metrics"]}
    unavailable = {item["id"] for item in registry["unavailable_capabilities"]}
    if set(fields) != supported | unavailable:
        raise ValueError("compatibility fields do not exactly cover the registry")
    if any(fields[metric_id]["status"] != "unavailable" for metric_id in unavailable):
        raise ValueError("unsupported registry capability has a numeric support status")
    expected_supported_status = "certified" if manifest["status"] == "certified" else "unverified"
    if any(fields[metric_id]["status"] != expected_supported_status for metric_id in supported):
        raise ValueError("supported field status conflicts with manifest status")
    if manifest["status"] == "unverified" and not manifest["certification_gates"]:
        raise ValueError("unverified manifest has no explicit remaining gate")
    if manifest["qualification_stage"] == "private_trial":
        if "soak_30d" in manifest["certification_gates"]:
            raise ValueError("general-release soak blocks private-trial qualification")
        if manifest["later_stage_gates"] != ["soak_30d"]:
            raise ValueError("private-trial manifest hides its later release soak")
    elif manifest["later_stage_gates"]:
        raise ValueError("general-release manifest has an undeclared later stage")
    for evidence in manifest["evidence"]:
        if evidence["kind"] in {"source_inspection", "artifact_inspection"} and evidence["execution"] == "executed":
            raise ValueError("inspection evidence was mislabeled as execution")


class SchemaAndRegistryTests(unittest.TestCase):
    def test_owned_schemas_are_valid_draft_2020_12(self) -> None:
        for path in (
            CONTRACTS / "metrics" / "v1"
        ).glob("*.schema.json"):
            Draft202012Validator.check_schema(load_json(path))
        for directory in ("probe/v1", "compatibility/v1"):
            for path in (CONTRACTS / directory).glob("*.schema.json"):
                Draft202012Validator.check_schema(load_json(path))

    def test_registry_is_finite_complete_and_unique(self) -> None:
        registry = load_json(CONTRACTS / "metrics/v1/metric-registry.json")
        validate("metrics/v1/metric-registry.schema.json", registry)
        expected_metrics = {
            "host.cpu.busy_ratio", "host.memory.pressure_level",
            "host.memory.compressed_bytes", "host.memory.swap_used_bytes",
            "host.disk.free_bytes", "host.network.received_bytes_total",
            "host.network.sent_bytes_total", "process.cpu.busy_ratio",
            "process.physical_footprint_bytes", "runtime.reachable",
            "runtime.model.loaded", "runtime.model.reported_size_bytes",
            "runtime.model.reported_size_vram_bytes", "request.client.first_byte_ms",
            "request.client.first_content_ms", "request.client.total_ms",
            "request.runtime.total_duration_ms", "request.runtime.load_duration_ms",
            "request.runtime.prompt_eval_duration_ms", "request.runtime.eval_duration_ms",
            "request.runtime.prompt_tokens", "request.runtime.output_tokens",
        }
        expected_unavailable = {
            "gpu.busy_ratio", "gpu.power_watts", "gpu.temperature_celsius",
            "gpu.process_memory_bytes", "runtime.queue_depth", "runtime.active_requests",
            "runtime.cache_hit_ratio", "request.passive.first_byte_ms",
            "request.passive.total_ms",
        }
        metric_ids = [metric["id"] for metric in registry["metrics"]]
        unavailable_ids = [item["id"] for item in registry["unavailable_capabilities"]]
        self.assertEqual(set(metric_ids), expected_metrics)
        self.assertEqual(len(metric_ids), len(set(metric_ids)))
        self.assertEqual(set(unavailable_ids), expected_unavailable)
        self.assertEqual(len(unavailable_ids), len(set(unavailable_ids)))
        self.assertNotIn("kern.memorystatus_level", metric_ids)
        for item in registry["unavailable_capabilities"]:
            self.assertIsNone(item["numeric_value"])
            self.assertEqual(item["reason"], "unsupported_platform_contract")

    def test_registry_semantic_invariants_and_primary_source_pin(self) -> None:
        registry = load_json(CONTRACTS / "metrics/v1/metric-registry.json")
        metrics = {metric["id"]: metric for metric in registry["metrics"]}
        source_pin_ids = {pin["id"] for pin in registry["source_pins"]}
        primary = registry["source_pins"][0]
        self.assertEqual(primary["id"], "ollama-0.34.0-source")
        self.assertEqual(primary["role"], "primary_current_semantic_source")
        self.assertEqual(primary["commit"], "d8ab4b4f0ca24b51d3a46b3bf4f462e58ce66b1f")
        self.assertEqual(primary["execution"], "source_inspection_only")
        for metric in registry["metrics"]:
            self.assertEqual(metric["support"], "unverified")
            self.assertTrue(metric["population"])
            self.assertTrue(metric["source_method"])
            self.assertTrue(metric["certification_gate"])
            self.assertTrue(set(metric["labels"]["required"]).isdisjoint(metric["labels"]["optional"]))
            if metric["source_pin_id"] is not None:
                self.assertIn(metric["source_pin_id"], source_pin_ids)
        self.assertEqual(metrics["process.physical_footprint_bytes"]["source_method"].split()[0], "RUSAGE_INFO_V4")
        for metric_id, metric in metrics.items():
            if metric_id.startswith("request.") and metric_id.endswith("_ms"):
                self.assertEqual(metric["value_contract"]["maximum"], 120000)
        self.assertIn("no additional logical-core division", metrics["host.cpu.busy_ratio"]["source_method"])
        self.assertIn("physical compressor storage", metrics["host.memory.compressed_bytes"]["source_method"])
        for metric_id in ("host.network.received_bytes_total", "host.network.sent_bytes_total"):
            metric = metrics[metric_id]
            self.assertEqual(metric["kind"], "cumulative_counter")
            self.assertEqual(metric["value_contract"]["wire_encoding"], "decimal_string")
            self.assertIn("counter_epoch_id", metric["labels"]["required"])
            self.assertIn("NET_RT_IFLIST2", metric["source_method"])
            self.assertIn("ifm_data64", metric["source_method"])
        pressure_pin = next(pin for pin in registry["source_pins"] if pin["id"].startswith("xnu-"))
        self.assertEqual(pressure_pin["commit"], "a1e26a70f38d1d7daa7b49b258e2f8538ad81650")
        self.assertEqual(pressure_pin["files"], [{
            "path": "bsd/kern/kern_memorystatus_notify.c",
            "sha256": "552451e0067fd7ee3b70242f53bc87b87566cfdca72f2c66d1f97895668f38e8",
        }])


class CounterContractTests(unittest.TestCase):
    def test_large_uint64_counter_preserves_integer_and_wire_shape(self) -> None:
        fixture = load_json(FIXTURES / "metrics/network-counter-cases.json")
        validate("collector/v1/network-observation.schema.json", fixture["valid_network_observation"])
        self.assertEqual(parse_uint64_decimal("9007199254740993"), 9_007_199_254_740_993)
        self.assertEqual(parse_uint64_decimal(str(UINT64_MAX)), UINT64_MAX)
        self.assertEqual(fixture["provenance"]["wire_shape"], "network_observations")
        for value in fixture["valid_decimal_values"]:
            parse_uint64_decimal(value)
        for value in fixture["invalid_values"]:
            with self.assertRaises(ValueError):
                parse_uint64_decimal(value)


class ProbeSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample = load_json(FIXTURES / "probe/request-sample-valid.json")
        self.run = load_json(FIXTURES / "probe/request-run-valid.json")

    def test_profile_sample_and_run_validate(self) -> None:
        validate("probe/v1/profile.schema.json", load_json(FIXTURES / "probe/profile-valid.json"))
        validate("probe/v1/request-sample.schema.json", self.sample)
        validate("probe/v1/request-run.schema.json", self.run)
        assert_sample_semantics(self.sample)
        assert_run_semantics(self.run)

        provenance = load_json(FIXTURES / "probe/fixture-provenance.json")
        self.assertEqual(provenance["source"], "contract_fixture")
        for item in provenance["files"]:
            self.assertTrue(item["synthetic"])
            self.assertFalse(item["runtime_capture"])
            path = ROOT / item["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])

    def test_normalized_schema_is_content_free_and_closed(self) -> None:
        for forbidden in ("prompt", "response", "thinking", "context", "raw_error"):
            bad = copy.deepcopy(self.sample)
            bad[forbidden] = "synthetic canary"
            self.assertTrue(schema_errors("probe/v1/request-sample.schema.json", bad))

    def test_import_cannot_claim_direct_capture(self) -> None:
        bad = copy.deepcopy(self.sample)
        bad["source_kind"] = "imported_test"
        self.assertTrue(schema_errors("probe/v1/request-sample.schema.json", bad))
        bad = copy.deepcopy(self.sample)
        bad["population_key"]["source_kind"] = "imported_test"
        self.assertTrue(schema_errors("probe/v1/request-sample.schema.json", bad))

    def test_null_and_zero_have_distinct_provenance(self) -> None:
        nullable = copy.deepcopy(self.sample)
        metric = "request.runtime.load_duration_ms"
        nullable["metrics"][metric] = None
        nullable["field_provenance"][metric]["missing_reason"] = "field_omitted"
        validate("probe/v1/request-sample.schema.json", nullable)
        assert_sample_semantics(nullable)

        zero = copy.deepcopy(self.sample)
        zero["metrics"][metric] = 0
        zero["field_provenance"][metric]["missing_reason"] = None
        validate("probe/v1/request-sample.schema.json", zero)
        assert_sample_semantics(zero)

        invalid = copy.deepcopy(nullable)
        invalid["field_provenance"][metric]["missing_reason"] = None
        with self.assertRaises(ValueError):
            assert_sample_semantics(invalid)

        client_null = copy.deepcopy(self.sample)
        for boundary in ("first_byte", "first_thinking", "first_content"):
            client_null["offsets_ns"][boundary] = None
        for metric_id in (
            "request.client.first_byte_ms",
            "request.client.first_content_ms",
        ):
            client_null["metrics"][metric_id] = None
            client_null["field_provenance"][metric_id]["missing_reason"] = "not_reached"
        validate("probe/v1/request-sample.schema.json", client_null)
        assert_sample_semantics(client_null)

        client_zero = copy.deepcopy(self.sample)
        client_zero["offsets_ns"]["headers"] = "0"
        client_zero["offsets_ns"]["first_byte"] = "0"
        client_zero["metrics"]["request.client.first_byte_ms"] = 0
        validate("probe/v1/request-sample.schema.json", client_zero)
        assert_sample_semantics(client_zero)

    def test_boundary_order_and_opaque_identity_are_semantic_contracts(self) -> None:
        self.assertEqual(self.sample["target_id"], self.sample["population_key"]["target_id"])
        self.assertRegex(self.sample["model_id"], r"^[0-9a-f-]{36}$")
        self.assertRegex(self.sample["config_snapshot_id"], r"^[0-9a-f-]{36}$")
        bad = copy.deepcopy(self.sample)
        bad["offsets_ns"]["first_content"] = "1500000"
        with self.assertRaises(ValueError):
            assert_sample_semantics(bad)

        independent = copy.deepcopy(self.sample)
        independent["offsets_ns"]["first_content"] = "2500000"
        independent["offsets_ns"]["first_thinking"] = "3000000"
        independent["metrics"]["request.client.first_content_ms"] = 2.5
        assert_sample_semantics(independent)

    def test_source_pin_and_completed_terminal_are_consistent(self) -> None:
        bad = copy.deepcopy(self.sample)
        bad["runtime_source_pin_id"] = "ollama-0.12.10-source"
        with self.assertRaises(ValueError):
            assert_sample_semantics(bad)

        for done_reason in ("load", "unload", "error"):
            bad = copy.deepcopy(self.sample)
            bad["done_reason"] = done_reason
            self.assertTrue(schema_errors("probe/v1/request-sample.schema.json", bad))

        bad = copy.deepcopy(self.sample)
        bad["terminal_record_observed"] = False
        self.assertTrue(schema_errors("probe/v1/request-sample.schema.json", bad))

    def test_run_limits_are_finite(self) -> None:
        for field, value in (("expected_count", 10001), ("decoded_size_bytes", 8388609)):
            bad = copy.deepcopy(self.run)
            bad[field] = value
            self.assertTrue(schema_errors("probe/v1/request-run.schema.json", bad), field)

    def test_completion_counts_are_exact(self) -> None:
        bad = copy.deepcopy(self.run)
        bad["failed_count"] = 1
        with self.assertRaises(ValueError):
            assert_run_semantics(bad)

    def test_normalized_negative_fixtures_reject_contradictions(self) -> None:
        fixture = load_json(FIXTURES / "probe/normalized-negative-cases.json")
        self.assertTrue(fixture["synthetic"])
        self.assertFalse(fixture["provenance"]["runtime_capture"])
        for case in fixture["cases"]:
            document = copy.deepcopy(self.sample if case["scope"] == "sample" else self.run)
            if case.get("operation") == "append_duplicate_first_sample":
                document["samples"].append(copy.deepcopy(document["samples"][0]))
            for path, value in case["mutations"].items():
                set_json_pointer(document, path, value)
            oracle = assert_sample_semantics if case["scope"] == "sample" else assert_run_semantics
            with self.assertRaisesRegex(ValueError, case["expected_error"], msg=case["id"]):
                oracle(document)

    def test_deadline_cancellation_records_truthful_observed_duration(self) -> None:
        sample = copy.deepcopy(self.sample)
        sample["terminal_record_observed"] = False
        sample["http_status"] = None
        sample["terminal_status"] = "cancelled"
        sample["done_reason"] = None
        sample["safe_error_category"] = "deadline"
        sample["offsets_ns"]["end"] = "60010000000"
        sample["metrics"]["request.client.total_ms"] = 60010
        for metric_id in sample["metrics"]:
            if metric_id.startswith("request.runtime."):
                sample["metrics"][metric_id] = None
                sample["field_provenance"][metric_id]["missing_reason"] = "cancelled"
        validate("probe/v1/request-sample.schema.json", sample)
        assert_sample_semantics(sample)
        timing = load_json(CONTRACTS / "probe/v1/request-sample.schema.json")["x-client-timing-contract"]
        self.assertEqual(timing["request_deadline_ms"], 60000)
        self.assertEqual(timing["observed_duration_max_ms"], 120000)


class OllamaGrammarTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = load_json(FIXTURES / "probe/ollama-ndjson-cases.json")

    def test_source_provenance_is_current_primary_and_historical_unverified(self) -> None:
        provenance = self.fixture["provenance"]
        self.assertTrue(self.fixture["synthetic"])
        self.assertFalse(provenance["runtime_capture"])
        self.assertEqual(provenance["primary_source"]["version"], "0.34.0")
        self.assertEqual(provenance["primary_source"]["compatibility"], "source_inspected_runtime_unverified")
        self.assertEqual(provenance["historical_source"]["version"], "0.12.10")
        self.assertEqual(provenance["historical_source"]["compatibility"], "unverified_observed_installation")

    def test_terminal_completion_and_noncompletion_cases(self) -> None:
        for case in self.fixture["cases"]:
            actual = normalize_ollama_case(case)
            expected = case["expected"]
            self.assertEqual(actual["terminal_status"], expected["terminal_status"], case["id"])
            for key in ("done_reason", "safe_error_category"):
                if key in expected:
                    self.assertEqual(actual.get(key), expected[key], case["id"])
        statuses = {case["id"]: normalize_ollama_case(case)["terminal_status"] for case in self.fixture["cases"]}
        self.assertEqual(statuses["http-200-error"], "failed")
        self.assertNotEqual(statuses["load-only"], "completed")
        self.assertNotEqual(statuses["unload-only"], "completed")
        self.assertEqual(statuses["missing-terminal"], "incomplete")
        self.assertEqual(statuses["malformed-negative-duration"], "failed")
        self.assertEqual(statuses["malformed-token-count-string"], "failed")
        self.assertEqual(statuses["post-terminal-data"], "failed")
        self.assertEqual(statuses["duplicate-terminal-records"], "failed")

    def test_durations_convert_from_nanoseconds_exactly_once(self) -> None:
        case = next(case for case in self.fixture["cases"] if case["id"].startswith("034-terminal-stop"))
        actual = normalize_ollama_case(case)
        self.assertEqual(actual["metrics"], case["expected"]["metrics"])
        self.assertEqual(actual["metrics"]["request.runtime.total_duration_ms"], 9.0)

    def test_first_byte_thinking_content_boundaries_are_distinct(self) -> None:
        case = next(case for case in self.fixture["cases"] if case["id"].startswith("034-terminal-stop"))
        boundaries = case["client_boundaries_ns"]
        self.assertLess(boundaries["first_byte"], boundaries["first_thinking"])
        self.assertLess(boundaries["first_thinking"], boundaries["first_content"])
        self.assertLess(boundaries["first_content"], boundaries["end"])
        normalized = normalize_ollama_case(case)
        self.assertFalse(any(key in normalized for key in ("response", "thinking", "context")))
        self.assertIn("prompt_eval_cached_count", case["expected"]["discarded_fields"])


class AggregationAndPopulationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = load_json(FIXTURES / "metrics/aggregation-cases.json")

    def test_exact_median_and_p95_boundaries(self) -> None:
        for case in self.fixture["cases"]:
            self.assertEqual(exact_field_summary(case["selected_values"]), case["expected"], case["id"])

    def test_request_summary_schema_enforces_p95_threshold(self) -> None:
        population = load_json(FIXTURES / "probe/request-run-valid.json")["population_key"]
        for case in self.fixture["cases"]:
            summary = exact_field_summary(case["selected_values"])
            document = {
                "schema_version": "1.0",
                "aggregation_revision": "exact-field-nearest-rank-1",
                "population_key": population,
                "population_status": "complete",
                "run_ids": ["00000000-0000-4000-8000-000000000007"],
                "metric_id": "request.client.total_ms",
                "completed_count": case["completed_count"],
                "valid_count": 0 if summary is None else summary["valid_n"],
                "failed_count": 2,
                "cancelled_count": 1,
                "incomplete_count": 3,
                "provenance_key": {"source_kind": "deliberate_probe", "verification_state": "direct_capture", "metric_source": "client_monotonic"},
                "summary": summary,
                "warnings": ["explicit_observed_requests_only", "other_ollama_traffic_absent"],
            }
            validate("metrics/v1/request-summary.schema.json", document)
            assert_summary_semantics(document)
            if summary is not None:
                self.assertEqual(document["valid_count"], summary["valid_n"])

        invalid = copy.deepcopy(document)
        invalid["valid_count"] = 99
        invalid["summary"] = {"valid_n": 99, "minimum": 1, "median": 50, "maximum": 99, "p95": 95, "algorithm": "exact_median_empirical_nearest_rank_p95"}
        self.assertTrue(schema_errors("metrics/v1/request-summary.schema.json", invalid))

        invalid = copy.deepcopy(document)
        invalid["valid_count"] = 100
        invalid["completed_count"] = 100
        invalid["summary"] = {"valid_n": 100, "minimum": 1, "median": 50.5, "maximum": 100, "p95": None, "algorithm": "exact_median_empirical_nearest_rank_p95"}
        self.assertTrue(schema_errors("metrics/v1/request-summary.schema.json", invalid))

        mismatch = copy.deepcopy(document)
        mismatch["valid_count"] = 100
        mismatch["completed_count"] = 100
        mismatch["summary"] = {"valid_n": 101, "minimum": 1, "median": 50.5, "maximum": 100, "p95": 95, "algorithm": "exact_median_empirical_nearest_rank_p95"}
        validate("metrics/v1/request-summary.schema.json", mismatch)
        with self.assertRaises(ValueError):
            assert_summary_semantics(mismatch)

        imported = copy.deepcopy(document)
        imported["population_key"]["source_kind"] = "imported_test"
        imported["population_key"]["verification_state"] = "operator_imported_unverified"
        imported["provenance_key"] = {
            "source_kind": "imported_test",
            "verification_state": "operator_imported_unverified",
            "metric_source": "operator_import",
        }
        imported["warnings"].append("operator_imported_unverified")
        validate("metrics/v1/request-summary.schema.json", imported)
        assert_summary_semantics(imported)

        false_direct = copy.deepcopy(imported)
        false_direct["provenance_key"]["verification_state"] = "direct_capture"
        self.assertTrue(schema_errors("metrics/v1/request-summary.schema.json", false_direct))

    def test_population_mismatch_and_single_declared_intervention(self) -> None:
        fixture = load_json(FIXTURES / "metrics/population-comparison-cases.json")
        before = fixture["base_population"]
        for case in fixture["cases"]:
            after = copy.deepcopy(before)
            for path, value in case["changes"].items():
                set_dotted(after, path, value)
            if case["declared_intervention"] is not None:
                validate_definition(
                    "api/v1/action-request.schema.json",
                    "declaredIntervention",
                    case["declared_intervention"],
                )
            actual = compare_population(before, after, case["declared_intervention"])
            self.assertEqual(actual, case["expected"], case["id"])


class CompatibilityContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.path = CONTRACTS / "compatibility/v1/macos-15.5-m1-ollama-0.34.0.unverified.json"
        self.manifest = load_json(self.path)

    def test_manifest_validates_and_covers_every_registry_entry(self) -> None:
        validate("compatibility/v1/compatibility-manifest.schema.json", self.manifest)
        registry = load_json(CONTRACTS / "metrics/v1/metric-registry.json")
        assert_compatibility_semantics(self.manifest, registry)
        expected = {item["id"] for item in registry["metrics"] + registry["unavailable_capabilities"]}
        actual = [item["id"] for item in self.manifest["field_capabilities"]]
        self.assertEqual(set(actual), expected)
        self.assertEqual(len(actual), len(set(actual)))
        self.assertEqual(self.manifest["status"], "unverified")
        self.assertEqual(self.manifest["execution_status"], "partially_executed")
        self.assertEqual(self.manifest["qualification_stage"], "private_trial")
        self.assertNotIn("soak_30d", self.manifest["certification_gates"])
        self.assertEqual(self.manifest["later_stage_gates"], ["soak_30d"])
        self.assertFalse(self.manifest["rmt_artifact"]["present"])
        self.assertEqual(self.manifest["runtime"]["execution_status"], "not_executed")
        self.assertEqual(self.manifest["platform_fields"]["gpu_driver"]["status"], "not_applicable")
        self.assertIsNone(self.manifest["model"]["tokenizer"]["sha256"])
        self.assertEqual(self.manifest["model"]["dataset"]["state"], "not_used")

    def test_manifest_evidence_hashes_are_current(self) -> None:
        for evidence in self.manifest["evidence"]:
            path = ROOT / evidence["path"]
            self.assertTrue(path.is_file())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), evidence["sha256"])
        source_path = ROOT / "docs/implementation/u01-source-verification.json"
        self.assertEqual(hashlib.sha256(source_path.read_bytes()).hexdigest(), self.manifest["source_verification_sha256"])

    def test_negative_certification_cases(self) -> None:
        fixture = load_json(FIXTURES / "compatibility/negative-cases.json")
        for case in fixture["cases"]:
            mutated = copy.deepcopy(self.manifest)
            for path, value in case["mutation"].items():
                indexed = re.fullmatch(r"(.+)\[(\d+)]\.(.+)", path)
                if indexed:
                    mutated[indexed.group(1)][int(indexed.group(2))][indexed.group(3)] = value
                else:
                    set_dotted(mutated, path, value)
            errors = schema_errors("compatibility/v1/compatibility-manifest.schema.json", mutated)
            if case["expected"] == "schema_reject":
                self.assertTrue(errors, case["id"])
            else:
                self.assertFalse(errors, case["id"])
                self.assertTrue(
                    mutated["status"] == "certified"
                    or mutated["security_review"]["status"] == "qualified"
                    or any(item["kind"] == "natural_baseline" and item["execution"] == "executed" for item in mutated["evidence"]),
                    case["id"],
                )

    def test_real_baseline_is_negative_observation_not_inference(self) -> None:
        manifest = load_json(ROOT / "fixtures/macos/observations/u01-natural-baseline/manifest.json")
        self.assertFalse(manifest["synthetic"])
        self.assertEqual(manifest["timing"]["sample_count"], 120)
        self.assertTrue(manifest["result"]["observation_complete"])
        self.assertFalse(manifest["result"]["load_authorized"])
        self.assertEqual(manifest["result"]["inference_requests"], 0)
        self.assertFalse(manifest["result"]["rmt_candidate_present"])
        observations = []
        with (ROOT / "fixtures/macos/observations/u01-natural-baseline/observations.jsonl").open(encoding="utf-8") as handle:
            for line in handle:
                item = json.loads(line)
                if "sequence" in item:
                    observations.append(item)
        self.assertEqual(len(observations), 120)
        self.assertEqual({item["pressure"] for item in observations}, {"normal"})
        self.assertEqual({item["swap_used_bytes"] for item in observations}, {2_899_181_568})
        self.assertTrue(all(item["headroom_floor_bytes"] == 0 for item in observations))
        self.assertTrue(all(item["owned_increment_bytes"] is None for item in observations))


if __name__ == "__main__":
    unittest.main()
