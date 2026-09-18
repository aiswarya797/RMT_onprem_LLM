"""U01-only semantic oracles for constraints JSON Schema cannot express."""

from __future__ import annotations

import json
import hashlib
from typing import Any

UINT64_MAX = 18_446_744_073_709_551_615
REQUIRED_BUNDLE_ENTRIES = {
    "README.html", "incident.json", "inventory.json",
    "configuration.json", "series.ndjson", "coverage.json",
}
IMMUTABLE_COMPARISON_KEYS = {
    "target_id", "model_digest", "profile_id", "profile_sha256", "concurrency",
    "vantage_id", "clock_method", "source_kind", "verification_state",
}


class ContractError(ValueError):
    pass


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate_key:{key}")
        result[key] = value
    return result


def load_bounded_json(raw: bytes, maximum_bytes: int) -> Any:
    if len(raw) > maximum_bytes:
        raise ContractError("decoded_json_too_large")
    try:
        return json.loads(
            raw,
            parse_constant=lambda value: (_ for _ in ()).throw(ContractError(f"nonfinite:{value}")),
            object_pairs_hook=_pairs_without_duplicates,
        )
    except UnicodeDecodeError as exc:
        raise ContractError("invalid_utf8") from exc


def uint64_decimal(value: str) -> int:
    if not isinstance(value, str) or not value or (value != "0" and value.startswith("0")) or not value.isascii() or not value.isdigit():
        raise ContractError("invalid_uint64_decimal")
    parsed = int(value)
    if parsed > UINT64_MAX:
        raise ContractError("uint64_overflow")
    return parsed


def validate_batch_semantics(batch: dict[str, Any]) -> None:
    encoded = json.dumps(batch, separators=(",", ":"), ensure_ascii=False).encode()
    if len(encoded) > 4 * 1024 * 1024:
        raise ContractError("batch_decoded_too_large")
    seen: set[tuple[str, int]] = set()
    for frame in batch["frames"]:
        key = (frame["source_id"], frame["sequence"])
        if key in seen:
            raise ContractError("duplicate_frame_identity")
        seen.add(key)
        start = uint64_decimal(frame["monotonic_start_ns"])
        end = uint64_decimal(frame["monotonic_end_ns"])
        if end < start or abs((end - start) / 1_000_000 - frame["duration_ms"]) > 1:
            raise ContractError("frame_duration_mismatch")
        missing_ids = [item["id"] for item in frame["capabilities_missing"]]
        if len(missing_ids) != len(set(missing_ids)):
            raise ContractError("duplicate_missing_capability")
        for metric_id, observation in frame["gauges"].items():
            value = observation["value"]
            if (value is None) != (observation["missing_reason"] is not None):
                raise ContractError("null_missing_reason_mismatch")
            if value is None and observation["quality"] != "unavailable":
                raise ContractError("unavailable_quality_required")
            if metric_id in missing_ids:
                raise ContractError("field_observation_duplicated_in_missing_capabilities")
            if isinstance(value, str) and metric_id.endswith("_bytes"):
                uint64_decimal(value)
        interface_ids: set[str] = set()
        for item in frame["network_observations"]:
            if item["interface_id"] in interface_ids:
                raise ContractError("duplicate_interface_identity")
            interface_ids.add(item["interface_id"])
            local_missing = {row["id"] for row in item["missing"]}
            for field, metric_id in (("received_bytes_total", "host.network.received_bytes_total"), ("sent_bytes_total", "host.network.sent_bytes_total")):
                value = item[field]
                if value is not None:
                    uint64_decimal(value)
                if (value is None) != (metric_id in local_missing):
                    raise ContractError("network_null_missing_reason_mismatch")
        for model in frame["model_observations"]:
            local_missing = {row["id"] for row in model["missing"]}
            for field, metric_id in (("reported_size_bytes", "runtime.model.reported_size_bytes"), ("reported_size_vram_bytes", "runtime.model.reported_size_vram_bytes")):
                value = model[field]
                if value is not None:
                    uint64_decimal(value)
                if (value is None) != (metric_id in local_missing):
                    raise ContractError("model_null_missing_reason_mismatch")
        model_ids = [model["model_id"] for model in frame["model_observations"]]
        if len(model_ids) != len(set(model_ids)):
            raise ContractError("duplicate_model_identity")
        for process in frame["process_observations"]:
            if process["host_id"] != batch["host_id"]:
                raise ContractError("process_cross_host")
            if process["association_quality"] == "none" and process["target_id"] is not None:
                raise ContractError("unassociated_process_has_target")
            local_missing = {row["id"] for row in process["missing"]}
            for field, metric_id in (("cpu_busy_ratio", "process.cpu.busy_ratio"), ("physical_footprint_bytes", "process.physical_footprint_bytes")):
                if (process[field] is None) != (metric_id in local_missing):
                    raise ContractError("process_null_missing_reason_mismatch")
            if process["physical_footprint_bytes"] is not None:
                uint64_decimal(process["physical_footprint_bytes"])
        if frame["process_summary"] is not None:
            summary = frame["process_summary"]
            if summary["retained_process_count"] != len(frame["process_observations"]):
                raise ContractError("process_summary_retained_count_mismatch")
            if (summary["enumeration_truncated"] or summary["permission_denied_count"] > 0) and summary["coverage"] != "partial":
                raise ContractError("process_summary_partial_coverage_required")


def validate_activation_pair(request: dict[str, Any], result: dict[str, Any]) -> None:
    if result["activation_request_id"] != request["activation_request_id"]:
        raise ContractError("activation_request_mismatch")
    if result["security_generation"] != request["security_generation"]:
        raise ContractError("activation_security_generation_mismatch")
    if result["collector_boot_id"] != request["collector_boot_id"]:
        raise ContractError("activation_boot_mismatch")
    if not request["expected_previous_generation"] < result["session_generation"] <= 9_007_199_254_740_991:
        raise ContractError("activation_compare_and_swap_mismatch")


def _fixed_json_sha256(value: dict[str, Any], keys: tuple[str, ...]) -> str:
    """Hash the compact UTF-8 encoding of a fixed, ordered recovery projection."""
    projection = {key: value[key] for key in keys}
    encoded = json.dumps(projection, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def recovery_manifest_sha256(manifest: dict[str, Any]) -> str:
    return _fixed_json_sha256(manifest, (
        "schema_version", "deployment_id", "host_id", "original_security_generation",
        "original_collector_boot_id", "created_ms", "total_bytes", "total_frames",
        "sources", "historical_definitions", "segments", "loss_intervals",
    ))


def recovery_grant_sha256(grant: dict[str, Any]) -> str:
    return _fixed_json_sha256(grant, (
        "schema_version", "grant_id", "deployment_id", "host_id",
        "current_security_generation", "original_security_generation",
        "original_collector_boot_id", "manifest_sha256", "approved_segments",
        "max_bytes", "max_frames", "issued_ms", "expires_ms",
    ))


def recovery_scope_sha256(replay: dict[str, Any]) -> str:
    def normalize(value: Any) -> Any:
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if not isinstance(value, dict):
            return value
        provenance = {"source", "method_revision", "verification"} <= set(value)
        result: dict[str, Any] = {}
        for key, item in value.items():
            if provenance and key in ("observed_at_ms", "source_artifact_sha256") and item is None:
                continue
            result[key] = normalize(item)
        return result

    value = dict(replay)
    value["frames"] = []
    for item in replay["frames"]:
        normalized = dict(item)
        frame = normalize(item["frame"])
        # encoding/json sorts map keys while retaining struct field order.
        # gauges is the sole map in CollectorFrame's fixed wire projection.
        frame["gauges"] = {key: frame["gauges"][key] for key in sorted(frame["gauges"])}
        normalized["frame"] = frame
        value["frames"].append(normalized)
    return _fixed_json_sha256(value, (
        "grant_sha256", "replay_request_id", "admitting_security_generation",
        "admitting_session_generation", "admitting_collector_boot_id", "deployment_id",
        "host_id", "original_security_generation", "original_collector_boot_id", "frames",
    ))


def recovery_segment_sha256(frames: list[dict[str, Any]]) -> str:
    """Hash exact original frame descriptors with unambiguous length framing."""
    digest = hashlib.sha256()
    for item in frames:
        descriptor = {
            "source_id": item["original_source_id"],
            "sequence": item["original_sequence"],
            "observed_ms": item["original_observed_ms"],
            "payload_sha256": item["original_payload_sha256"],
        }
        encoded = json.dumps(descriptor, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        digest.update(len(encoded).to_bytes(4, byteorder="big", signed=False))
        digest.update(encoded)
    return digest.hexdigest()


def validate_recovery_contract(manifest: dict[str, Any], grant: dict[str, Any], replay: dict[str, Any], ack: dict[str, Any] | None = None) -> None:
    owner = (manifest["deployment_id"], manifest["host_id"], manifest["original_security_generation"], manifest["original_collector_boot_id"])
    if owner != (grant["deployment_id"], grant["host_id"], grant["original_security_generation"], grant["original_collector_boot_id"]):
        raise ContractError("recovery_grant_owner_mismatch")
    if grant["manifest_sha256"] != manifest["manifest_sha256"]:
        raise ContractError("recovery_manifest_hash_mismatch")
    if manifest["manifest_sha256"] != recovery_manifest_sha256(manifest):
        raise ContractError("recovery_manifest_canonical_hash_mismatch")
    if grant["grant_sha256"] != recovery_grant_sha256(grant):
        raise ContractError("recovery_grant_canonical_hash_mismatch")
    if grant["expires_ms"] <= grant["issued_ms"] or grant["expires_ms"] > grant["issued_ms"] + 3_600_000:
        raise ContractError("recovery_grant_expiry_invalid")
    if manifest["total_bytes"] != sum(segment["bytes"] for segment in manifest["segments"]):
        raise ContractError("recovery_manifest_byte_sum_mismatch")
    if manifest["total_frames"] != sum(segment["frame_count"] for segment in manifest["segments"]):
        raise ContractError("recovery_manifest_frame_sum_mismatch")
    if grant["max_bytes"] != manifest["total_bytes"] or grant["max_frames"] != manifest["total_frames"]:
        raise ContractError("recovery_grant_totals_mismatch")
    available = {(s["source_id"], s["from_sequence"], s["to_sequence"], s["segment_sha256"]) for s in manifest["segments"]}
    approved = {(s["source_id"], s["from_sequence"], s["to_sequence"], s["segment_sha256"]) for s in grant["approved_segments"]}
    if approved != available:
        raise ContractError("recovery_segment_not_in_manifest")
    last_sequence: dict[str, int] = {}
    for segment in sorted(manifest["segments"], key=lambda item: (item["source_id"], item["from_sequence"])):
        if segment["source_id"] not in manifest["sources"] or segment["to_sequence"] < segment["from_sequence"] or segment["last_ms"] < segment["first_ms"]:
            raise ContractError("recovery_segment_range_invalid")
        if segment["frame_count"] != segment["to_sequence"] - segment["from_sequence"] + 1:
            raise ContractError("recovery_segment_count_mismatch")
        if segment["frame_count"] > 4 or segment["bytes"] > 1_048_576:
            raise ContractError("recovery_segment_transfer_bound")
        if segment["source_id"] in last_sequence and segment["from_sequence"] <= last_sequence[segment["source_id"]]:
            raise ContractError("recovery_segment_overlap")
        last_sequence[segment["source_id"]] = segment["to_sequence"]
    if replay["grant_id"] != grant["grant_id"] or replay["grant_sha256"] != grant["grant_sha256"]:
        raise ContractError("recovery_replay_grant_mismatch")
    if replay["admitting_security_generation"] != grant["current_security_generation"]:
        raise ContractError("recovery_admitting_generation_mismatch")
    if (replay["deployment_id"], replay["host_id"], replay["original_security_generation"], replay["original_collector_boot_id"]) != owner:
        raise ContractError("recovery_replay_owner_mismatch")
    if replay["scope_sha256"] != recovery_scope_sha256(replay):
        raise ContractError("recovery_scope_hash_mismatch")
    if len(replay["frames"]) > grant["max_frames"] or len(replay["frames"]) > 4:
        raise ContractError("recovery_replay_frame_limit")
    allowed = {
        (segment["source_id"], sequence)
        for segment in grant["approved_segments"]
        for sequence in range(segment["from_sequence"], segment["to_sequence"] + 1)
    }
    frame_keys: set[tuple[str, int]] = set()
    for item in replay["frames"]:
        key = (item["original_source_id"], item["original_sequence"])
        frame = item["frame"]
        if key in frame_keys or key not in allowed:
            raise ContractError("recovery_frame_scope_invalid")
        if (frame["source_id"], frame["sequence"], frame["observed_wall_ms"]) != (item["original_source_id"], item["original_sequence"], item["original_observed_ms"]):
            raise ContractError("recovery_frame_original_identity_mismatch")
        frame_keys.add(key)
    # The hub accepts only complete reviewed segments, never an arbitrary
    # subset of approved sequence numbers. This binds the administrator's
    # reviewed descriptor hash to the bytes the collector actually replays.
    segment_by_start = {(item["source_id"], item["from_sequence"]): item for item in manifest["segments"]}
    index = 0
    while index < len(replay["frames"]):
        first = replay["frames"][index]
        segment = segment_by_start.get((first["original_source_id"], first["original_sequence"]))
        if segment is None or index + segment["frame_count"] > len(replay["frames"]):
            raise ContractError("recovery_incomplete_reviewed_segment")
        group = replay["frames"][index:index + segment["frame_count"]]
        for offset, item in enumerate(group):
            if (item["original_source_id"], item["original_sequence"]) != (segment["source_id"], segment["from_sequence"] + offset):
                raise ContractError("recovery_segment_physical_run_mismatch")
        observed = [item["original_observed_ms"] for item in group]
        if min(observed) != segment["first_ms"] or max(observed) != segment["last_ms"] or recovery_segment_sha256(group) != segment["segment_sha256"]:
            raise ContractError("recovery_segment_hash_mismatch")
        index += segment["frame_count"]
    definitions = manifest["historical_definitions"]
    if not definitions["historical_only"] or {source["source_id"] for source in definitions["sources"]} != set(manifest["sources"]):
        raise ContractError("recovery_historical_definitions_incomplete")
    if any(source["active"] for source in definitions["sources"]) or any(model["reported_loaded"] for model in definitions["models"]):
        raise ContractError("recovery_definition_must_be_historical")
    if ack is not None:
        if (ack["grant_id"], ack["grant_sha256"], ack["replay_request_id"], ack["scope_sha256"]) != (replay["grant_id"], replay["grant_sha256"], replay["replay_request_id"], replay["scope_sha256"]):
            raise ContractError("recovery_ack_request_mismatch")
        expected = {
            (replay["original_collector_boot_id"], item["original_source_id"], item["original_sequence"]): item["original_payload_sha256"]
            for item in replay["frames"]
        }
        counts = {"recovered": 0, "duplicate": 0, "rejected": 0}
        for receipt in ack["receipts"]:
            key = (receipt["original_collector_boot_id"], receipt["original_source_id"], receipt["original_sequence"])
            if expected.pop(key, None) != receipt["original_payload_sha256"]:
                raise ContractError("recovery_ack_receipt_mismatch")
            disposition = receipt["disposition"]
            counts[disposition if disposition in ("recovered", "duplicate") else "rejected"] += 1
        if expected or (ack["accepted"], ack["duplicate"], ack["rejected"]) != (counts["recovered"], counts["duplicate"], counts["rejected"]):
            raise ContractError("recovery_ack_count_mismatch")


def validate_bundle_manifest(manifest: dict[str, Any]) -> None:
    paths = [entry["path"] for entry in manifest["entries"]]
    if len(paths) != len(set(paths)):
        raise ContractError("duplicate_bundle_path")
    if not REQUIRED_BUNDLE_ENTRIES.issubset(paths):
        raise ContractError("required_bundle_entry_missing")
    if "manifest.json" in paths:
        raise ContractError("self_referential_manifest_entry")
    if sum(entry["size_bytes"] for entry in manifest["entries"]) != manifest["payload_uncompressed_bytes"]:
        raise ContractError("bundle_size_sum_mismatch")
    if manifest["payload_uncompressed_bytes"] + manifest["manifest_size_bytes"] != manifest["total_archive_decoded_bytes"]:
        raise ContractError("bundle_archive_size_mismatch")
    if manifest["total_archive_decoded_bytes"] > 100 * 1024 * 1024:
        raise ContractError("bundle_too_large")
    for entry in manifest["entries"]:
        is_attachment = entry["path"].startswith("attachments/")
        if is_attachment != (entry["validation"] == "opaque_unverified"):
            raise ContractError("attachment_validation_mismatch")
        if is_attachment != (entry["provenance"] == "operator_approved_unverified_attachment"):
            raise ContractError("attachment_provenance_mismatch")


def validate_static_readme(html: str) -> None:
    lowered = html.lower()
    forbidden = ("<script", "javascript:", "src=\"http", "src='http", "href=\"http", "href='http")
    if any(value in lowered for value in forbidden):
        raise ContractError("active_or_remote_html")


def validate_comparison(before: dict[str, Any], after: dict[str, Any], intervention: dict[str, Any] | None, status: str) -> None:
    if before.get("metric_id") != after.get("metric_id"):
        raise ContractError("comparison_metric_mismatch")
    if before.get("provenance_key") != after.get("provenance_key"):
        raise ContractError("comparison_provenance_mismatch")
    left = before["population_key"]
    right = after["population_key"]
    differences = {key for key in left.keys() | right.keys() if left.get(key) != right.get(key)}
    if differences & IMMUTABLE_COMPARISON_KEYS:
        raise ContractError("comparison_population_mismatch")
    if not differences:
        if intervention is not None:
            raise ContractError("intervention_without_recorded_difference")
        if status == "observed_change_with_confounds":
            raise ContractError("confound_status_without_intervention")
        return
    if intervention is None:
        raise ContractError("uncontrolled_comparison_difference")
    if differences in ({"runtime_version"}, {"runtime_version", "runtime_build"}):
        expected_type = "runtime_version"
        expected_field = "runtime_version"
    elif differences == {"config_revision"}:
        expected_type = "config_revision"
        expected_field = "config_revision"
    elif differences == {"options"}:
        option_differences = {
            key for key in left["options"].keys() | right["options"].keys()
            if left["options"].get(key) != right["options"].get(key)
        }
        if len(option_differences) != 1:
            raise ContractError("multiple_generation_option_differences")
        expected_type = "generation_option"
        expected_field = next(iter(option_differences))
        if expected_field not in left["options"] or expected_field not in right["options"]:
            raise ContractError("uncontrolled_comparison_difference")
    else:
        raise ContractError("uncontrolled_comparison_difference")
    if intervention["type"] != expected_type:
        raise ContractError("intervention_type_mismatch")
    if intervention["field"] != expected_field:
        raise ContractError("intervention_field_mismatch")
    before_hash = hashlib.sha256(json.dumps(
        left[expected_field] if expected_type != "generation_option" else left["options"][expected_field],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    after_hash = hashlib.sha256(json.dumps(
        right[expected_field] if expected_type != "generation_option" else right["options"][expected_field],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode()).hexdigest()
    if intervention["before_value_sha256"] != before_hash or intervention["after_value_sha256"] != after_hash:
        raise ContractError("intervention_value_hash_mismatch")
    if status != "observed_change_with_confounds":
        raise ContractError("intervention_requires_confound_status")


def validate_host_window_comparison(request: dict[str, Any], result: dict[str, Any] | None = None) -> None:
    if request.get("comparison_kind") != "host_window":
        raise ContractError("host_window_kind_required")
    before, after = request["before"], request["after"]
    before_duration = before["end_ms"] - before["start_ms"]
    after_duration = after["end_ms"] - after["start_ms"]
    if before_duration != after_duration or before_duration < 300_000 or before_duration > 86_400_000:
        raise ContractError("host_window_duration_incompatible")
    if not (before["end_ms"] <= after["start_ms"] or after["end_ms"] <= before["start_ms"]):
        raise ContractError("host_windows_overlap")
    minimum = request["minimum_coverage_ratio"]
    if before["coverage_ratio"] < minimum or after["coverage_ratio"] < minimum:
        raise ContractError("host_window_coverage_insufficient")
    if request["clock_method"] != "single_host_monotonic_aligned" or not request["epoch_id"]:
        raise ContractError("host_window_clock_or_epoch_ineligible")
    if result is None:
        return
    for key in ("host_id", "source_id", "metric_id", "definition_revision", "method_revision", "resolution_tier", "epoch_id", "clock_method", "minimum_coverage_ratio"):
        if result.get(key) != request.get(key):
            raise ContractError(f"host_window_result_{key}_mismatch")
    for side in ("before", "after"):
        for key in ("start_ms", "end_ms", "coverage_ratio"):
            if result[side][key] != request[side][key]:
                raise ContractError("host_window_result_range_mismatch")
        summary = result[side]
        if request["metric_id"] == "host.memory.pressure_level":
            if summary["aggregate_kind"] != "state_duration" or summary["state_durations_ms"] is None or summary["rate_per_second"] is not None:
                raise ContractError("pressure_requires_state_duration")
            observed_ms = sum(summary["state_durations_ms"].values())
            duration_ms = summary["end_ms"] - summary["start_ms"]
            if observed_ms > duration_ms:
                raise ContractError("pressure_duration_coverage_mismatch")
            if observed_ms * 10 < duration_ms * 9:
                raise ContractError("pressure_observed_coverage_insufficient")
            # coverage_ratio is a display/serialization fact. Its absolute 0.01
            # tolerance never participates in the exact 90% eligibility gate.
            if abs(observed_ms / duration_ms - summary["coverage_ratio"]) > 0.01:
                raise ContractError("pressure_duration_coverage_mismatch")
        elif request["metric_id"] in ("host.network.received_bytes_total", "host.network.sent_bytes_total"):
            if summary["aggregate_kind"] != "counter_rate" or summary["rate_per_second"] is None or summary["state_durations_ms"] is not None:
                raise ContractError("counter_requires_epoch_scoped_rate")
        elif summary["aggregate_kind"] != "numeric_min_median_max" or summary["state_durations_ms"] is not None or summary["rate_per_second"] is not None:
            raise ContractError("numeric_host_metric_summary_invalid")
    if result["claim_scope"] != "host_observation_windows_no_causal_claim":
        raise ContractError("host_window_claim_scope_mismatch")


def validate_local_target_manifest(action: dict[str, Any], raw_manifest: bytes) -> None:
    manifest = load_bounded_json(raw_manifest, 65_536)
    if manifest != action["reviewed_manifest"]:
        raise ContractError("reviewed_manifest_content_mismatch")
    if hashlib.sha256(raw_manifest).hexdigest() != action["manifest_sha256"]:
        raise ContractError("reviewed_manifest_hash_mismatch")
    endpoint = manifest["endpoint"]
    if endpoint["scheme"] != "http" or endpoint["loopback_host"] not in ("127.0.0.1", "::1"):
        raise ContractError("target_endpoint_not_loopback")


def validate_action_inventory(actions: list[dict[str, Any]], openapi: dict[str, Any]) -> None:
    ids = [action["id"] for action in actions]
    if len(ids) != len(set(ids)):
        raise ContractError("duplicate_action_id")
    for action in actions:
        if action["mutation"] and action["surface"] == "remote_api" and action["generation_precondition"] != "required" and action["generation_precondition"] != "exempt_auth":
            raise ContractError("remote_mutation_missing_generation_rule")
        if action["mutation"] and action["generation_precondition"] == "required" and action["idempotency"] != "required":
            raise ContractError("mutation_missing_idempotency")
        if action["method"] is not None:
            operation = openapi.get("paths", {}).get(action["path"], {}).get(action["method"].lower())
            if operation is None or operation.get("operationId") != action["id"].replace(".", "_").replace("-", "_"):
                raise ContractError(f"openapi_action_missing:{action['id']}")
            names = {item["name"] for item in operation.get("parameters", [])}
            if action["generation_precondition"] == "required" and "If-Deployment-Generation" not in names:
                raise ContractError("openapi_generation_header_missing")
            if action["idempotency"] == "required" and "Idempotency-Key" not in names:
                raise ContractError("openapi_idempotency_header_missing")
            ordered_names = [item["name"] for item in operation.get("parameters", [])]
            if action["generation_precondition"] == "required" and action["idempotency"] == "required":
                if ordered_names.index("If-Deployment-Generation") > ordered_names.index("Idempotency-Key"):
                    raise ContractError("generation_must_precede_idempotency")
