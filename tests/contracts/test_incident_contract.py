from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[2]


def load(path: str):
    return json.loads((ROOT / path).read_text())


def registry() -> Registry:
    result = Registry()
    for path in (ROOT / "contracts").rglob("*.schema.json"):
        document = json.loads(path.read_text())
        if "$id" in document:
            result = result.with_resource(document["$id"], Resource.from_contents(document))
    return result


REGISTRY = registry()


def validate(definition: str, instance) -> None:
    schema = load("contracts/api/v1/incident-response.schema.json")
    Draft202012Validator(
        {"$ref": schema["$id"] + f"#/$defs/{definition}"},
        registry=REGISTRY,
        format_checker=FormatChecker(),
    ).validate(instance)


class IncidentContractTests(unittest.TestCase):
    def test_actual_alert_response_keeps_condition_and_frozen_evidence_separate(self):
        # Captured from TestAlertIncidentHTTPKeepsConditionAndFrozenEvidenceSeparate:
        # an explicitly synthetic storage-pressure input, not host pressure.
        incident = load("fixtures/contracts/valid/alert-incident-response.json")
        validate("incidentDetail", incident)
        self.assertIsNone(incident["end_ms"])
        self.assertEqual(incident["alert_state"]["condition"], "FIRING")
        self.assertEqual(incident["capsule"]["schema_revision"], "alert-trigger-capsule-1")
        for mutate in (
            lambda value: value.pop("alert_state"),
            lambda value: value.update(origin="manual"),
            lambda value: value["capsule"]["evidence"].update(source_samples=None),
            lambda value: value["alert_state"].update(condition="acknowledged"),
        ):
            invalid = copy.deepcopy(incident)
            mutate(invalid)
            with self.assertRaises(Exception):
                validate("incidentDetail", invalid)

    def test_closed_manual_capsule_and_bounded_pages(self):
        incident = valid_incident()
        validate("incidentDetail", incident)
        validate("incidentList", {"items": [incident_summary(incident)], "next_cursor": incident["id"]})
        validate("annotationList", {"items": incident["annotations"], "next_cursor": None})

        extra = copy.deepcopy(incident)
        extra["alert_state"] = "FIRING"
        with self.assertRaises(Exception):
            validate("incidentDetail", extra)
        too_many = {"items": [incident_summary(incident)] * 101, "next_cursor": None}
        with self.assertRaises(Exception):
            validate("incidentList", too_many)

    def test_create_and_annotation_inputs_are_plain_bounded_values(self):
        schema = load("contracts/api/v1/incident-request.schema.json")
        validator = lambda name: Draft202012Validator(
            {"$ref": schema["$id"] + f"#/$defs/{name}"}, registry=REGISTRY, format_checker=FormatChecker()
        )
        validator("manualIncidentCreate").validate({
            "title": "Pressure review",
            "scope": {"kind": "host", "id": "10000000-0000-4000-8000-000000000001"},
            "start": "2027-01-15T08:00:00Z",
            "end": "2027-01-15T08:05:00Z",
        })
        validator("manualIncidentUpdate").validate({
            "expected_revision": 3,
            "title": "Reviewed pressure episode",
            "workflow_state": "closed",
        })
        with self.assertRaises(Exception):
            validator("manualIncidentUpdate").validate({"expected_revision": 3})
        with self.assertRaises(Exception):
            validator("manualIncidentUpdate").validate({"expected_revision": 3, "workflow_state": "resolved"})
        validator("annotationCreate").validate({
            "incident_id": "10000000-0000-4000-8000-000000000010",
            "declared_time_ms": 1_800_000_300_000,
            "text": "Operator-declared observation only.",
        })
        with self.assertRaises(Exception):
            validator("annotationEdit").validate({"expected_revision": 1, "text": "hidden\u0001control"})


def incident_summary(value: dict) -> dict:
    return {key: value[key] for key in (
        "schema_version", "id", "revision", "title", "origin", "scope", "start_ms", "end_ms",
        "workflow_state", "owner_user_id", "evidence_status", "capsule_sha256", "created_ms", "updated_ms",
    )}


def valid_incident() -> dict:
    scope = {"kind": "host", "id": "10000000-0000-4000-8000-000000000001"}
    return {
        "schema_version": "1.0",
        "id": "10000000-0000-4000-8000-000000000010",
        "revision": 1,
        "title": "Pressure review",
        "origin": "manual",
        "scope": scope,
        "start_ms": 1_800_000_000_000,
        "end_ms": 1_800_000_300_000,
        "workflow_state": "open",
        "owner_user_id": None,
        "evidence_status": "partial",
        "capsule_sha256": "a" * 64,
        "created_ms": 1_800_000_300_000,
        "updated_ms": 1_800_000_300_000,
        "capsule": {
            "schema_revision": "incident-capsule-1",
            "catalogue_revision": "ec01-ec07-mac-1",
            "generated_ms": 1_800_000_300_000,
            "scope": scope,
            "focus_window": {"start_ms": 1_800_000_000_000, "end_ms": 1_800_000_300_000},
            "baseline_window": {"start_ms": 1_799_999_700_000, "end_ms": 1_800_000_000_000},
            "evidence_state": "partial",
            "cards": [{
                "card_id": "EC07", "priority": 7, "copy_template_id": "ec07_evidence_limits", "scope": scope,
                "title": "Evidence limits", "summary": "Passive timing remains unavailable.", "eligibility": "insufficient",
                "reason_codes": ["passive_request_timing_unavailable"],
                "requested_window": {"start_ms": 1_800_000_000_000, "end_ms": 1_800_000_300_000},
                "effective_window": None, "coverage_ratio": None, "source_ids": [], "definition_revisions": [],
                "config_ids": [], "inputs": [], "gaps": [], "referenced_event_ids": [], "source_links": [],
                "next_check_code": "collect_reviewed_evidence", "next_check_label": "Collect reviewed evidence.",
            }],
            "collapsed_card_count": 0,
        },
        "annotations": [{
            "id": "10000000-0000-4000-8000-000000000020", "revision": 1,
            "incident_id": "10000000-0000-4000-8000-000000000010", "declared_time_ms": 1_800_000_300_000,
            "text": "Operator-declared observation only.", "author_user_id": "10000000-0000-4000-8000-000000000003",
            "edited_ms": None, "created_ms": 1_800_000_300_000, "provenance": "operator_declared",
        }],
        "annotations_next_cursor": None,
        "comparisons": [],
    }


if __name__ == "__main__":
    unittest.main()
