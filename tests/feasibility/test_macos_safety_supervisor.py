import importlib.util
import json
import os
import signal
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tests/feasibility/macos_safety_supervisor.py"
SPEC = importlib.util.spec_from_file_location("macos_safety_supervisor", MODULE_PATH)
assert SPEC and SPEC.loader
safety = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = safety
SPEC.loader.exec_module(safety)


class SafetyEvaluatorTests(unittest.TestCase):
    def test_threshold_fixtures(self):
        path = ROOT / "fixtures/macos/safety/threshold-cases.json"
        cases = json.loads(path.read_text(encoding="utf-8"))
        for case in cases:
            with self.subTest(case=case["name"]):
                evaluator = safety.SafetyEvaluator(case["baseline_owned_bytes"])
                decision = evaluator.evaluate(
                    case["sample"],
                    case["elapsed_seconds"],
                    case["heartbeat_delay_seconds"],
                    case["require_owned_tree"],
                )
                self.assertEqual(case["expected_stop_reason"], decision.stop_reason)

    def test_swap_growth_at_128_mib_within_30_seconds_stops(self):
        path = ROOT / "fixtures/macos/safety/swap-growth-cases.json"
        case = json.loads(path.read_text(encoding="utf-8"))
        evaluator = safety.SafetyEvaluator()
        self.assertIsNone(evaluator.evaluate(case["baseline"], 0, 0, False).stop_reason)
        decision = evaluator.evaluate(case["threshold"], 30, 0, False)
        self.assertEqual(case["expected_stop_reason"], decision.stop_reason)

    def test_swap_growth_older_than_window_does_not_trigger(self):
        path = ROOT / "fixtures/macos/safety/swap-growth-cases.json"
        case = json.loads(path.read_text(encoding="utf-8"))
        evaluator = safety.SafetyEvaluator()
        evaluator.evaluate(case["baseline"], 0, 0, False)
        decision = evaluator.evaluate(case["threshold"], 30.001, 0, False)
        self.assertIsNone(decision.stop_reason)

    def test_unknown_owned_rusage_stops(self):
        sample = {
            "pressure": {"ok": True, "raw": 1},
            "headroom": {"ok": True, "consistent": True, "independently_validated": True, "floor_bytes": 3 * safety.GIB},
            "swap": {"ok": True, "used_bytes": 1},
            "desktop": {"ok": True, "round_trip_ms": 1},
            "owned_tree": {
                "ok": True,
                "processes": [{"rusage_ok": False}],
            },
        }
        decision = safety.SafetyEvaluator(0).evaluate(sample, 0, 0, True)
        self.assertEqual("owned_process_identity_lost", decision.stop_reason)

    def test_all_numeric_signals_survive_a_failing_headroom_gate(self):
        sample = {
            "pressure": {"ok": True, "raw": 1},
            "headroom": {
                "ok": True,
                "consistent": True,
                "independently_validated": False,
                "method": safety.HEADROOM_METHOD,
                "floor_bytes": safety.GIB,
                "reclaimable_proxy_bytes": 1536 * safety.MIB,
                "reserve_bytes": 512 * safety.MIB,
                "kernel_percent_bytes": 3 * safety.GIB,
                "userspace_noncompressed_bytes": 3 * safety.GIB,
            },
            "swap": {"ok": True, "used_bytes": 2899181568},
            "desktop": {"ok": True, "round_trip_ms": 88.809},
            "owned_tree": {"requested": False, "ok": True, "processes": []},
        }
        decision = safety.SafetyEvaluator().evaluate(sample, 0, 0.125, False)
        record = safety.sanitized_record(0, 0, sample, decision)

        self.assertEqual("headroom_not_independently_validated", decision.stop_reason)
        self.assertIn("headroom_below_2gib", decision.threshold_reasons)
        self.assertEqual(2899181568, record["swap_used_bytes"])
        self.assertEqual(0, record["swap_growth_bytes"])
        self.assertEqual(88.809, record["desktop_round_trip_ms"])
        self.assertEqual(0.125, record["heartbeat_delay_seconds"])
        self.assertFalse(record["headroom_independently_validated"])

    def test_observation_mode_never_marks_load_authorized(self):
        with tempfile.TemporaryDirectory(dir=ROOT / "tests/feasibility") as directory:
            output = Path(directory) / "observation.jsonl"
            completed, reason, _ = safety.run_loop(
                FakeProbe({1: safety.ProcessIdentity(1, os.getuid(), 1, 1)}),
                output,
                duration_seconds=0,
                observation_only=True,
            )
            self.assertTrue(completed)
            self.assertEqual("observation_complete", reason)
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertFalse(record["load_authorized"])

    def test_one_off_observation_admission_ignores_only_unvalidated_headroom(self):
        sample = {
            "pressure": {"ok": True, "raw": 1},
            "headroom": {"ok": True, "consistent": True, "independently_validated": False, "floor_bytes": 0},
            "swap": {"ok": True, "used_bytes": 1},
            "desktop": {"ok": True, "round_trip_ms": 1},
        }
        evaluator = safety.SafetyEvaluator(allow_unvalidated_headroom=True)
        decision = evaluator.evaluate(sample, 0, 0, False)
        self.assertIsNone(decision.stop_reason)
        self.assertFalse(sample["headroom"]["independently_validated"])
        warning = dict(sample)
        warning["pressure"] = {"ok": True, "raw": 2}
        self.assertEqual("memory_pressure_warning", evaluator.evaluate(warning, 1, 0, False).stop_reason)


class FakeProbe:
    def __init__(self, identities, parents=None):
        self.identities = dict(identities)
        self.parents = parents or {}

    def snapshot(self, owned_pid=None, timeout_seconds=None):
        if owned_pid not in self.identities:
            return {"owned_tree": {"ok": False, "error": 3, "processes": []}}
        selected = {owned_pid}
        changed = True
        while changed:
            changed = False
            for pid, parent in self.parents.items():
                if parent in selected and pid in self.identities and pid not in selected:
                    selected.add(pid)
                    changed = True
        rows = []
        for pid in sorted(selected):
            identity = self.identities[pid]
            rows.append({
                "pid": identity.pid,
                "uid": identity.uid,
                "start_abstime": identity.start_abstime,
                "start_unix_us": identity.start_unix_us,
                "phys_footprint_bytes": 1,
                "rusage_ok": True,
            })
        return {"owned_tree": {"ok": True, "processes": rows}}


class FakeSender:
    def __init__(self, probe, remove_on_signal=True):
        self.probe = probe
        self.remove_on_signal = remove_on_signal
        self.calls = []

    def send(self, pid, sig):
        self.calls.append((pid, sig))
        if self.remove_on_signal:
            self.probe.identities.pop(pid, None)


class UnknownAfterSignalSender(FakeSender):
    def send(self, pid, sig):
        self.calls.append((pid, sig))
        self.probe.broken.add(pid)


class SometimesUnknownProbe(FakeProbe):
    def __init__(self, identities, parents=None):
        super().__init__(identities, parents)
        self.broken = set()

    def snapshot(self, owned_pid=None, timeout_seconds=None):
        if owned_pid in self.broken:
            raise RuntimeError("probe_failed")
        return super().snapshot(owned_pid, timeout_seconds)


class ErrorProbe(FakeProbe):
    def __init__(self, error):
        super().__init__({})
        self.error = error

    def snapshot(self, owned_pid=None, timeout_seconds=None):
        return {"owned_tree": {"ok": False, "error": self.error, "processes": []}}


class CleanupTests(unittest.TestCase):
    def identity(self, pid, start):
        return safety.ProcessIdentity(pid, os.getuid(), start, start + 1000)

    def test_cleanup_signals_separate_request_then_child_then_root_after_recheck(self):
        root = self.identity(700, 10)
        child = self.identity(701, 20)
        request = self.identity(900, 30)
        probe = FakeProbe({700: root, 701: child, 900: request}, {701: 700})
        sender = FakeSender(probe)
        cleaner = safety.OwnedTreeCleaner(probe, sender, sleep=lambda _: None)

        ok, result = cleaner.cleanup(root, {700: root, 701: child}, request)

        self.assertTrue(ok)
        self.assertEqual("graceful_exit", result)
        self.assertEqual(
            [(900, signal.SIGINT), (701, signal.SIGINT), (700, signal.SIGINT)],
            sender.calls,
        )

    def test_root_pid_reuse_skips_root_but_cleans_independently_verified_child(self):
        expected = self.identity(700, 10)
        reused = self.identity(700, 99)
        child = self.identity(701, 20)
        probe = FakeProbe({700: reused, 701: child})
        sender = FakeSender(probe)
        cleaner = safety.OwnedTreeCleaner(probe, sender, sleep=lambda _: None)

        ok, result = cleaner.cleanup(expected, {700: expected, 701: child})

        self.assertTrue(ok)
        self.assertEqual("graceful_exit", result)
        self.assertEqual([(701, signal.SIGINT)], sender.calls)

    def test_request_identity_mismatch_skips_request_but_cleans_root(self):
        root = self.identity(700, 10)
        expected_request = self.identity(900, 30)
        reused_request = self.identity(900, 31)
        probe = FakeProbe({700: root, 900: reused_request})
        sender = FakeSender(probe)
        cleaner = safety.OwnedTreeCleaner(probe, sender, sleep=lambda _: None)

        ok, result = cleaner.cleanup(root, {700: root}, expected_request)

        self.assertTrue(ok)
        self.assertEqual("graceful_exit", result)
        self.assertEqual([(700, signal.SIGINT)], sender.calls)

    def test_probe_error_after_sigint_is_not_reported_as_graceful_exit(self):
        root = self.identity(700, 10)
        probe = SometimesUnknownProbe({700: root})
        sender = UnknownAfterSignalSender(probe)
        cleaner = safety.OwnedTreeCleaner(probe, sender, sleep=lambda _: None)

        ok, result = cleaner.cleanup(root, {700: root})

        self.assertFalse(ok)
        self.assertEqual("cleanup_identity_unknown", result)
        self.assertEqual([(700, signal.SIGINT)], sender.calls)

    def test_unconfirmed_term_is_reported_and_never_escalates_to_sigkill(self):
        root = self.identity(700, 10)
        probe = FakeProbe({700: root})
        sender = FakeSender(probe, remove_on_signal=False)
        cleaner = safety.OwnedTreeCleaner(probe, sender, sleep=lambda _: None)

        ok, result = cleaner.cleanup(root, {700: root})

        self.assertFalse(ok)
        self.assertEqual("termination_unconfirmed", result)
        self.assertEqual([(700, signal.SIGINT), (700, signal.SIGTERM)], sender.calls)
        self.assertNotIn(signal.SIGKILL, [sig for _, sig in sender.calls])

    def test_total_cleanup_deadline_fails_closed_without_signaling(self):
        root = self.identity(700, 10)
        probe = FakeProbe({700: root})
        sender = FakeSender(probe)
        ticks = iter((0.0, 9.0, 9.0, 9.0))
        cleaner = safety.OwnedTreeCleaner(
            probe,
            sender,
            sleep=lambda _: None,
            monotonic=lambda: next(ticks, 9.0),
        )

        ok, result = cleaner.cleanup(root, {700: root})

        self.assertFalse(ok)
        self.assertEqual("cleanup_identity_unknown", result)
        self.assertEqual([], sender.calls)

    def test_non_esrch_root_lookup_error_is_unknown(self):
        root = self.identity(700, 10)
        probe = ErrorProbe(5)
        sender = FakeSender(probe)
        cleaner = safety.OwnedTreeCleaner(probe, sender, sleep=lambda _: None)

        ok, result = cleaner.cleanup(root, {700: root})

        self.assertFalse(ok)
        self.assertEqual("cleanup_identity_unknown", result)
        self.assertEqual([], sender.calls)


class PrivacyTests(unittest.TestCase):
    def test_sanitized_record_does_not_copy_native_process_or_window_details(self):
        sample = {
            "desktop": {"round_trip_ms": 4, "window_title": "private"},
            "headroom": {"method": "secret", "reclaimable_proxy_bytes": "token"},
            "owned_tree": {
                "requested": True,
                "processes": [{"pid": 1, "command": "secret", "environment": "token"}],
            },
        }
        decision = safety.SampleDecision(
            None, (), "normal", 3 * safety.GIB, 1, 0, 4.0, 0.0, 0
        )
        encoded = json.dumps(safety.sanitized_record(0, 0, sample, decision))
        self.assertNotIn("private", encoded)
        self.assertNotIn("secret", encoded)
        self.assertNotIn("token", encoded)
        self.assertNotIn('"pid"', encoded)


if __name__ == "__main__":
    unittest.main()
