#!/usr/bin/env python3
"""Fail-closed supervisor for the bounded U01 Ollama experiment.

This tool does not start Ollama, issue HTTP requests, or accept commands/URLs.
It samples a native read-only probe and can stop only a pre-identified,
same-user disposable process tree after rechecking every PID/start identity.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Protocol

GIB = 1024**3
MIB = 1024**2
PRESSURE_NAMES = {1: "normal", 2: "warning", 4: "critical"}
MIN_HEADROOM_BYTES = 2 * GIB
SWAP_GROWTH_BYTES = 128 * MIB
SWAP_WINDOW_SECONDS = 30.0
OWNED_INCREMENT_BYTES = 1 * GIB
MAX_HEARTBEAT_SECONDS = 2.0
PREFLIGHT_SECONDS = 120.0
SAMPLE_INTERVAL_SECONDS = 1.0
REQUEST_DEADLINE_SECONDS = 60.0
GRACE_SECONDS = 5.0
CLEANUP_TOTAL_SECONDS = 8.0
HEADROOM_METHOD = "free_plus_purgeable_minus_512mib_uncertified_proxy"
LIVE_SUPERVISION_QUALIFIED = False
ONE_OFF_OBSERVATION_ADMISSION_POLICY = "phase2-observation-v1"


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    start_abstime: int
    start_unix_us: int


@dataclass(frozen=True)
class SampleDecision:
    stop_reason: str | None
    threshold_reasons: tuple[str, ...]
    pressure: str | None
    headroom_bytes: int | None
    swap_used_bytes: int | None
    swap_growth_bytes: int | None
    desktop_round_trip_ms: float | None
    heartbeat_delay_seconds: float
    owned_increment_bytes: int | None


class Probe(Protocol):
    def snapshot(self, owned_pid: int | None = None, timeout_seconds: float | None = None) -> dict: ...


class NativeProbe:
    def __init__(self, executable: Path, timeout_seconds: float = MAX_HEARTBEAT_SECONDS):
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.poisoned = False

    def snapshot(self, owned_pid: int | None = None, timeout_seconds: float | None = None) -> dict:
        command = [str(self.executable)]
        if owned_pid is not None:
            command += ["--owned-pid", str(owned_pid)]
        if self.poisoned:
            raise RuntimeError("native_probe_unreaped")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={"PATH": "/usr/bin:/bin"},
        )
        try:
            timeout = self.timeout_seconds if timeout_seconds is None else min(self.timeout_seconds, timeout_seconds)
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                self.poisoned = True
            raise
        completed_returncode = process.returncode
        if completed_returncode != 0:
            raise RuntimeError(f"native_probe_exit_{completed_returncode}")
        try:
            value = json.loads(stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise RuntimeError("native_probe_invalid_json") from exc
        if not isinstance(value, dict):
            raise RuntimeError("native_probe_invalid_shape")
        return value


class SignalSender(Protocol):
    def send(self, pid: int, sig: int) -> None: ...


class OSSignalSender:
    def send(self, pid: int, sig: int) -> None:
        os.kill(pid, sig)


class SafetyEvaluator:
    def __init__(self, baseline_owned_bytes: int | None = None, allow_unvalidated_headroom: bool = False):
        self.baseline_owned_bytes = baseline_owned_bytes
        self.allow_unvalidated_headroom = allow_unvalidated_headroom
        self.swap_history: deque[tuple[float, int]] = deque()

    def evaluate(
        self,
        sample: dict,
        elapsed_seconds: float,
        heartbeat_delay_seconds: float,
        require_owned_tree: bool,
    ) -> SampleDecision:
        reasons: list[str] = []
        signal_loss = False
        pressure_block = sample.get("pressure")
        headroom_block = sample.get("headroom")
        swap_block = sample.get("swap")
        desktop_block = sample.get("desktop")
        if heartbeat_delay_seconds > MAX_HEARTBEAT_SECONDS:
            reasons.append("heartbeat_delay")

        raw_pressure = pressure_block.get("raw") if isinstance(pressure_block, dict) and pressure_block.get("ok") is True else None
        pressure = PRESSURE_NAMES.get(raw_pressure)
        if pressure is None:
            signal_loss = True
        elif pressure != "normal":
            reasons.append(f"memory_pressure_{pressure}")

        headroom = headroom_block.get("floor_bytes") if isinstance(headroom_block, dict) and headroom_block.get("ok") is True else None
        if not isinstance(headroom, int) or isinstance(headroom, bool) or headroom < 0:
            headroom = None
            if not self.allow_unvalidated_headroom:
                signal_loss = True
        elif not self.allow_unvalidated_headroom:
            if headroom_block.get("independently_validated") is not True:
                reasons.append("headroom_not_independently_validated")
            if headroom_block.get("consistent") is not True:
                reasons.append("headroom_crosscheck_failed")
            if headroom < MIN_HEADROOM_BYTES:
                reasons.append("headroom_below_2gib")

        swap_used = swap_block.get("used_bytes") if isinstance(swap_block, dict) and swap_block.get("ok") is True else None
        swap_growth = None
        if not isinstance(swap_used, int) or isinstance(swap_used, bool) or swap_used < 0:
            swap_used = None
            signal_loss = True
        else:
            self.swap_history.append((elapsed_seconds, swap_used))
            while self.swap_history and elapsed_seconds - self.swap_history[0][0] > SWAP_WINDOW_SECONDS:
                self.swap_history.popleft()
            minimum_recent_swap = min(value for _, value in self.swap_history)
            swap_growth = swap_used - minimum_recent_swap
            if swap_growth >= SWAP_GROWTH_BYTES:
                reasons.append("swap_growth_128mib_30s")

        desktop_ms = desktop_block.get("round_trip_ms") if isinstance(desktop_block, dict) and desktop_block.get("ok") is True else None
        if not isinstance(desktop_ms, (int, float)) or isinstance(desktop_ms, bool) or desktop_ms < 0:
            desktop_ms = None
            signal_loss = True
        elif desktop_ms > MAX_HEARTBEAT_SECONDS * 1000:
            reasons.append("desktop_delay")

        owned_increment = None
        if require_owned_tree:
            owned = sample.get("owned_tree")
            processes = owned.get("processes") if isinstance(owned, dict) and owned.get("ok") is True else None
            if not isinstance(processes, list) or not processes:
                reasons.append("owned_process_identity_lost")
            elif any(
                not isinstance(row, dict)
                or row.get("rusage_ok") is not True
                or not isinstance(row.get("phys_footprint_bytes"), int)
                or not isinstance(row.get("start_abstime"), int)
                or row.get("start_abstime") <= 0
                for row in processes
            ):
                reasons.append("owned_process_identity_lost")
            else:
                owned_bytes = sum(row["phys_footprint_bytes"] for row in processes)
                if self.baseline_owned_bytes is None:
                    reasons.append("owned_baseline_missing")
                else:
                    owned_increment = max(0, owned_bytes - self.baseline_owned_bytes)
                    if owned_increment >= OWNED_INCREMENT_BYTES:
                        reasons.append("owned_increment_1gib")

        if signal_loss:
            # Keep specific observed threshold reasons, but loss of any required
            # independent input is the fail-closed stop priority for this sample.
            reasons.insert(0, "safety_signal_loss")
        unique_reasons = tuple(dict.fromkeys(reasons))
        return SampleDecision(
            unique_reasons[0] if unique_reasons else None,
            unique_reasons,
            pressure,
            headroom,
            swap_used,
            swap_growth,
            float(desktop_ms) if desktop_ms is not None else None,
            heartbeat_delay_seconds,
            owned_increment,
        )


def process_identities(sample: dict) -> dict[int, ProcessIdentity]:
    owned = sample.get("owned_tree")
    processes = owned.get("processes") if isinstance(owned, dict) and owned.get("ok") is True else None
    if not isinstance(processes, list):
        return {}
    result: dict[int, ProcessIdentity] = {}
    for row in processes:
        if not isinstance(row, dict) or row.get("rusage_ok") is not True:
            return {}
        values = (row.get("pid"), row.get("uid"), row.get("start_abstime"), row.get("start_unix_us"))
        if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
            return {}
        identity = ProcessIdentity(*values)
        if identity.pid <= 0 or identity.start_abstime <= 0 or identity.start_unix_us <= 0:
            return {}
        result[identity.pid] = identity
    return result


def identity_matches(expected: ProcessIdentity, actual: ProcessIdentity | None) -> bool:
    return actual == expected


class OwnedTreeCleaner:
    def __init__(
        self,
        probe: Probe,
        sender: SignalSender,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.probe = probe
        self.sender = sender
        self.sleep = sleep
        self.monotonic = monotonic

    def cleanup(
        self,
        root: ProcessIdentity,
        observed: dict[int, ProcessIdentity],
        request: ProcessIdentity | None = None,
    ) -> tuple[bool, str]:
        if root.uid != os.getuid():
            return False, "root_uid_mismatch"
        if request is not None and request.uid != root.uid:
            return False, "request_uid_mismatch"

        deadline = self.monotonic() + CLEANUP_TOTAL_SECONDS
        root_status, current = self._identity_status(root, deadline)

        candidates = dict(observed)
        if root_status == "match":
            candidates.update(current)
        candidates[root.pid] = root
        if request is not None:
            request_status, current_request = self._identity_status(request, deadline)
            if request_status == "match":
                candidates.update(current_request)
            candidates[request.pid] = request

        verified = []
        unknown = root_status == "unknown"
        for identity in candidates.values():
            if identity.uid != root.uid or self.monotonic() >= deadline:
                unknown = True
                continue
            status, _ = self._identity_status(identity, deadline)
            if status == "match":
                verified.append(identity)
            elif status == "unknown":
                unknown = True

        if not verified:
            return (False, "cleanup_identity_unknown") if unknown else (True, "already_exited_or_reused")

        # Cancel the request first, then ask descendants and root to exit.
        ordered = sorted((item for item in verified if item != root), key=lambda item: item.pid)
        if request is not None and request in ordered:
            ordered.remove(request)
            ordered.insert(0, request)
        if root in verified:
            ordered.append(root)
        for identity in ordered:
            send_status = self._send_if_same_identity(identity, signal.SIGINT, deadline)
            unknown |= send_status in ("unknown", "signal_error")

        remaining = max(0.0, deadline - self.monotonic())
        self.sleep(min(GRACE_SECONDS, remaining))
        survivors = []
        for identity in ordered:
            status, _ = self._identity_status(identity, deadline)
            if status == "match":
                survivors.append(identity)
            elif status == "unknown":
                unknown = True
        for identity in survivors:
            send_status = self._send_if_same_identity(identity, signal.SIGTERM, deadline)
            unknown |= send_status in ("unknown", "signal_error")
        if not survivors and not unknown:
            return True, "graceful_exit"
        self.sleep(min(1.0, max(0.0, deadline - self.monotonic())))
        still_running = False
        for identity in survivors:
            status, _ = self._identity_status(identity, deadline)
            still_running |= status == "match"
            unknown |= status == "unknown"
        if still_running:
            return False, "termination_unconfirmed"
        if unknown:
            return False, "cleanup_identity_unknown"
        return True, "terminated"

    def _identity_status(
        self, expected: ProcessIdentity, deadline: float
    ) -> tuple[str, dict[int, ProcessIdentity]]:
        remaining = deadline - self.monotonic()
        if remaining <= 0:
            return "unknown", {}
        try:
            sample = self.probe.snapshot(expected.pid, timeout_seconds=min(0.5, remaining))
        except Exception:
            return "unknown", {}
        owned = sample.get("owned_tree")
        if not isinstance(owned, dict):
            return "unknown", {}
        if owned.get("ok") is not True:
            return ("gone", {}) if owned.get("error") == 3 else ("unknown", {})
        current = process_identities(sample)
        actual = current.get(expected.pid)
        if actual is None:
            return "unknown", current
        return ("match" if identity_matches(expected, actual) else "reused"), current

    def _send_if_same_identity(self, expected: ProcessIdentity, sig: int, deadline: float) -> str:
        status, _ = self._identity_status(expected, deadline)
        if status != "match":
            return status
        try:
            self.sender.send(expected.pid, sig)
        except ProcessLookupError:
            return "gone"
        except PermissionError:
            return "signal_error"
        return "sent"


def append_record(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def safe_nonnegative_number(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return None
    return value


def sanitized_record(sequence: int, elapsed: float, sample: dict, decision: SampleDecision, admission_policy: str | None = None) -> dict:
    pressure = sample.get("pressure") if isinstance(sample.get("pressure"), dict) else {}
    headroom = sample.get("headroom") if isinstance(sample.get("headroom"), dict) else {}
    swap = sample.get("swap") if isinstance(sample.get("swap"), dict) else {}
    desktop = sample.get("desktop") if isinstance(sample.get("desktop"), dict) else {}
    record = {
        "sequence": sequence,
        "elapsed_seconds": round(elapsed, 6),
        "pressure": decision.pressure,
        "pressure_ok": pressure.get("ok") is True,
        "pressure_raw": safe_nonnegative_number(pressure.get("raw")),
        "headroom_method": HEADROOM_METHOD,
        "headroom_ok": headroom.get("ok") is True,
        "headroom_consistent": headroom.get("consistent") is True,
        "headroom_independently_validated": headroom.get("independently_validated") is True,
        "headroom_floor_bytes": decision.headroom_bytes,
        "headroom_reclaimable_proxy_bytes": safe_nonnegative_number(headroom.get("reclaimable_proxy_bytes")),
        "headroom_reserve_bytes": safe_nonnegative_number(headroom.get("reserve_bytes")),
        "headroom_kernel_percent_bytes": safe_nonnegative_number(headroom.get("kernel_percent_bytes")),
        "headroom_userspace_noncompressed_bytes": safe_nonnegative_number(headroom.get("userspace_noncompressed_bytes")),
        "swap_ok": swap.get("ok") is True,
        "swap_used_bytes": decision.swap_used_bytes,
        "swap_growth_bytes": decision.swap_growth_bytes,
        "desktop_ok": desktop.get("ok") is True,
        "desktop_round_trip_ms": decision.desktop_round_trip_ms,
        "heartbeat_delay_seconds": round(decision.heartbeat_delay_seconds, 6),
        "owned_increment_bytes": decision.owned_increment_bytes,
        "stop_reason": decision.stop_reason,
        "threshold_reasons": list(decision.threshold_reasons),
    }
    if admission_policy is not None:
        record["admission_policy"] = admission_policy
    owned = sample.get("owned_tree", {})
    if owned.get("requested") is True:
        record["owned_process_count"] = len(owned.get("processes", []))
    return record


def run_loop(
    probe: Probe,
    output: Path,
    duration_seconds: float,
    owned_root: ProcessIdentity | None = None,
    baseline_owned_bytes: int | None = None,
    deadline_reason: str | None = None,
    observation_only: bool = False,
    allow_unvalidated_headroom: bool = False,
    admission_policy: str | None = None,
) -> tuple[bool, str, dict[int, ProcessIdentity]]:
    evaluator = SafetyEvaluator(baseline_owned_bytes, allow_unvalidated_headroom)
    observed: dict[int, ProcessIdentity] = {}
    started = time.monotonic()
    sequence = 0
    print("Safety supervisor active. Press Ctrl-C to stop; aborted runs never restart automatically.", flush=True)
    while True:
        try:
            scheduled = started + sequence * SAMPLE_INTERVAL_SECONDS
            now = time.monotonic()
            if now < scheduled:
                time.sleep(scheduled - now)
            sample_started = time.monotonic()
            heartbeat_delay = max(0.0, sample_started - scheduled)
            elapsed = sample_started - started
            if elapsed >= duration_seconds:
                if deadline_reason:
                    append_record(output, {"result": "abort", "stop_reason": deadline_reason,
                        "elapsed_seconds": round(elapsed, 6)})
                    return False, deadline_reason, observed
                result = "observation_complete" if observation_only else "pass"
                completion = {"result": result, "elapsed_seconds": round(elapsed, 6),
                    "load_authorized": False if observation_only else True}
                if admission_policy is not None:
                    completion["admission_policy"] = admission_policy
                append_record(output, completion)
                return True, result, observed
            sample = probe.snapshot(owned_root.pid if owned_root else None)
        except KeyboardInterrupt:
            append_record(output, {"sequence": sequence, "result": "abort", "stop_reason": "ctrl_c"})
            return False, "ctrl_c", observed
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            reason = "heartbeat_delay" if isinstance(exc, subprocess.TimeoutExpired) else "safety_signal_loss"
            append_record(output, {"sequence": sequence, "result": "abort", "stop_reason": reason})
            return False, reason, observed
        decision = evaluator.evaluate(sample, elapsed, heartbeat_delay, owned_root is not None)
        if owned_root is not None:
            identities = process_identities(sample)
            if not identity_matches(owned_root, identities.get(owned_root.pid)):
                reasons = ("owned_process_identity_lost",) + tuple(
                    reason for reason in decision.threshold_reasons
                    if reason != "owned_process_identity_lost"
                )
                decision = SampleDecision(
                    reasons[0], reasons, decision.pressure, decision.headroom_bytes,
                    decision.swap_used_bytes, decision.swap_growth_bytes,
                    decision.desktop_round_trip_ms, decision.heartbeat_delay_seconds,
                    decision.owned_increment_bytes,
                )
            else:
                observed.update(identities)
        append_record(output, sanitized_record(sequence, elapsed, sample, decision, admission_policy))
        if decision.stop_reason and not observation_only:
            append_record(output, {"result": "abort", "stop_reason": decision.stop_reason})
            return False, decision.stop_reason, observed
        sequence += 1


def parse_identity(value: str) -> ProcessIdentity:
    try:
        raw = json.loads(value)
        return ProcessIdentity(
            pid=int(raw["pid"]),
            uid=int(raw["uid"]),
            start_abstime=int(raw["start_abstime"]),
            start_unix_us=int(raw["start_unix_us"]),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise argparse.ArgumentTypeError("identity must be a JSON object with pid, uid, start_abstime, start_unix_us") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)
    preflight = subparsers.add_parser("preflight", help="run the fixed 120 second no-load gate")
    preflight.add_argument("--probe", type=Path, required=True)
    preflight.add_argument("--output", type=Path, required=True)
    preflight.add_argument("--admission-policy", choices=[ONE_OFF_OBSERVATION_ADMISSION_POLICY])

    observe = subparsers.add_parser("observe", help="record 120 seconds without ever authorizing load")
    observe.add_argument("--probe", type=Path, required=True)
    observe.add_argument("--output", type=Path, required=True)

    supervise = subparsers.add_parser("supervise", help="observe an already-started disposable owned process")
    supervise.add_argument("--probe", type=Path, required=True)
    supervise.add_argument("--output", type=Path, required=True)
    supervise.add_argument("--owned-identity", type=parse_identity, required=True)
    supervise.add_argument("--baseline-owned-bytes", type=int, required=True)
    supervise.add_argument("--request-identity", type=parse_identity)
    supervise.add_argument("--admission-policy", choices=[ONE_OFF_OBSERVATION_ADMISSION_POLICY])
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.probe.resolve() == Path(__file__).resolve() or not args.probe.is_file():
        print("probe executable is missing", file=sys.stderr)
        return 64
    if args.output.exists():
        print("output already exists; refusing to mix experiment runs", file=sys.stderr)
        return 64
    probe = NativeProbe(args.probe)
    try:
        if args.mode == "preflight":
            policy = args.admission_policy
            passed, reason, _ = run_loop(
                probe, args.output, PREFLIGHT_SECONDS,
                allow_unvalidated_headroom=policy == ONE_OFF_OBSERVATION_ADMISSION_POLICY,
                admission_policy=policy,
            )
            print(f"preflight: {'PASS' if passed else 'ABORT'} ({reason}); policy={policy or 'default'}", flush=True)
            return 0 if passed else 2
        if args.mode == "observe":
            completed, reason, _ = run_loop(
                probe, args.output, PREFLIGHT_SECONDS, observation_only=True
            )
            print(f"observation: {'COMPLETE' if completed else 'ABORT'} ({reason}); load_authorized=false", flush=True)
            return 0 if completed else 2

        if args.baseline_owned_bytes < 0 or args.owned_identity.uid != os.getuid():
            print("owned identity/baseline is invalid for this user", file=sys.stderr)
            return 64
        if not LIVE_SUPERVISION_QUALIFIED and args.admission_policy != ONE_OFF_OBSERVATION_ADMISSION_POLICY:
            print("live supervision is review-only and not qualified for a model load", file=sys.stderr)
            return 69
        initial = process_identities(probe.snapshot(args.owned_identity.pid))
        if not identity_matches(args.owned_identity, initial.get(args.owned_identity.pid)):
            print("owned root identity does not match current process", file=sys.stderr)
            return 64
        passed, reason, observed = run_loop(
            probe,
            args.output,
            REQUEST_DEADLINE_SECONDS,
            args.owned_identity,
            args.baseline_owned_bytes,
            "request_deadline_60s",
            allow_unvalidated_headroom=args.admission_policy == ONE_OFF_OBSERVATION_ADMISSION_POLICY,
            admission_policy=args.admission_policy,
        )
        cleaner = OwnedTreeCleaner(probe, OSSignalSender())
        cleanup_ok, cleanup_result = cleaner.cleanup(args.owned_identity, observed, args.request_identity)
        append_record(args.output, {"cleanup_ok": cleanup_ok, "cleanup_result": cleanup_result})
        print(f"supervision: ABORT ({reason}); cleanup={cleanup_result}", flush=True)
        return 2 if cleanup_ok else 3
    except KeyboardInterrupt:
        print("Ctrl-C received; no automatic restart.", file=sys.stderr, flush=True)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
