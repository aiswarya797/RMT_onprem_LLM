#!/usr/bin/env python3
"""Finite real CLI/HTTP smoke. Never installs or invokes launchd.

Ollama is contacted only with --ollama-port, through passive read-only routes.
No mode imports, loads, unloads or runs inference on a model.

Run with the pinned contract-test Python environment after building the two
binaries, with the heavy-test slot free. All test
state is retained under this project's .work directory. This is not T01/T23
signed installation, browser, inference, or resource-overhead qualification.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sqlite3
import subprocess
import time
import uuid
from urllib.parse import urlencode, urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource


PROJECT = Path(__file__).resolve().parents[2]


def schema_validator():
    registry = Registry()
    for path in (PROJECT / "contracts").rglob("*.schema.json"):
        document = json.loads(path.read_text())
        registry = registry.with_resource(document["$id"], Resource.from_contents(document))

    def validate(reference, value):
        Draft202012Validator({"$ref": reference}, registry=registry,
                             format_checker=FormatChecker()).validate(value)

    return validate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--collector-binary", type=Path,
                        help="also exercise passive native collection and history across hub restart")
    parser.add_argument("--ollama-port", type=int,
                        help="observe an already-running local Ollama using bounded read-only API calls")
    parser.add_argument("--remote-collector", action="store_true",
                        help="also enroll a second isolated installation over loopback TLS; one physical Mac only")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not binary.is_relative_to(PROJECT):
        parser.error("binary must be inside this project")
    collector_binary = args.collector_binary.resolve(strict=True) if args.collector_binary else None
    if collector_binary and not collector_binary.is_relative_to(PROJECT):
        parser.error("collector binary must be inside this project")
    if args.ollama_port and (not collector_binary or not 1 <= args.ollama_port <= 65535):
        parser.error("--ollama-port requires a collector and a valid local port")
    if args.remote_collector and not collector_binary:
        parser.error("--remote-collector requires --collector-binary")
    run_id = uuid.uuid4().hex[:8]
    work = PROJECT / ".work" / "u02-smoke" / run_id
    home = work / "Install home ? #"
    runtime = PROJECT / ".work" / ("s-" + run_id)
    home.mkdir(parents=True, mode=0o700)
    runtime.mkdir(mode=0o700)
    if len(os.fsencode(runtime / "hub.sock")) >= 104:
        parser.error("project path leaves insufficient space for a Darwin socket")
    guard = work / "guard"
    guard.mkdir()
    launch_log = work / "unexpected-launchctl.txt"
    launchctl = guard / "launchctl"
    launchctl.write_text('#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$RMT_TEST_LAUNCHCTL_LOG"\nexit 64\n')
    launchctl.chmod(0o700)
    env = dict(os.environ, PATH=str(guard) + os.pathsep + os.environ.get("PATH", ""),
               RMT_TEST_LAUNCHCTL_LOG=str(launch_log))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    collector_port = None
    if args.remote_collector:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            collector_port = reservation.getsockname()[1]
    command = [str(binary), "--installation-root", str(home),
               "--runtime-dir", str(runtime), "--listen", f"127.0.0.1:{port}"]
    passed = []
    cli_transcripts = []
    secret_values = []
    child = None
    collector_child = None
    remote_child = None
    log = (work / "hub.log").open("wb")
    collector_log = (work / "collector.log").open("wb") if collector_binary else None
    started = time.monotonic()
    with binary.open("rb") as binary_file:
        binary_hash = hashlib.file_digest(binary_file, "sha256").hexdigest()
    report = {"test": "passive_native_cli_http" if collector_binary else "u02_real_cli_http", "run_id": run_id,
              "binary_sha256": binary_hash,
              "state_directory": str(work), "runtime_directory": str(runtime),
              "launchd": "guarded against invocation; not qualified", "inference": "not attempted"}
    validate = schema_validator()
    openapi = json.loads((PROJECT / "contracts/api/v1/openapi.json").read_text())
    contract_root = "https://llm-monitor.local/contracts/api/v1/"

    def check(condition, description):
        if not condition:
            raise AssertionError(description)
        passed.append(description)

    def cli_raw(*tail, expected=0, saved_listen=False):
        base = command[:-2] if saved_listen else command
        result = subprocess.run(base + list(tail), env=env, capture_output=True, timeout=10)
        cli_transcripts.append(result.stdout + result.stderr)
        check(result.returncode == expected, "CLI exit: " + " ".join(tail[:2]))
        value = json.loads(result.stdout)
        return value

    def cli(*tail, expected=0, saved_listen=False):
        value = cli_raw(*tail, expected=expected, saved_listen=saved_listen)
        definitions = {"version": "versionIdentity", "install": "installCheck",
                       "setup": "setupLocal", "status": "foundationStatus",
                       "admin": "bootstrapRenew", "uninstall": "uninstallResult", "targets": "localResult"}
        reference = ("error.schema.json" if expected else
                     "local-response.schema.json#/$defs/" + definitions[tail[0]])
        validate(contract_root + reference, value)
        return value

    def request(path, method="GET", body=None, cookie=None, headers=None):
        fields = {"Origin": origin, **(headers or {})}
        if cookie:
            fields["Cookie"] = cookie
        if body is not None:
            fields["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None, fields)
            response = connection.getresponse()
            data = response.read(1024 * 1024 + 1)
            check(len(data) <= 1024 * 1024, "HTTP response is bounded")
            if path.startswith("/api/"):
                if response.status >= 400:
                    validate(contract_root + "error.schema.json", json.loads(data))
                elif response.status != 204:
                    operation = openapi["paths"][urlsplit(path).path][method.lower()]
                    reference = operation["responses"][str(response.status)]["content"]["application/json"]["schema"]["$ref"]
                    validate(contract_root + reference, json.loads(data))
            return response.status, dict(response.getheaders()), data
        finally:
            connection.close()

    def start_hub():
        nonlocal child
        child = subprocess.Popen(command[:-2] + ["hub", "serve"], env=env, stdout=log, stderr=log,
                                 start_new_session=not bool(collector_binary))
        for _ in range(50):
            if child.poll() is not None:
                raise AssertionError("hub exited during startup; inspect retained hub.log")
            try:
                status, _, _ = request("/api/v1/auth/bootstrap")
                if status == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise AssertionError("hub startup exceeded five seconds")

    def stop_hub():
        nonlocal child
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=3)
        child = None

    def passive_overview(predicate, description, timeout=12):
        end = time.monotonic() + timeout
        last = None
        while time.monotonic() < end:
            if collector_child.poll() is not None:
                raise AssertionError("collector exited; inspect retained collector.log")
            status, _, raw = request("/api/v1/overview", cookie=cookie)
            last = json.loads(raw)
            if status == 200 and predicate(last):
                passed.append(description)
                return last
            time.sleep(.25)
        (work / "last-overview.json").write_text(json.dumps(last, indent=2) + "\n")
        raise AssertionError(description + ": deadline exceeded")

    def deadline(_signal, _frame):
        raise TimeoutError("ninety-second integration deadline")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(90)
    try:
        version = cli("version", "--json")
        check(version["registry_revision"] == "mac-ollama-1", "binary registry identity")
        support = home / "Library" / "Application Support" / "LLM Monitor"
        check(cli("install", "check", "--role", "local", "--json")["compatible"],
              "real host passes proposed installation compatibility checks")
        cli("status", "--json", expected=5)
        check(not support.exists(), "fresh status has no install side effects")
        listener_options = ["--collector-listen", f"127.0.0.1:{collector_port}"] if collector_port else []
        first = cli("setup", "local", "--no-start", "--json", *listener_options)
        second = cli("setup", "local", "--no-start", "--json", saved_listen=True)
        check(first["created"] and not second["created"] and
              first["deployment_id"] == second["deployment_id"], "setup is idempotent")
        check(first["hub_state"] == first["collector_state"] == "not_started", "setup does not start services")
        preview = cli("uninstall", "--keep-data", "--preview", "--json")
        check(preview["preview"] and preview["removed_paths"] == [], "uninstall preview is non-mutating")
        token_path = Path(first["bootstrap_token_path"])
        check(token_path.is_relative_to(home) and token_path.stat().st_mode & 0o777 == 0o600,
              "bootstrap file stays private and inside selected root")
        token = token_path.read_text().strip()
        secret_values.append(token)
        check(token not in json.dumps(first), "CLI reports token path without token value")
        start_hub()
        passed.append("repeat setup and hub start preserve the saved nondefault port")
        status, headers, page = request("/")
        check(status == 200 and b'<div id="root">' in page and "Content-Security-Policy" in headers,
              "real embedded UI and CSP served offline")
        check(request("/api/v1/status")[0] == 401, "status requires authentication")
        check(request("/api/v1/auth/bootstrap", headers={"Host": "outside.invalid"})[0] == 400,
              "foreign Host rejected")
        check(request("/api/v1/auth/bootstrap", headers={"Origin": "https://outside.invalid"})[0] == 403,
              "foreign Origin rejected")
        credentials = {"username": "smoke-admin", "password": secrets.token_urlsafe(24)}
        secret_values.append(credentials["password"])
        payload = {"bootstrap_token": token, **credentials}
        status, headers, raw = request("/api/v1/auth/bootstrap", "POST", payload)
        check(status == 201, "real first administrator bootstrap")
        session = json.loads(raw)
        cookie_header = headers["Set-Cookie"]
        cookie = cookie_header.split(";", 1)[0]
        check("HttpOnly" in cookie_header and "SameSite=Strict" in cookie_header, "session cookie protections")
        check(headers["X-Deployment-Generation"] == first["deployment_generation"], "generation header matches setup")
        check(request("/api/v1/auth/bootstrap", "POST", payload)[0] in (401, 409), "bootstrap cannot be reused")
        status, _, raw = request("/api/v1/status", cookie=cookie)
        data = json.loads(raw)
        check(status == 200 and data["target_count"] == 0 and not data["collection_started"]
              and not data["inference_started"], "authenticated real no-target state")
        local = cli("status", "--json")
        check(local["hub_state"] == "running" and local["collector_state"] == "stopped", "local socket reports actual services")

        api_token_headers = {"X-CSRF-Token": session["csrf_token"],
                             "If-Deployment-Generation": first["deployment_generation"],
                             "Idempotency-Key": str(uuid.uuid4())}
        api_token_body = {"display_name": "CLI integration administrator", "expires_in_seconds": 3600}
        status, _, raw = request("/api/v1/auth/tokens", "POST", api_token_body, cookie, api_token_headers)
        check(status == 201, "browser session creates the initial bounded API bearer")
        initial_token = json.loads(raw)
        retry_status, _, retry_raw = request("/api/v1/auth/tokens", "POST", api_token_body, cookie, api_token_headers)
        check(retry_status == 201 and json.loads(retry_raw) == initial_token,
              "API bearer exact retry returns the same one-time result")
        admin_bearer = initial_token["token"]
        secret_values.append(admin_bearer)
        admin_token_file = work / "admin-api.token"
        descriptor = os.open(admin_token_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as private_file:
            private_file.write(admin_bearer + "\n")
        check(admin_token_file.stat().st_mode & 0o777 == 0o600, "initial API bearer file is private")

        child_token_file = work / "automation-api.token"
        child_created = cli_raw(
            "auth", "token", "create", "--token-file", str(admin_token_file),
            "--output-token-file", str(child_token_file), "--name", "Integration child",
            "--expires", "1h", "--deployment-generation", first["deployment_generation"],
            "--idempotency-key", str(uuid.uuid4()), "--json")
        child_bearer = child_token_file.read_text().strip()
        secret_values.append(child_bearer)
        validate(contract_root + "response.schema.json#/$defs/token", child_created["record"])
        check(set(child_created) == {"schema_version", "status", "token_file", "record"} and
              child_created["status"] == "created" and child_created["token_file"] == str(child_token_file)
              and child_created["record"]["scope"] == "admin",
              "auth token create uses the authenticated CLI and preserves role scope")
        check(child_token_file.stat().st_mode & 0o777 == 0o600 and child_bearer not in json.dumps(child_created),
              "created API bearer is private and omitted from CLI output")
        token_list = cli_raw("auth", "token", "list", "--token-file", str(admin_token_file), "--json")
        validate(contract_root + "response.schema.json#/$defs/tokenList", token_list)
        listed_ids = {item["id"] for item in token_list["items"]}
        check({initial_token["record"]["id"], child_created["record"]["id"]} <= listed_ids,
              "auth token list reports both retained token identities without bearers")
        if collector_binary:
            if args.ollama_port:
                manifest = {
                    "schema_version": "1.0", "manifest_id": str(uuid.uuid4()), "manifest_revision": 1,
                    "adapter_id": "ollama", "endpoint": {"scheme": "http", "loopback_host": "127.0.0.1", "port": args.ollama_port, "base_path": ""},
                    "identity_revision": hashlib.sha256(f"local-ollama:{args.ollama_port}".encode()).hexdigest(),
                    "display_name": "Existing local Ollama"}
                manifest_path = work / "read-only-target.json"
                manifest_path.write_text(json.dumps(manifest) + "\n")
                manifest_path.chmod(0o600)
                manifest_hash = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
                cli("targets", "add", "--manifest", str(manifest_path), "--manifest-sha256", manifest_hash,
                    "--deployment-generation", first["deployment_generation"], "--confirm-deployment", first["deployment_id"],
                    "--idempotency-key", str(uuid.uuid4()), "--json")
                report["ollama"] = "existing literal-loopback target; read-only monitoring; no inference or model mutation"
            collector_child = subprocess.Popen(
                [str(collector_binary), "--installation-root", str(home),
                 "--runtime-dir", str(runtime), "serve"], env=env,
                stdout=collector_log, stderr=collector_log)
            first_live = passive_overview(
                lambda item: item["host_count"] == 1 and item["history_available"] and
                any(metric["value"] is not None and metric["provenance"]["verification"] != "synthetic_fixture"
                    for host in item["hosts"] for metric in host["metrics"]),
                "native host observations reach authenticated overview and durable history")
            (work / "first-live-overview.json").write_text(json.dumps(first_live, indent=2) + "\n")
            check(first_live["target_count"] == (1 if args.ollama_port else 0) and first_live["observed_request_population"] == "absent",
                  "passive collection preserves configured target count and absent inference population")
            if args.ollama_port:
                target_live = passive_overview(
                    lambda item: len(item["targets"]) == 1 and item["targets"][0]["reachable"]["value"] is True
                    and item["targets"][0]["models_observed_ms"] is not None,
                    "existing Ollama reachability and loaded-model inventory reach the authenticated API")
                (work / "ollama-overview.json").write_text(json.dumps(target_live, indent=2) + "\n")
            local = cli("status", "--json")
            check(local["collection_started"] and not local["inference_started"],
                  "CLI reports actual passive collection without inference")
        check(request("/api/v1/auth/session", "DELETE", cookie=cookie)[0] == 403, "logout requires CSRF")
        stop_hub()
        outage_start_ms = int(time.time() * 1000)
        check(cli("status", "--json")["hub_state"] == "stopped", "stopped hub is not reported running")
        if collector_binary:
            time.sleep(18)
        outage_end_ms = int(time.time() * 1000)
        start_hub()
        check(request("/api/v1/auth/session", cookie=cookie)[0] == 200, "session survives hub restart")
        if collector_binary:
            restart_ms = int(time.time() * 1000)
            recovered = passive_overview(
                lambda item: item["history_available"] and
                any((metric["observed_ms"] or 0) >= restart_ms
                    for host in item["hosts"] for metric in host["metrics"]),
                "collector resumes persisted live observations after hub outage")
            (work / "recovered-overview.json").write_text(json.dumps(recovered, indent=2) + "\n")
            settled = passive_overview(
                lambda item: any(host["source_state"] in ("fresh", "partial") and
                                 sum(process["category"] == "rmt" for process in host["process_observations"]) == 2
                                 for host in item["hosts"]),
                "heartbeat recovers and both verified RMT process identities follow hub restart", timeout=20)
            (work / "settled-overview.json").write_text(json.dumps(settled, indent=2) + "\n")
            database_uri = (support / "hub" / "monitor.sqlite3").as_uri() + "?mode=ro"
            replay_deadline = time.monotonic() + 12
            replayed = 0
            while time.monotonic() < replay_deadline:
                with sqlite3.connect(database_uri, uri=True, timeout=1) as database:
                    replayed = database.execute(
                        "SELECT count(*) FROM source_frames WHERE delivery_mode='replay' "
                        "AND original_wall_ms>=? AND original_wall_ms<?",
                        (outage_start_ms, outage_end_ms)).fetchone()[0]
                if replayed:
                    break
                time.sleep(.25)
            check(replayed > 0, "outage backlog replays durably while current observations continue")
            series_query = urlencode({
                "scope": recovered["hosts"][0]["id"], "metric": "host.memory.swap_used_bytes", "resolution": "raw",
                "start": datetime.fromtimestamp((outage_start_ms - 10_000) / 1000, timezone.utc).isoformat(),
                "end": datetime.now(timezone.utc).isoformat()})
            status, _, raw = request("/api/v1/series?" + series_query, cookie=cookie)
            series = json.loads(raw)
            check(status == 200 and any(outage_start_ms <= point["time_ms"] < outage_end_ms
                                       for point in series["points"]),
                  "authenticated history query includes actual observations from hub outage")
            (work / "recovered-series.json").write_text(json.dumps(series, indent=2) + "\n")
        if args.remote_collector:
            transfer = work / "remote-enrollment.json"
            enrollment_key = str(uuid.uuid4())
            enrollment_result = cli_raw(
                "hosts", "enroll", "--token-file", str(admin_token_file),
                "--name", "Second test installation", "--output-enrollment-file", str(transfer),
                "--deployment-generation", first["deployment_generation"],
                "--idempotency-key", enrollment_key, "--json")
            enrollment_file = json.loads(transfer.read_text())
            enrollment_bearer = enrollment_file["token"]
            secret_values.append(enrollment_bearer)
            check(set(enrollment_result) == {"schema_version", "status", "host_id", "enrollment_file", "expires_ms"} and
                  enrollment_result["status"] == "created" and
                  enrollment_result["host_id"] == enrollment_file["host_id"] and
                  enrollment_result["enrollment_file"] == str(transfer),
                  "hosts enroll CLI creates a bounded transfer for the reserved host")
            check(transfer.stat().st_mode & 0o777 == 0o600 and
                  enrollment_bearer not in json.dumps(enrollment_result),
                  "enrollment transfer is private and its bearer is omitted from CLI output")
            first_transfer = transfer.read_bytes()
            enrollment_retry = cli_raw(
                "hosts", "enroll", "--token-file", str(admin_token_file),
                "--name", "Second test installation", "--output-enrollment-file", str(transfer),
                "--deployment-generation", first["deployment_generation"],
                "--idempotency-key", enrollment_key, "--json")
            check(enrollment_retry == enrollment_result and transfer.read_bytes() == first_transfer,
                  "hosts enroll exact retry preserves the same transfer and host identity")
            remote_home = work / "remote-home"
            remote_runtime = PROJECT / ".work" / ("r-" + run_id)
            remote_command = [str(binary), "--installation-root", str(remote_home), "--runtime-dir", str(remote_runtime)]
            setup = subprocess.run(remote_command + ["setup", "collector", "--enrollment-file", str(transfer), "--no-start", "--json"],
                                   env=env, capture_output=True, timeout=10)
            cli_transcripts.append(setup.stdout + setup.stderr)
            check(setup.returncode == 0, "actual collector CLI exchanges pinned enrollment over TLS")
            remote_result = json.loads(setup.stdout)
            check(remote_result["host_id"] == enrollment_result["host_id"] and remote_result["collector_state"] == "not_started",
                  "remote setup binds reserved host identity without launchctl")
            remote_child = subprocess.Popen([str(collector_binary), *remote_command[1:], "serve"], env=env, stdout=collector_log, stderr=collector_log)
            remote_view = passive_overview(
                lambda item: item["host_count"] == 2 and any(host["id"] == enrollment_result["host_id"] and
                    any(metric["observed_ms"] is not None for metric in host["metrics"]) for host in item["hosts"]),
                "second isolated installation persists native observations through authenticated TLS")
            check(remote_child.poll() is None, "remote collector remains responsive")
            (work / "remote-overview.json").write_text(json.dumps(remote_view, indent=2) + "\n")
            report["remote_collector"] = "two isolated installations on one Mac; actual TLS; second physical host not qualified"

        revoked = cli_raw(
            "auth", "token", "revoke", "--token-file", str(admin_token_file),
            "--token", child_created["record"]["id"],
            "--deployment-generation", first["deployment_generation"],
            "--idempotency-key", str(uuid.uuid4()), "--json")
        validate(contract_root + "response.schema.json#/$defs/tokenRevocation", revoked)
        check(revoked["id"] == child_created["record"]["id"] and revoked["revoked_ms"] > 0,
              "auth token revoke reports the exact retained token identity")
        rejected = cli_raw("auth", "token", "list", "--token-file", str(child_token_file), "--json", expected=4)
        validate(contract_root + "error.schema.json", rejected)
        check(rejected["code"] == "api_token_rejected", "revoked API bearer is rejected by the actual CLI")
        check(request("/api/v1/auth/session", "DELETE", cookie=cookie,
                      headers={"X-CSRF-Token": session["csrf_token"]})[0] == 204, "authenticated CSRF logout")
        check(request("/api/v1/auth/session", cookie=cookie)[0] == 401, "logout revokes session")
        check(request("/api/v1/auth/sessions", "POST", credentials)[0] == 200, "password login persists after restart")
        stop_hub()
        check(not (runtime / "hub.sock").exists(), "graceful hub shutdown removes socket")
        check(not launch_log.exists(), "no launchctl invocation")
        check(all(secret.encode() not in transcript for secret in secret_values for transcript in cli_transcripts),
              "CLI stdout and stderr omit all API and enrollment bearers")
        database = support / "hub" / "monitor.sqlite3"
        secret_artifacts = [database, work / "hub.log"]
        if collector_log:
            secret_artifacts.append(work / "collector.log")
        secret_artifacts.extend(path for suffix in ("-wal", "-shm") if (path := Path(str(database) + suffix)).exists())
        for file in secret_artifacts:
            content = file.read_bytes()
            check(all(secret.encode() not in content for secret in secret_values),
                  "no plaintext auth or transfer canaries in " + file.name)
        report["status"] = "pass"
    except Exception as error:
        report["status"] = "fail"
        report["failure"] = str(error) if isinstance(error, (AssertionError, TimeoutError)) else type(error).__name__
    finally:
        signal.alarm(0)
        if remote_child is not None and remote_child.poll() is None:
            remote_child.terminate()
            try:
                remote_child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                remote_child.kill()
                remote_child.wait(timeout=3)
        stop_hub()
        if collector_child is not None and collector_child.poll() is None:
            collector_child.terminate()
            try:
                collector_child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                collector_child.kill()
                collector_child.wait(timeout=3)
        if collector_log:
            collector_log.close()
        log.close()
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["passed_assertions"] = passed
        (work / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
