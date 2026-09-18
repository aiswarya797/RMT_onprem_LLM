#!/usr/bin/env python3
"""Finite real backup/restore CLI + HTTP workflow in an isolated installation.

Launchd reads are simulated as absent; any mutation is trapped. No user service,
Ollama endpoint or model is contacted. Run only under independent supervision.
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

from u02_cli_smoke import PROJECT, schema_validator


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--recover-spool', action='store_true', help='also exercise reviewed old-generation spool recovery')
    parser.add_argument('--rules', action='store_true', help='also exercise reviewed alert-rule CRUD; no deliberate load or notification send')
    parser.add_argument('--alerts', action='store_true', help='wait for a real stopped test-collector heartbeat alert and exercise acknowledgement/mute; no external delivery')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    collector_binary = binary.with_name('llm-monitor-collector').resolve(strict=True)
    if not binary.is_relative_to(PROJECT) or not collector_binary.is_relative_to(PROJECT):
        parser.error('binary must be inside this project')
    run_id = uuid.uuid4().hex[:8]
    work = PROJECT / '.work' / 'recovery-smoke' / run_id
    work.mkdir(parents=True, mode=0o700)
    home = work / 'home'
    home.mkdir(mode=0o700)
    runtime = PROJECT / '.work' / ('r-' + run_id)
    runtime.mkdir(mode=0o700)
    guard = work / 'guard'
    guard.mkdir(mode=0o700)
    launch_log = work / 'unexpected-launchctl.txt'
    launchctl = guard / 'launchctl'
    launchctl.write_text('#!/bin/sh\nif [ "$1" = print ]; then exit 113; fi\nprintf "%s\\n" "$*" >> "$RMT_TEST_LAUNCHCTL_LOG"\nexit 64\n')
    launchctl.chmod(0o700)
    env = dict(os.environ, PATH=str(guard) + os.pathsep + os.environ.get('PATH', ''),
               RMT_TEST_LAUNCHCTL_LOG=str(launch_log))
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    command = [str(binary), '--installation-root', str(home), '--runtime-dir', str(runtime), '--listen', f'127.0.0.1:{port}']
    support = home / 'Library' / 'Application Support' / 'LLM Monitor'
    passed, transcripts, secret_values = [], [], []
    child = None
    collector_child = None
    log = (work / 'hub.log').open('wb')
    validate = schema_validator()
    contract = 'https://llm-monitor.local/contracts/api/v1/'
    report = {'test': 'actual_encrypted_backup_restore_cli_http', 'run_id': run_id,
              'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
              'collector_binary_sha256': hashlib.sha256(collector_binary.read_bytes()).hexdigest(),
              'state_directory': str(work), 'launchd': 'absence simulated; mutations trapped; not qualified',
              'inference': 'not attempted'}
    started = time.monotonic()

    def check(value, description):
        if not value:
            raise AssertionError(description)
        passed.append(description)

    def cli(*args, schema=None, expected=0, input_bytes=None):
        result = subprocess.run(command + list(args), env=env, capture_output=True, timeout=15, input=input_bytes)
        transcripts.append(result.stdout + result.stderr)
        check(result.returncode == expected, 'CLI exit: ' + ' '.join(args[:2]))
        value = json.loads(result.stdout)
        if expected:
            validate(contract + 'error.schema.json', value)
        elif schema:
            validate(contract + 'local-response.schema.json#/$defs/' + schema, value)
        return value

    def request(path, method='GET', body=None, cookie=None, headers=None):
        fields = {'Origin': origin, **(headers or {})}
        if cookie:
            fields['Cookie'] = cookie
        if body is not None:
            fields['Content-Type'] = 'application/json'
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        try:
            connection.request(method, path, json.dumps(body) if body is not None else None, fields)
            response = connection.getresponse()
            raw = response.read((1 << 20) + 1)
            check(len(raw) <= 1 << 20, 'HTTP response remains bounded')
            return response.status, dict(response.getheaders()), json.loads(raw)
        finally:
            connection.close()

    def start_hub():
        nonlocal child
        child = subprocess.Popen(command + ['hub', 'serve'], env=env, stdout=log, stderr=log)
        for _ in range(50):
            if child.poll() is not None:
                raise AssertionError('hub exited; inspect retained hub.log')
            try:
                if request('/api/v1/auth/bootstrap')[0] == 200:
                    return
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(.1)
        raise AssertionError('hub startup exceeded five seconds')

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

    def start_collector():
        nonlocal collector_child
        collector_child = subprocess.Popen([str(collector_binary), '--installation-root', str(home), '--runtime-dir', str(runtime), 'serve'], env=env, stdout=log, stderr=log)

    def stop_collector():
        nonlocal collector_child
        if collector_child is not None and collector_child.poll() is None:
            collector_child.terminate()
            try:
                collector_child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                collector_child.kill()
                collector_child.wait(timeout=3)
        collector_child = None

    def observed_host(cookie, after_ms=0):
        until = time.monotonic() + 12
        while time.monotonic() < until:
            if collector_child is None or collector_child.poll() is not None:
                raise AssertionError('owned collector exited before native observations')
            code, _, overview = request('/api/v1/overview', cookie=cookie)
            if code == 200:
                for host in overview['hosts']:
                    if host['state'] == 'active' and any((metric['observed_ms'] or 0) > after_ms and metric['value'] is not None for metric in host['metrics']):
                        return host
            time.sleep(.2)
        raise AssertionError('native observations did not arrive within twelve seconds')

    def spool_hashes():
        result, total = {}, 0
        for path in sorted((support / 'collector' / 'spool').rglob('*')):
            if not path.is_file():
                continue
            total += path.stat().st_size
            if total > 257 << 20:
                raise AssertionError('test spool exceeded bounded retained state')
            digest = hashlib.sha256()
            with path.open('rb') as source:
                for chunk in iter(lambda: source.read(65536), b''):
                    digest.update(chunk)
            result[str(path.relative_to(support / 'collector' / 'spool'))] = digest.hexdigest()
        return result

    def retained_original_boot():
        # Read only the bounded first envelope from the test-owned spool. No
        # payload is decoded, edited or injected into the collector.
        for path in sorted((support / 'collector' / 'spool').glob('*.seg')):
            with path.open('rb') as source:
                header = source.read(40)
                check(len(header) == 40 and header[:4] == b'RMT1', 'retained spool envelope is recognizable')
                length = int.from_bytes(header[4:8], 'big')
                check(0 < length <= 352 << 10, 'retained spool envelope length remains bounded')
                encoded = source.read(length)
            check(hashlib.sha256(encoded).digest() == header[8:], 'retained spool envelope hash verifies')
            record = json.loads(encoded)
            if record['security_generation'] == setup['deployment_generation']:
                return record['collector_boot_id']
        raise AssertionError('original collector boot missing from retained spool')

    def recovery_db_evidence(grant_id):
        database = support / 'hub' / 'monitor.sqlite3'
        connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=2)
        try:
            controls = connection.execute('SELECT count(*),max(observed_ms),max(admitted_ms) FROM source_status').fetchone()
            rows = connection.execute("SELECT original_security_generation,original_collector_boot_id,delivery_mode,recovery_grant_hash,count(*) FROM source_frames WHERE recovery_grant_id=? GROUP BY 1,2,3,4", (grant_id,)).fetchall()
            receipts = connection.execute('SELECT count(*) FROM recovery_grant_receipts WHERE grant_id=?', (grant_id,)).fetchone()[0]
            return controls, rows, receipts
        finally:
            connection.close()

    workflow_timeout = 85 if args.alerts else 60
    def deadline(_signal, _frame):
        raise TimeoutError(f'finite {workflow_timeout}-second recovery workflow deadline')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(workflow_timeout)
    try:
        setup = cli('setup', 'local', '--no-start', '--json', schema='setupLocal')
        inspection = cli('recovery', 'inspect', '--json', schema='recoveryInspection')
        check(inspection['state'] == 'no_journal' and not inspection['resume_argv'], 'new installation inspection invents no recovery transaction')
        token = Path(setup['bootstrap_token_path']).read_text().strip()
        password = secrets.token_urlsafe(24)
        secret_values.extend([token, password])
        start_hub()
        status, headers, session = request('/api/v1/auth/bootstrap', 'POST',
                                          {'bootstrap_token': token, 'username': 'original-owner', 'password': password})
        check(status == 201, 'actual initial administrator creation')
        cookie = headers['Set-Cookie'].split(';', 1)[0]
        secret_values.append(cookie.split('=', 1)[1])
        start_collector()
        original_host = observed_host(cookie)
        check(bool(original_host['metrics']), 'native collector publishes actual host observations before backup')
        backup_path, key_path = work / 'recovery.age', work / 'recovery.key'
        backup = cli('backup', 'create', '--out', str(backup_path), '--key-out', str(key_path),
                     '--confirm-deployment', setup['deployment_id'], '--deployment-generation', setup['deployment_generation'],
                     '--json', schema='backup')
        check(backup['published'] and backup_path.read_bytes().startswith(b'age-encryption.org/v1'), 'online backup is published in authenticated encrypted format')
        check(key_path.stat().st_mode & 0o777 == 0o600, 'operator recovery key remains private')
        secret_values.append(key_path.read_text().strip())
        verified = cli('backup', 'verify', '--from', str(backup_path), '--key-file', str(key_path),
                       '--confirm-deployment', setup['deployment_id'], '--json', schema='backup')
        check(verified['manifest_sha256'] == backup['manifest_sha256'], 'CLI verification confirms the recovery manifest')
        restore_args = ('restore', '--from', str(backup_path), '--key-file', str(key_path), '--confirm-deployment', setup['deployment_id'],
                        '--deployment-generation', setup['deployment_generation'], '--confirm-recovery-point-ms', str(backup['recovery_point_ms']), '--json')
        cli(*restore_args, expected=8)
        check(request('/api/v1/status', cookie=cookie)[0] == 200, 'rejected online restore leaves live hub responsive')
        status, _, issued = request('/api/v1/auth/tokens', 'POST', {'display_name': 'after-backup', 'expires_in_seconds': 3600}, cookie,
                                     {'X-CSRF-Token': session['csrf_token'], 'If-Deployment-Generation': setup['deployment_generation'], 'Idempotency-Key': str(uuid.uuid4())})
        check(status == 201, 'actual post-backup token mutation')
        old_bearer = issued['token']
        secret_values.append(old_bearer)
        old_ca = (support / 'ca.pem').read_bytes()
        old_secret = (support / 'session.key').read_bytes()
        stop_hub()
        # One five-second native cycle while the hub is absent retains real
        # unacknowledged records. This does not make an inference request.
        time.sleep(5.5)
        stop_collector()
        retained_spool = spool_hashes()
        check(any(name.endswith('.seg') for name in retained_spool), 'hub outage leaves retained collector spool segments')
        original_boot = retained_original_boot() if args.recover_spool else None
        restored = cli(*restore_args, schema='restoreResult')
        inspection = cli('recovery', 'inspect', '--json', schema='recoveryInspection')
        check(inspection['state'] == 'committed' and inspection['transaction_id'] == restored['transaction_id'] and not inspection['resume_argv'], 'actual recovery inspection reports committed identity without replaying activation')
        check(restored['deployment_generation'] != setup['deployment_generation'], 'restore creates a new deployment generation')
        check(restored['later_changes_unknown'] and any(item['class'] == 'audit' and item['retained_rows'] > 0 for item in restored['recovery_evidence']['known_later_records']), 'restore reports known later audit records without claiming zero loss')
        displaced = Path(restored['displaced_directory'])
        check((displaced / 'monitor.sqlite3').is_file() and (displaced / 'ca.key').stat().st_mode & 0o777 == 0o400, 'displaced database and readonly trust files survive')
        check(old_ca != (support / 'ca.pem').read_bytes() and old_secret != (support / 'session.key').read_bytes(), 'CA and session trust both rotate')
        start_hub()
        check(request('/api/v1/auth/session', cookie=cookie)[0] == 401, 'restored hub rejects the previous session')
        check(request('/api/v1/status', headers={'Authorization': 'Bearer ' + old_bearer})[0] == 401, 'restored hub rejects the previous API token')
        new_token = Path(restored['bootstrap_token_path']).read_text().strip()
        secret_values.append(new_token)
        restored_password = secrets.token_urlsafe(24)
        secret_values.append(restored_password)
        status, new_headers, _ = request('/api/v1/auth/bootstrap', 'POST', {'bootstrap_token': new_token, 'username': 'restored-owner', 'password': restored_password})
        check(status == 201, 'actual new administrator bootstrap completes recovery')
        new_cookie = new_headers['Set-Cookie'].split(';', 1)[0]
        secret_values.append(new_cookie.split('=', 1)[1])
        status, _, state = request('/api/v1/deployment-state', cookie=new_cookie)
        check(status == 200 and state['mutations_allowed'] and state['recovery_point_ms'] == backup['recovery_point_ms'], 'restored deployment returns recovery point and opens normal mutations only after bootstrap')
        reenrolled = cli('setup', 'local', '--re-enroll', '--no-start', '--json', schema='setupLocal')
        check(reenrolled['status'] == 'reenrolled' and reenrolled['deployment_generation'] == restored['deployment_generation'], 'explicit local re-enrollment advances the retained collector into restored trust')
        repeated = cli('setup', 'local', '--re-enroll', '--no-start', '--json', schema='setupLocal')
        check(repeated['status'] == 'already_reenrolled', 'explicit local re-enrollment retry is idempotent')
        check(spool_hashes() == retained_spool, 'restore and re-enrollment preserve every retained spool byte')
        restarted_ms = int(time.time() * 1000)
        start_collector()
        recovered_host = observed_host(new_cookie, restarted_ms)
        check(recovered_host['id'] == original_host['id'], 'native monitoring resumes under the same retained host identity')
        stop_collector()
        resumed_spool = spool_hashes()
        check(all(resumed_spool.get(name) == digest for name, digest in retained_spool.items() if name.endswith('.seg')),
              'fresh monitoring preserves old-generation segments pending reviewed recovery')
        session_file = work / 'cli-session.json'
        cli('auth', 'login', '--username', 'restored-owner', '--password-stdin', '--session-file', str(session_file), '--json', schema='authSessionCLI', input_bytes=(restored_password + '\n').encode())
        saved_session = json.loads(session_file.read_text())
        secret_values.extend([saved_session['cookie'], saved_session['session']['csrf_token']])
        auth_flags = ('--session-file', str(session_file), '--json')
        mutation_flags = ('--deployment-generation', state['deployment_generation'])
        hosts = cli('hosts', 'list', *auth_flags)
        check(any(item['id'] == original_host['id'] for item in hosts['items']), 'authenticated CLI sees the retained host')
        catalog = cli('history', 'catalog', *auth_flags)
        check(any(item['id'] == original_host['id'] for item in catalog['scopes']), 'authenticated CLI exposes retained history scopes')
        end_time = datetime.now(timezone.utc)
        end_text = end_time.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        start_text = datetime.fromtimestamp(end_time.timestamp()-300, timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
        series = cli('series', 'query', '--scope', original_host['id'], '--metric', 'host.cpu.busy_ratio', '--start', start_text, '--end', end_text, *auth_flags)
        check(len(series['points']) > 0, 'authenticated CLI reads actual native history')
        create_key = str(uuid.uuid4())
        create_args = ('incidents', 'create', '--title', 'Restored native monitoring', '--scope-kind', 'host', '--scope', original_host['id'], '--start', start_text, '--end', end_text, *mutation_flags, '--idempotency-key', create_key, *auth_flags)
        created_incident = cli(*create_args)
        validate(contract + 'incident-response.schema.json#/$defs/incidentSummary', created_incident)
        incident = cli('incidents', 'show', '--id', created_incident['id'], *auth_flags)
        validate(contract + 'incident-response.schema.json#/$defs/incidentDetail', incident)
        check(incident['origin'] == 'manual' and incident['capsule']['cards'], 'manual investigation saves bounded evidence without inventing an alert')
        retry = cli(*create_args)
        check(retry['id'] == incident['id'] and retry['capsule_sha256'] == incident['capsule_sha256'], 'exact incident retry preserves the frozen capsule')
        annotation_args = ('annotations', 'create', '--incident', incident['id'], '--declared-time', end_text, '--text', 'Observed restored native readings; no inference was run.', *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
        annotation = cli(*annotation_args)
        validate(contract + 'incident-response.schema.json#/$defs/annotation', annotation)
        edited = cli('annotations', 'edit', '--id', annotation['id'], '--expected-revision', str(annotation['revision']), '--text', 'Operator note: restored native readings observed; inference remains untested.', *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
        check(edited['revision'] == annotation['revision'] + 1 and edited['provenance'] == 'operator_declared', 'annotation edit increments revision and preserves declared provenance')
        check(cli(*annotation_args) == annotation, 'annotation creation retry preserves its original result after an edit')
        reopened = cli('incidents', 'show', '--id', incident['id'], *auth_flags)
        check(reopened['capsule_sha256'] == incident['capsule_sha256'] and reopened['annotations'][0]['text'] == edited['text'], 'saved incident reopens with immutable evidence and edited note')
        notes = cli('annotations', 'list', '--incident', incident['id'], '--limit', '1', *auth_flags)
        check(len(notes['items']) == 1 and notes['next_cursor'] is None, 'annotation CLI page is bounded and complete')
        renamed = cli('incidents', 'update', '--id', incident['id'], '--expected-revision', str(reopened['revision']), '--title', 'Reviewed restored monitoring', *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
        check(renamed['title'] == 'Reviewed restored monitoring' and renamed['capsule_sha256'] == incident['capsule_sha256'], 'renaming preserves frozen evidence')
        close_args = ('incidents', 'close', '--id', incident['id'], '--expected-revision', str(renamed['revision']), *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
        closed = cli(*close_args)
        validate(contract + 'incident-response.schema.json#/$defs/incidentSummary', closed)
        closed_retry = cli(*close_args)
        check(closed['workflow_state'] == 'closed' and closed_retry['revision'] == closed['revision'] and closed['capsule_sha256'] == incident['capsule_sha256'], 'manual close is idempotent and preserves evidence')
        opened = cli('incidents', 'reopen', '--id', incident['id'], '--expected-revision', str(closed['revision']), *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
        check(opened['workflow_state'] == 'open' and opened['capsule_sha256'] == incident['capsule_sha256'], 'manual reopen preserves frozen evidence')
        old_close_receipt = cli(*close_args)
        check(old_close_receipt == closed, 'exact close retry after a later reopen returns its original bounded result')
        current_incident = cli('incidents', 'show', '--id', incident['id'], *auth_flags)
        check(current_incident['workflow_state'] == 'open' and current_incident['revision'] == opened['revision'], 'old mutation retry does not roll back the current workflow')
        check(cli(*create_args) == created_incident, 'incident creation retry returns its original result after later metadata edits')
        process_scope = next((item for item in catalog['scopes'] if item['kind'] == 'process'), None)
        check(process_scope is not None, 'native collection exposes an actual retained process scope')
        process_incident = cli('incidents', 'create', '--title', 'Actual retained process', '--scope-kind', 'process', '--scope', process_scope['id'], '--start', start_text, '--end', end_text, *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
        process_detail = cli('incidents', 'show', '--id', process_incident['id'], *auth_flags)
        validate(contract + 'incident-response.schema.json#/$defs/incidentDetail', process_detail)
        check(process_detail['scope'] == {'kind': 'process', 'id': process_scope['id']} and process_detail['capsule']['cards'], 'an offered actual process scope saves and reopens its bounded evidence')
        if args.rules:
            definition = {'expected_revision': None, 'evaluator_type': 'heavy_cpu', 'scope_id': original_host['id'], 'enabled': True,
                          'metric_id': None, 'request_population': None, 'aggregation': None, 'threshold': 0.9, 'dwell_ms': 60000, 'recovery_ms': 60000}
            definition_file = work / 'reviewed-cpu-rule.json'
            definition_file.write_text(json.dumps(definition) + '\n')
            rule_args = ('rules', 'create', '--definition-file', str(definition_file), *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
            created_rule = cli(*rule_args)
            validate(contract + 'response.schema.json#/$defs/rule', created_rule)
            check(cli(*rule_args) == created_rule, 'rule create exact retry returns the original definition')
            disable_file = work / 'reviewed-disabled-cpu-rule.json'
            disable_file.write_text(json.dumps({**definition, 'expected_revision': created_rule['revision'], 'enabled': False}) + '\n')
            disable_args = ('rules', 'disable', '--id', created_rule['id'], '--definition-file', str(disable_file), *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
            disabled_rule = cli(*disable_args)
            check(disabled_rule['revision'] == created_rule['revision'] + 1 and not disabled_rule['definition']['enabled'], 'reviewed rule disable creates a new revision')
            check(cli(*disable_args) == disabled_rule and cli(*rule_args) == created_rule, 'rule retries retain original mutation results after later edits')
            check(cli('rules', 'show', '--id', created_rule['id'], *auth_flags) == disabled_rule, 'old create retry does not revert the current rule')
            rule_list = cli('rules', 'list', *auth_flags)
            check(any(item['id'] == created_rule['id'] for item in rule_list['items']), 'reviewed rules remain discoverable')
            report['rule_crud'] = 'passed; evaluator and notification journey separately pending'
        if args.alerts:
            check(collector_child is None, 'only the isolated test collector is stopped for the heartbeat scenario')
            definition = {'expected_revision': None, 'evaluator_type': 'host_not_reporting', 'scope_id': original_host['id'], 'enabled': True,
                          'metric_id': None, 'request_population': None, 'aggregation': None, 'threshold': 60000, 'dwell_ms': 0, 'recovery_ms': 30000}
            definition_file = work / 'reviewed-heartbeat-rule.json'
            definition_file.write_text(json.dumps(definition))
            rule = cli('rules', 'create', '--definition-file', str(definition_file), *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
            # Observe the actual 60-second absence; never rewrite timestamps or
            # inject an alert row. The outer supervisor independently caps time.
            until, alert = min(started + 78, time.monotonic() + 70), None
            while time.monotonic() < until:
                if child is None or child.poll() is not None:
                    raise AssertionError('owned hub exited during heartbeat observation')
                inbox = cli('incidents', 'list', *auth_flags)
                alert = next((item for item in inbox['items'] if item.get('alert_state', {}).get('rule_id') == rule['id']), None)
                if alert is not None:
                    break
                time.sleep(2)
            check(alert is not None, 'automatic evaluator opens an incident for the actual missing test-collector heartbeat')
            health = cli('monitor-health', 'show', *auth_flags)
            validate(contract + 'response.schema.json#/$defs/monitorHealth', health)
            check(health['evaluator']['last_success_ms'] is not None and not health['evaluator']['last_pass_failed'], 'authenticated health reports a successful current evaluator')
            check(request('/healthz')[0] == 200 and request('/readyz')[0] == 200, 'hub liveness and monitoring readiness remain available during collector absence')
            detail = cli('incidents', 'show', '--id', alert['id'], *auth_flags)
            validate(contract + 'incident-response.schema.json#/$defs/incidentDetail', detail)
            check(detail['alert_state']['condition'] == 'FIRING' and detail['end_ms'] is None, 'heartbeat incident condition is firing with an open evidence interval')
            check(detail['capsule']['rule']['evaluator_type'] == 'host_not_reporting', 'frozen capsule identifies the observed heartbeat rule')
            control_flags = ('--id', alert['id'], *mutation_flags, *auth_flags)
            ack_args = ('incidents', 'acknowledge', '--observed-transition-seq', str(detail['alert_state']['transition_seq']), *control_flags, '--idempotency-key', str(uuid.uuid4()))
            acknowledged = cli(*ack_args)
            validate(contract + 'incident-response.schema.json#/$defs/alertControl', acknowledged)
            check(cli(*ack_args) == acknowledged and acknowledged['alert_state']['condition'] == 'FIRING', 'acknowledgement retries exactly without resolving the observed condition')
            expiry = datetime.fromtimestamp(time.time() + 600, timezone.utc).isoformat()
            mute_args = ('incidents', 'mute', '--reason', 'Isolated test collector is intentionally stopped', '--expires', expiry, *control_flags, '--idempotency-key', str(uuid.uuid4()))
            muted = cli(*mute_args)
            validate(contract + 'incident-response.schema.json#/$defs/alertControl', muted)
            unmuted = cli('incidents', 'unmute', *control_flags, '--idempotency-key', str(uuid.uuid4()))
            validate(contract + 'incident-response.schema.json#/$defs/alertControl', unmuted)
            check(cli(*mute_args) == muted, 'older mute retry returns its exact prior action result')
            current = cli('incidents', 'show', '--id', alert['id'], *auth_flags)
            check(current['alert_state']['condition'] == 'FIRING' and current['alert_state']['muted_until_ms'] is None and current['alert_state']['acknowledged_ms'] is not None,
                  'older mute retry cannot remute or resolve the current alert')
            check(current['capsule_sha256'] == detail['capsule_sha256'] and current['alert_state']['delivery']['total'] == 0,
                  'controls preserve frozen evidence and no notification destination was enabled')
            report['automatic_heartbeat_alert'] = {'incident_id': alert['id'], 'rule_id': rule['id'], 'condition': current['alert_state']['condition'], 'delivery': 'not configured; no sends', 'recovery': 'not tested in this bounded run'}
        if args.recover_spool:
            manifest_file, grant_file, report_file = work / 'recovery-manifest.json', work / 'recovery-grant.json', work / 'spool-recovery-report.json'
            preview_args = ('collector', 'recover-spool', 'preview', '--out', str(manifest_file), '--idempotency-key', str(uuid.uuid4()), '--confirm-deployment', setup['deployment_id'], '--deployment-generation', state['deployment_generation'], '--original-generation', setup['deployment_generation'], '--original-boot', original_boot, '--json')
            before_preview = spool_hashes()
            cli(*preview_args, schema='collectorRecoveryPreview')
            manifest_bytes = manifest_file.read_bytes()
            cli(*preview_args, schema='collectorRecoveryPreview')
            check(manifest_file.read_bytes() == manifest_bytes and spool_hashes() == before_preview, 'owner preview exact retry preserves manifest and every spool byte')
            manifest = json.loads(manifest_bytes)
            validate('https://llm-monitor.local/contracts/collector/v1/recovery-manifest.schema.json', manifest)
            grant_args = ('recovery', 'grants', 'create', '--manifest', str(manifest_file), '--out', str(grant_file), *mutation_flags, '--idempotency-key', str(uuid.uuid4()), *auth_flags)
            grant = cli(*grant_args)
            check(cli(*grant_args) == grant, 'administrator grant creation has an exact retry result')
            check(cli('recovery', 'grants', 'show', '--grant', grant['grant_id'], *auth_flags) == grant, 'reviewed recovery grant remains discoverable')
            before_controls, _, _ = recovery_db_evidence(grant['grant_id'])
            apply_args = ('collector', 'recover-spool', 'apply', '--grant', str(grant_file), '--grant-sha256', hashlib.sha256(grant_file.read_bytes()).hexdigest(), '--idempotency-key', str(uuid.uuid4()), '--confirm-deployment', setup['deployment_id'], '--deployment-generation', state['deployment_generation'], '--report-out', str(report_file), '--json')
            cli(*apply_args, schema='collectorRecoveryReport')
            first_report = report_file.read_bytes()
            after_controls, recovered_rows, receipt_count = recovery_db_evidence(grant['grant_id'])
            check(after_controls == before_controls, 'historical recovery does not fabricate fresh control observations')
            check(receipt_count == manifest['total_frames'] and sum(row[4] for row in recovered_rows) > 0, 'actual retained outage frames have durable recovery receipts and stored history')
            check(all(row[:4] == (setup['deployment_generation'], original_boot, 'restored_replay', grant['grant_sha256']) for row in recovered_rows), 'recovered history retains original generation, boot and exact grant provenance')
            cli(*apply_args, schema='collectorRecoveryReport')
            check(report_file.read_bytes() == first_report and recovery_db_evidence(grant['grant_id']) == (after_controls, recovered_rows, receipt_count), 'owner apply exact retry preserves evidence without duplicate writes')
            report['retained_spool_recovery'] = {'grant_id': grant['grant_id'], 'frames': receipt_count, 'status': 'passed'}
        cli('auth', 'logout', '--session-file', str(session_file), '--json', schema='authSessionCLI')
        check(not session_file.exists(), 'CLI logout removes its revoked private session file')
        stop_hub()
        check(not launch_log.exists(), 'no launchd mutation was invoked')
        log.flush()
        public_output = b'\n'.join(transcripts) + (work / 'hub.log').read_bytes()
        check(all(value.encode() not in public_output for value in secret_values), 'credentials never appear in CLI output or hub logs')
        check(not (runtime / 'hub.sock').exists(), 'task-owned hub socket removed after shutdown')
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=str(error))
        raise
    finally:
        signal.alarm(0)
        stop_collector()
        stop_hub()
        log.close()
        report.update(assertions=passed, elapsed_seconds=round(time.monotonic()-started, 3))
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'status': report['status'], 'assertions': len(passed), 'report': str(work / 'result.json')}))


if __name__ == '__main__':
    main()
