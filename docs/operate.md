# Operate the local monitor

> Same-machine developer preview: remote setup, probes, comparisons and external notifications are disabled by default. Historical advanced instructions require the explicit [experimental opt-in](experimental.md). See [current verification and limits](preview-verification.md).


The current Phase 1 source exposes service state, native host observations,
configured Ollama target status and persisted history. A package must be
rebuilt after source changes. Development artifacts remain explicitly
unqualified.

```sh
LLM_MONITOR="$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor"
"$LLM_MONITOR" status
"$LLM_MONITOR" status --json
"$LLM_MONITOR" install check --role local
"$LLM_MONITOR" stop
```

The browser opens at `http://127.0.0.1:9443`. A configured installation asks for the local username and password. Session loss returns to sign-in. Sign out revokes the current session.

## Read the observations

The overview shows each value's age, quality and source method. Memory pressure
uses the validated macOS signal for the exact supported build; missing or stale
values remain explicit. Compression and existing swap are separate facts and do
not establish that a model caused pressure. RMT's own process footprints are
shown separately from other observable same-user processes.

Ollama reachability, installed model inventory and loaded-model observations are
separate. An empty successful loaded-model response means no loaded model was
observed. A failed inventory check means inventory is unavailable. Passive
monitoring does not observe all generation requests, request latency, queue
depth or GPU utilization. No request samples means no captured samples; it does
not mean no inference traffic occurred.

Local target changes use `targets add|edit|remove` with a reviewed private
manifest, its SHA-256, deployment identity/generation and an idempotency key.
The exact manifest format is
[the local target contract](../contracts/api/v1/local-target-manifest.schema.json).
Only a literal loopback HTTP endpoint with an explicit port is accepted. The
collector issues bounded read-only checks; it does not load a model or generate
text. An endpoint edit creates a new target identity and retains old history.

During a hub outage the collector retains observations within its spool limits.
Recovery sends current data and replays retained history. Replayed observations
remain historical and cannot make the current host appear fresh. Age or capacity
loss is reported; no history beyond the configured retention is promised.

## Master and second collector

Install the dashboard and storage role on the master Mac with the generated
`./llm-monitor-install.sh master` command. It selects a literal private
listener and starts only the hub. The dashboard's **Connect another Mac** panel
generates one command for the other Mac:

```sh
./llm-monitor-install.sh collector --hub-url "https://MASTER-IP:PORT" --pairing-code "PAIRING-CODE"
```

The panel shows Waiting, Connected, Expired or Failed. The reservation is
single-use and expires after ten minutes. The collector obtains and pins the
master CA, completes mTLS enrollment, creates its own loopback-only Ollama
target and starts its own user service. No macOS trust store or remote command
is involved. Target selection remains collector-side.

For an existing installation, a deliberate listener change uses
`setup master --collector-listen PRIVATE_IP:PORT` and requires
`--confirm-deployment ID` and `--deployment-generation GENERATION` from current
status. Only explicit private or loopback IP addresses are accepted; wildcard
and public binds are rejected. `--no-start` writes configuration without
operating LaunchAgents. An already running hub must be restarted before a
listener change takes effect.

The listener uses TLS1.3 and the deployment's existing CA. Enrollment reserves
one of the two host slots for ten minutes. The collector generates its own
private key locally. The bounded local test covers administrator enrollment,
CA pinning, private credential files and exact CLI retries; physical
remote-machine testing remains outside this phase.

## First administrator

The local browser obtains the one-use setup handoff automatically. It expires
after 30 minutes and is consumed atomically. The browser does not persist the
handoff or password in URLs or application browser storage. Renew an expired
handoff only while no administrator exists:

```sh
"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor" admin bootstrap-renew
```

## CLI sign-in and API tokens

After creating the first administrator in the local UI, sign in through the
same local hub using `auth login --username NAME --password-stdin
--session-file ABSOLUTE_PATH --json`. Supply the password through standard input
from a password manager or a hidden terminal prompt. Never put it in command
arguments, shell history or a script. The command creates a new owner-only
session file; it will not replace an existing file. Keep that file private.

Use `auth token create --session-file ABSOLUTE_PATH --name NAME --expires 24h
--output-token-file ABSOLUTE_PATH --deployment-generation GENERATION
--idempotency-key UNIQUE_KEY --json` to obtain a bearer token. Read the current
generation from `status --json`. Token commands accept exactly one session file
or token file. Credentials are saved privately and are not printed in JSON.

`auth logout --session-file ABSOLUTE_PATH --json` revokes the session through
the hub before removing its local file. If the hub cannot confirm revocation,
the command retains the file for retry. Signing out does not revoke separately
created API tokens; use `auth token revoke` for those. An expired session must
be signed out before its path can be reused for a new sign-in.

## Read monitoring evidence from the CLI

`hosts list`, `hosts show --id ID`, `targets check --id ID`, and
`history catalog` accept `--token-file FILE` or `--session-file FILE` plus
`--json`. These read the same stored observations as the UI; `targets check`
reports the last observed state and does not contact Ollama.

Use `series query --scope ID --metric host.cpu.busy_ratio --start RFC3339
--end RFC3339 --resolution auto` with the same credential flag. Absolute times
are normalized to UTC; the hub chooses the retained tier and reports coverage,
gaps and unavailable values. A missing series is not a zero measurement.

## Save a manual investigation

`incidents create --title TITLE --scope-kind host --scope ID --start RFC3339
--end RFC3339 --deployment-generation GENERATION --idempotency-key KEY`
requires an administrator credential. It preserves bounded evidence for that
focus window and the preceding baseline. Read it with `incidents show --id ID`.
`incidents list --limit 100` returns a page; pass its `next_cursor` with
`--cursor ID` until that field is null.

Use `annotations create --incident ID --declared-time RFC3339 --text NOTE`
with the same generation and idempotency flags to add a plaintext note.
`annotations edit --id ID --expected-revision N --text NOTE` preserves prior
edits and refuses stale revisions. Notes are explicitly operator-declared;
they do not become observed machine events. Incident details include the first
page of notes; `annotations list --incident ID --cursor ID` reads later pages.
Rename with `incidents update --id ID --expected-revision N --title TITLE`.
Use `incidents close` or `incidents reopen` with the same ID/revision and mutation
flags to change manual workflow state. These preserve the capsule and do not
resolve an alert condition. Reopening remains subject to open-investigation
capacity; expired evidence does not reappear.

Updates return a bounded metadata result. Retrying the same key and input returns
that operation's saved result, even if a later edit has occurred. Use `incidents
show --id ID` to read the current state; an old retry does not undo later edits.

Every command accepts a session or token file and `--json`; `--help` lists its
flags. Saved manual investigations do not assert that an alert fired.

## Configure and inspect alerts

Open **Alert rules** in the local UI. An administrator can create or edit a
versioned definition; viewers can inspect it. Enable only the scopes you intend
to monitor. Passive Ollama inventory does not supply request-duration samples.

CLI parity: `rules list`, `rules show --id ID`, and `rules create
--definition-file FILE`. To edit or disable, use `rules edit|disable --id ID
--definition-file FILE`. The file contains the complete reviewed definition,
including `expected_revision` (null for creation). Mutations also require
`--deployment-generation`, `--idempotency-key` and a private credential file.
Retry the identical file and key after an uncertain response; retrieve the
current rule separately because an old retry returns its original result.

An alert incident keeps its condition, evidence quality, human acknowledgement
and delivery status separate. Its original trigger evidence is immutable.
Use `incidents acknowledge --id ID --observed-transition-seq N`, `incidents
mute --id ID --reason TEXT --expires RFC3339`, or `incidents unmute --id ID`,
with the same mutation flags. Mutes last at most24 hours. Neither acknowledgement
nor mute resolves the observed condition. A notification already in flight
may still arrive. Refresh the incident after a control action to see current
state; retry receipts describe the original action.

`monitor-health show` with a credential file reports storage and evaluator
health. `/healthz` checks process liveness; `/readyz` returns503 until storage
and the alert evaluator are ready. Detailed health requires authentication.
The Services panel warns when evaluation fails or becomes delayed. Sleeping
or logged-out Macs cannot evaluate or deliver alerts while stopped.

Current implementation checkpoint: destination configuration and actual
notification delivery remain incomplete. No delivery success or real-model
qualification is implied by a saved rule or a passing predicate test.

## Review retained spool after a restore

Re-enroll the retained collector into the restored deployment, then stop that
collector before inspecting its spool. A running collector holds the spool lock;
the recovery command refuses to compete with it. Ordinary monitoring can resume
independently of old-generation recovery.

On the collector Mac, use `collector recover-spool preview --out FILE
--idempotency-key UUID --confirm-deployment UUID --deployment-generation UUID
--original-generation UUID --original-boot UUID`. The preview writes a private
manifest and reports its hash, frame count and original time range. It does not
repair, prune or acknowledge spool data. Keep the exact manifest for review and
retry. Oversized manifests need a smaller contiguous sequence selection using
`--from-sequence N --to-sequence M`; a selection cannot skip an earlier physical
record awaiting recovery.

A current administrator reviews that manifest, then runs `recovery grants create
--manifest FILE --out GRANT --deployment-generation UUID --idempotency-key KEY`
with a session or token file. `recovery grants show --grant UUID` retrieves the
approved scope; `recovery grants revoke --grant UUID` revokes unused approval.
Mutations require the current generation and a retry key. A grant expires after
one hour and does not extend the spool's 24-hour eligibility window.

On the collector Mac, run `collector recover-spool apply --grant GRANT
--grant-sha256 FILE_SHA256 --idempotency-key UUID --confirm-deployment UUID
--deployment-generation UUID --report-out FILE`. The supplied hash is over the
exact grant file bytes. Recovery verifies complete approved segments and advances
only durable acknowledgements. Retry an interrupted apply with its original key
and reviewed files. Recovered observations retain original provenance and remain
historical; they do not establish current freshness. Keep the report, then resume
ordinary collection. This development workflow remains under integration testing.

## User-session lifecycle

The hub and collector are per-user LaunchAgents. They start after login and have no before-login or asleep guarantee. They do not change power settings. After login or wake:

```sh
"$HOME/Library/Application Support/LLM Monitor/bin/llm-monitor" status
```

Use the offline recovery guide at `~/Library/Application Support/LLM Monitor/docs/recover.html` if a service is unavailable.
