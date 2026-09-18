import type { AlertIncidentState, AlertTriggerCapsule } from "./api";

export function AlertStatePanel({ state }: { state: AlertIncidentState | undefined }) {
  if (!state) return <p role="status">Current alert condition and delivery state are unavailable.</p>;
  const delivery = state.delivery;
  const deliveries = state.deliveries ?? [];
  return <section aria-labelledby="alert-current-state">
    <h3 id="alert-current-state">Alert state at last refresh</h3>
    <dl className="status-grid">
      <div><dt>Condition</dt><dd>{state.condition}</dd></div>
      <div><dt>Data quality</dt><dd>{state.data_state}</dd></div>
      <div><dt>Acknowledgement</dt><dd>{state.acknowledged_ms === null ? "Unacknowledged" : `Acknowledged at ${date(state.acknowledged_ms)} by ${state.acknowledged_by ?? "unavailable actor"}`}</dd></div>
      <div><dt>Delivery mute</dt><dd>{state.muted_until_ms === null ? "Not muted" : `${state.muted_until_ms > Date.now() ? "Muted until" : "Expired at"} ${date(state.muted_until_ms)}`}</dd></div>
    </dl>
    <p>Acknowledgement and mute do not change the observed condition.</p>
    <h4>Notification delivery</h4>
    {delivery.total === 0 ? <p>No notification records.</p> : <ul>
      <li>Pending: {delivery.pending}; in flight: {delivery.leased}; sent: {delivery.sent}.</li>
      <li>Failed: {delivery.failed}; expired: {delivery.expired}; muted: {delivery.muted}; superseded before delivery: {delivery.superseded_before_delivery}.</li>
    </ul>}
    {deliveries.length > 0 && <>
      <h5>Delivery records</h5>
      <ul aria-label="Notification delivery records">
        {deliveries.map((item) => <li key={item.id}>
          <code>{item.destination_id}</code>: <strong>{deliveryStatusLabel(item.status)}</strong> (attempts {item.attempts}, stored state {item.state}).
          {item.receiver_ack_ms !== null && <> Receiver acknowledged at {date(item.receiver_ack_ms)}.</>}
          {item.safe_error_code !== null && <> Safe error: <code>{item.safe_error_code}</code>.</>}
          {item.accepted_unknown && <> The outcome is accepted as unknown.</>}
        </li>)}
      </ul>
    </>}
    {(delivery.failed > 0 || delivery.expired > 0) && <p role="status">A notification did not complete successfully. This remains visible even after the alert condition resolves.</p>}
    {state.muted_until_ms !== null && state.muted_until_ms > Date.now() && delivery.leased > 0 && <p role="status">One notification may still arrive.</p>}
  </section>;
}

export function AlertEvidence({ capsule }: { capsule: AlertTriggerCapsule }) {
  const { evaluation, evidence, rule } = capsule;
  const value = evidence.number_value ?? evidence.state_value ?? evidence.boolean_value;
  return <section aria-labelledby="alert-trigger-evidence">
    <h3 id="alert-trigger-evidence">Original trigger evidence</h3>
    <p>This saved evidence describes the alert when it fired. Current condition and delivery status are shown separately.</p>
    <dl className="status-grid">
      <div><dt>Fired</dt><dd>{date(evaluation.event_ms)}</dd></div>
      <div><dt>Observation</dt><dd>{date(evidence.observed_ms)}</dd></div>
      <div><dt>Measured value</dt><dd>{value === null ? "Unavailable" : String(value)} {evidence.unit}</dd></div>
      <div><dt>Evidence quality</dt><dd>{evidence.quality}</dd></div>
      <div><dt>Observed trigger dwell</dt><dd>{evaluation.observed_dwell_ms / 1000} seconds</dd></div>
      <div><dt>Rule revision</dt><dd>{rule.version}</dd></div>
    </dl>
    <p>Evidence window: {date(evidence.window_start_ms)} to {date(evidence.window_end_ms)} (end excluded).</p>
    {evidence.valid_n !== null && <p>{evidence.valid_n} valid duration samples from {evidence.completed_n === null ? "an unavailable count of" : evidence.completed_n} completed requests in the selected population.</p>}
    {evidence.gaps.length > 0 && <><h4>Captured gaps</h4><ul>{evidence.gaps.map((gap, index) => <li key={index}>{date(gap.start_ms)} to {date(gap.end_ms)}: {gap.reason}</li>)}</ul></>}
    {evidence.unavailable_reasons.length > 0 && <><h4>Evidence limits</h4><ul>{evidence.unavailable_reasons.map((reason, index) => <li key={index}>{reason}</li>)}</ul></>}
    <details><summary>Trigger calculation and sources</summary>
      <dl>
        <dt>Metric</dt><dd>{evidence.metric_id}</dd>
        <dt>Definition</dt><dd>{evidence.definition_revision}</dd>
        <dt>Collection method</dt><dd>{evidence.method_revision}</dd>
        <dt>Transition</dt><dd>{evaluation.previous_state} → {evaluation.new_state}</dd>
        <dt>Trigger predicate</dt><dd>{evaluation.predicate}: {evaluation.reason}</dd>
        <dt>Evidence SHA-256</dt><dd><code>{evaluation.evidence_sha256}</code></dd>
      </dl>
      <p>{evidence.source_samples.length} of {evidence.source_sample_count} source sample identities retained{evidence.source_samples_truncated ? "; identity list truncated to the protected evidence limit" : ""}.</p>
      {evidence.source_samples.length === 0 && !evidence.status_sample && <p>No collector sample identity is retained in this capsule.</p>}
      {evidence.status_sample && <section aria-label="Collector heartbeat evidence">
        <h4>Collector heartbeat evidence</h4>
        <p>Host <code>{evidence.status_sample.host_id}</code>, boot <code>{evidence.status_sample.collector_boot_id}</code>, session {evidence.status_sample.session_generation}, status sequence {evidence.status_sample.sequence}.</p>
        <p>Observed {date(evidence.status_sample.observed_ms)}; received {date(evidence.status_sample.admitted_ms)}.</p>
        <p>Status SHA-256: <code>{evidence.status_sample.payload_sha256}</code>.</p>
      </section>}
      {evidence.status_absence && <p>No status record had been received for host <code>{evidence.status_absence.host_id}</code>, session {evidence.status_absence.session_generation}, as checked at {date(evidence.status_absence.checked_ms)}. This does not establish healthy monitoring.</p>}
      {evidence.source_samples.map(sample => <div key={`${sample.collector_boot_id}/${sample.source_id}/${sample.sequence}`}>
        <p>Source <code>{sample.source_id}</code>, boot <code>{sample.collector_boot_id}</code>, sequence {sample.sequence}.</p>
        <p>Configuration identities: {sample.config_ids.length ? sample.config_ids.join(", ") : "not captured"}.</p>
      </div>)}
      {evidence.request_sample_count > 0 && <>
        <p>{evidence.request_sample_ids.length} of {evidence.request_sample_count} request sample identities retained{evidence.request_samples_truncated ? "; identity list truncated to the protected evidence limit" : ""}.</p>
        <ul>{evidence.request_sample_ids.map(id => <li key={id}><code>{id}</code></li>)}</ul>
      </>}
    </details>
  </section>;
}
function date(value: number) { return new Date(value).toISOString(); }

function deliveryStatusLabel(status: AlertIncidentState["deliveries"][number]["status"]) {
  return status === "terminal_failure" ? "Terminal failure" : status.replaceAll("_", " ").replace(/^[a-z]/, (value) => value.toUpperCase());
}
