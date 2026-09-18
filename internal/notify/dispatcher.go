package notify

import (
	"context"
	"time"

	"rmt.local/monitor/internal/store"
)

// Dispatcher is the hub-owned worker for durable notification deliveries. It
// claims the exact destination revision and secret reference that the outbox
// recorded, then commits the transport result back to the same row.
type Dispatcher struct {
	store        *store.Store
	vault        Vault
	transport    Transport
	pollInterval time.Duration
	onError      func(error)
}

func NewDispatcher(st *store.Store, vault Vault, onError func(error)) *Dispatcher {
	return &Dispatcher{store: st, vault: vault, transport: Transport{}, pollInterval: 500 * time.Millisecond, onError: onError}
}

// NewDispatcherWithTransport keeps the production dispatcher on the operating
// system trust store while allowing package integration tests to provide a
// process-scoped certificate pool and clock.
func NewDispatcherWithTransport(st *store.Store, vault Vault, transport Transport, onError func(error)) *Dispatcher {
	return &Dispatcher{store: st, vault: vault, transport: transport, pollInterval: 500 * time.Millisecond, onError: onError}
}

func (d *Dispatcher) Run(ctx context.Context) {
	if d == nil || d.store == nil {
		return
	}
	d.dispatch(ctx)
	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.dispatch(ctx)
		}
	}
}

func (d *Dispatcher) dispatch(ctx context.Context) {
	state, err := d.store.DeploymentState(ctx)
	if err != nil {
		d.report(err)
		return
	}
	lease, err := d.store.ClaimNotificationDelivery(ctx, state.DeploymentID, state.DeploymentGeneration)
	if err != nil {
		d.report(err)
		return
	}
	if lease == nil {
		return
	}

	result := Result{Permanent: true, SafeCode: "notification_secret_unavailable"}
	secret := ""
	secretErr := error(nil)
	if lease.SecretRef != "" {
		secret, secretErr = d.vault.Read(lease.SecretRef)
	}
	if secretErr == nil {
		result = d.transport.Send(ctx, lease.Kind, lease.Config, secret, lease.Payload, lease.IdempotencyKey)
	}
	_, err = d.store.CompleteNotificationDelivery(ctx, store.DeliveryCompletion{
		ID:              lease.ID,
		ExpectedAttempt: lease.Attempts,
		LeaseToken:      lease.LeaseToken,
		Succeeded:       result.Succeeded,
		Permanent:       result.Permanent,
		SafeCode:        result.SafeCode,
		RetryAfter:      result.RetryAfter,
		ReceiverACKMS:   result.ReceiverACKMS,
	})
	if err != nil {
		d.report(err)
	}
}

func (d *Dispatcher) report(err error) {
	if d.onError != nil && err != nil {
		d.onError(err)
	}
}
