package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

func recoveryDefinitions(sourceIDs ...string) protocol.RecoveryDefinitions {
	sources := make([]protocol.InventorySource, 0, len(sourceIDs))
	for _, sourceID := range sourceIDs {
		sources = append(sources, protocol.InventorySource{SourceID: sourceID, Kind: "host", CapabilityRevision: domain.RegistryRevision, Active: false})
	}
	return protocol.RecoveryDefinitions{HistoricalOnly: true, Sources: sources, Targets: []protocol.InventoryTarget{}, Models: []protocol.InventoryModel{}}
}

func previewRecovery(t *testing.T, spool *Spool, now time.Time, sourceIDs ...string) protocol.RecoveryManifest {
	t.Helper()
	manifest, err := spool.PreviewRecovery(RecoveryPreviewOptions{
		DeploymentID:               testID,
		HostID:                     testID,
		OriginalSecurityGeneration: testID,
		OriginalCollectorBootID:    testID,
		CreatedMS:                  now.Add(time.Second).UnixMilli(),
		Definitions:                recoveryDefinitions(sourceIDs...),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func recoveryGrant(t *testing.T, manifest protocol.RecoveryManifest, now time.Time) protocol.RecoveryGrant {
	t.Helper()
	approved := make([]protocol.ApprovedRecoverySegment, 0, len(manifest.Segments))
	for _, segment := range manifest.Segments {
		approved = append(approved, protocol.ApprovedRecoverySegment{SourceID: segment.SourceID, FromSequence: segment.FromSequence, ToSequence: segment.ToSequence, SegmentSHA256: segment.SegmentSHA256})
	}
	grant := protocol.RecoveryGrant{
		SchemaVersion: domain.SchemaVersion, GrantID: nextBoot, DeploymentID: testID, HostID: testID,
		CurrentSecurityGeneration: nextBoot, OriginalSecurityGeneration: testID, OriginalCollectorBootID: testID,
		ManifestSHA256: manifest.ManifestSHA256, ApprovedSegments: approved, MaxBytes: manifest.TotalBytes,
		MaxFrames: manifest.TotalFrames, IssuedMS: now.UnixMilli(), ExpiresMS: now.Add(time.Hour).UnixMilli(),
	}
	var err error
	grant.GrantSHA256, err = protocol.CanonicalRecoveryGrantHash(grant)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func fileHashes(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		result[entry.Name()] = hex.EncodeToString(sum[:])
	}
	return result
}

func TestRecoveryPreviewIsReadOnlyAndSegmentsBounded(t *testing.T) {
	now := time.Unix(1_789_473_600, 0)
	dir := t.TempDir()
	spool := openTest(t, dir, &now, 8<<20)
	payload := bytes.Repeat([]byte("x"), 128<<10)
	for sequence := uint64(1); sequence <= 8; sequence++ {
		record := sample(now.Add(time.Duration(sequence)*time.Millisecond), sequence)
		record.Payload = payload
		if err := spool.Append(record); err != nil {
			t.Fatal(err)
		}
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	before := fileHashes(t, dir)
	spool, err := OpenReadOnly(dir, Options{Bytes: 8 << 20, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	manifest := previewRecovery(t, spool, now, testID)
	after := fileHashes(t, dir)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("preview changed retained spool bytes or journals")
	}
	if manifest.TotalFrames != 8 || manifest.TotalBytes != int64(8*len(payload)) || len(manifest.Segments) != 2 {
		t.Fatalf("unexpected bounded preview metadata: %#v", manifest)
	}
	for index, segment := range manifest.Segments {
		wantFrom := int64(index*protocol.MaxRecoverySegmentFrames + 1)
		if segment.FromSequence != wantFrom || segment.ToSequence != wantFrom+3 || segment.FrameCount != protocol.MaxRecoverySegmentFrames || segment.Bytes != int64(protocol.MaxRecoverySegmentFrames*len(payload)) {
			t.Fatalf("unexpected streamed segment %d: %#v", index, segment)
		}
	}
	if err := spool.Close(); err != nil {
		t.Fatal(err)
	}
	spool, err = Open(dir, Options{Bytes: 8 << 20, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer spool.Close()
	grant := recoveryGrant(t, manifest, now)
	pending, err := spool.ReadRecovery(grant, int(protocol.MaxRecoverySegmentBytes), protocol.MaxRecoveryReplayFrames)
	if err != nil || len(pending.Records) != protocol.MaxRecoveryReplayFrames || pending.Records[0].Sequence != 1 || pending.Records[3].Sequence != 4 {
		t.Fatalf("reviewed recovery grant did not admit one complete physical segment: records=%d err=%v", len(pending.Records), err)
	}
	altered := grant
	altered.ApprovedSegments = append([]protocol.ApprovedRecoverySegment(nil), grant.ApprovedSegments...)
	prefix := "f"
	if altered.ApprovedSegments[0].SegmentSHA256[0] == 'f' {
		prefix = "e"
	}
	altered.ApprovedSegments[0].SegmentSHA256 = prefix + altered.ApprovedSegments[0].SegmentSHA256[1:]
	altered.GrantSHA256, err = protocol.CanonicalRecoveryGrantHash(altered)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := spool.ReadRecovery(altered, int(protocol.MaxRecoverySegmentBytes), protocol.MaxRecoveryReplayFrames); err == nil {
		t.Fatal("grant whose reviewed segment hash conflicts with retained bytes was accepted")
	}
}

func TestRecoveryReadOnlyOpenRefusesRepairAndDoesNotPruneExpiredEvidence(t *testing.T) {
	now := time.Unix(1_789_473_600, 0)
	dir := t.TempDir()
	writable := openTest(t, dir, &now, 8<<20)
	if err := writable.Append(sample(now, 1)); err != nil {
		t.Fatal(err)
	}
	if err := writable.Close(); err != nil {
		t.Fatal(err)
	}
	now = now.Add(MaxAge + time.Second)
	before := fileHashes(t, dir)
	readOnly, err := OpenReadOnly(dir, Options{Bytes: 8 << 20, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readOnly.PreviewRecovery(RecoveryPreviewOptions{DeploymentID: testID, HostID: testID, OriginalSecurityGeneration: testID, OriginalCollectorBootID: testID, CreatedMS: now.UnixMilli(), Definitions: recoveryDefinitions(testID)}); err == nil {
		t.Fatal("expired retained evidence was presented as eligible")
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}
	if after := fileHashes(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("read-only preview pruned expired evidence")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var segmentPath string
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) == ".seg" {
			segmentPath = filepath.Join(dir, entry.Name())
			break
		}
	}
	file, err := os.OpenFile(segmentPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("torn-tail")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	tornBefore := fileHashes(t, dir)
	if candidate, err := OpenReadOnly(dir, Options{Bytes: 8 << 20, Now: func() time.Time { return now }}); err == nil {
		candidate.Close()
		t.Fatal("read-only preview repaired or accepted a torn tail")
	}
	if after := fileHashes(t, dir); !reflect.DeepEqual(tornBefore, after) {
		t.Fatal("read-only open changed torn-tail evidence")
	}
}

func TestRecoveryPreviewPreservesPhysicalInterleavingAndACKPrefix(t *testing.T) {
	now := time.Unix(1_789_473_600, 0)
	spool := openTest(t, t.TempDir(), &now, 8<<20)
	sources := []string{testID, nextBoot, testID, nextBoot}
	for index, sourceID := range sources {
		record := sample(now.Add(time.Duration(index)*time.Millisecond), uint64(index/2+1))
		record.SourceID = sourceID
		record.Payload = []byte{byte(index + 1)}
		if err := spool.Append(record); err != nil {
			t.Fatal(err)
		}
	}
	manifest := previewRecovery(t, spool, now, testID, nextBoot)
	if len(manifest.Segments) != 4 {
		t.Fatalf("interleaved physical runs were merged: %#v", manifest.Segments)
	}
	grant := recoveryGrant(t, manifest, now)
	pending, err := spool.ReadRecovery(grant, int(protocol.MaxRecoverySegmentBytes), protocol.MaxRecoveryReplayFrames)
	if err != nil || len(pending.Records) != 4 {
		t.Fatalf("interleaved physical prefix unavailable: records=%d err=%v", len(pending.Records), err)
	}
	for index, record := range pending.Records {
		if record.SourceID != sources[index] {
			t.Fatalf("physical order changed at %d: got=%s want=%s", index, record.SourceID, sources[index])
		}
	}
	fixture, err := os.Open(filepath.Join("..", "..", "..", "fixtures", "contracts", "valid", "recovery-replay.json"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := protocol.DecodeRecoveryReplay(fixture)
	fixture.Close()
	if err != nil {
		t.Fatal(err)
	}
	replay := base
	replay.GrantID, replay.GrantSHA256 = grant.GrantID, grant.GrantSHA256
	replay.ReplayRequestID = "33333333-3333-4333-8333-333333333333"
	replay.AdmittingSecurityGeneration, replay.AdmittingCollectorBootID = nextBoot, nextBoot
	replay.DeploymentID, replay.HostID = testID, testID
	replay.OriginalSecurityGeneration, replay.OriginalCollectorBootID = testID, testID
	replay.Frames = make([]protocol.RecoveryFrame, 0, len(pending.Records))
	receipts := make([]protocol.RecoveryReceipt, 0, len(pending.Records))
	for _, record := range pending.Records {
		frame := base.Frames[0].Frame
		frame.SourceID, frame.Sequence, frame.ObservedWallMS = record.SourceID, int64(record.Sequence), record.ObservedMS
		hash := sha256.Sum256(record.Payload)
		payloadHash := hex.EncodeToString(hash[:])
		replay.Frames = append(replay.Frames, protocol.RecoveryFrame{OriginalSourceID: record.SourceID, OriginalSequence: int64(record.Sequence), OriginalObservedMS: record.ObservedMS, OriginalPayloadSHA256: payloadHash, Frame: frame})
		receipts = append(receipts, protocol.RecoveryReceipt{OriginalCollectorBootID: testID, OriginalSourceID: record.SourceID, OriginalSequence: int64(record.Sequence), OriginalPayloadSHA256: payloadHash, Disposition: "recovered"})
	}
	replay.ScopeSHA256, err = protocol.CanonicalRecoveryScopeHash(replay)
	if err != nil {
		t.Fatal(err)
	}
	ack := protocol.RecoveryACK{GrantID: grant.GrantID, GrantSHA256: grant.GrantSHA256, ReplayRequestID: replay.ReplayRequestID, ScopeSHA256: replay.ScopeSHA256, Durable: true, Accepted: len(receipts), Receipts: receipts, Complete: true, HubTimeMS: now.UnixMilli()}
	if err := spool.AckRecovery(pending, replay, ack); err != nil {
		t.Fatal(err)
	}
	remaining, err := spool.ReadRecovery(grant, int(protocol.MaxRecoverySegmentBytes), protocol.MaxRecoveryReplayFrames)
	if err != nil || len(remaining.Records) != 0 {
		t.Fatalf("ACK did not advance the exact physical prefix: records=%d err=%v", len(remaining.Records), err)
	}
}

func TestRecoveryPreviewSplitsCrossFileRunAndRefusesOversizedTransfer(t *testing.T) {
	now := time.Unix(1_789_473_600, 0)
	spool := openTest(t, t.TempDir(), &now, 8<<20)
	first := sample(now, 1)
	first.Payload = bytes.Repeat([]byte("a"), 64<<10)
	second := sample(now.Add(6*time.Second), 2)
	second.Payload = bytes.Repeat([]byte("b"), 64<<10)
	if err := spool.Append(first); err != nil {
		t.Fatal(err)
	}
	if err := spool.Append(second); err != nil {
		t.Fatal(err)
	}
	manifest := previewRecovery(t, spool, now.Add(6*time.Second), testID)
	if len(manifest.Segments) != 2 || manifest.Segments[0].FrameCount != 1 || manifest.Segments[1].FrameCount != 1 {
		t.Fatalf("cross-file run was not split at durable cursor boundaries: %#v", manifest.Segments)
	}
	grant := recoveryGrant(t, manifest, now.Add(6*time.Second))
	if _, err := spool.ReadRecovery(grant, len(first.Payload)-1, protocol.MaxRecoveryReplayFrames); err == nil {
		t.Fatal("complete reviewed segment larger than the transfer bound was split or admitted")
	}
}

func TestRecoveryPreviewVirtuallyPrunesExpiredPhysicalPrefix(t *testing.T) {
	for _, test := range []struct {
		name         string
		secondOffset time.Duration
	}{
		{name: "wholly expired file", secondOffset: time.Second},
		{name: "mixed age file follows first observation expiry", secondOffset: 4 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := time.Unix(1_789_473_600, 0)
			now := base
			dir := t.TempDir()
			options := Options{Bytes: 8 << 20, Age: 5 * time.Second, Now: func() time.Time { return now }}
			queue, err := Open(dir, options)
			if err != nil {
				t.Fatal(err)
			}
			for sequence, at := range []time.Time{base, base.Add(test.secondOffset), base.Add(6 * time.Second)} {
				if err := queue.Append(sample(at, uint64(sequence+1))); err != nil {
					queue.Close()
					t.Fatal(err)
				}
			}
			if len(queue.segments) != 2 {
				queue.Close()
				t.Fatalf("fixture did not create two physical files: %#v", queue.segments)
			}
			if err := queue.Close(); err != nil {
				t.Fatal(err)
			}

			now = base.Add(7 * time.Second)
			before := fileHashes(t, dir)
			queue, err = OpenReadOnly(dir, options)
			if err != nil {
				t.Fatal(err)
			}
			manifest := previewRecovery(t, queue, now, testID)
			if manifest.TotalFrames != 1 || len(manifest.Segments) != 1 || manifest.Segments[0].FromSequence != 3 || len(manifest.LossIntervals) != 1 || manifest.LossIntervals[0].LostCount != 2 || manifest.LossIntervals[0].Reason != "spool_age" {
				queue.Close()
				t.Fatalf("virtual age prune manifest=%#v", manifest)
			}
			if err := queue.Close(); err != nil {
				t.Fatal(err)
			}
			if after := fileHashes(t, dir); !reflect.DeepEqual(before, after) {
				t.Fatal("virtual age prune changed raw spool bytes or journals")
			}

			queue, err = Open(dir, options)
			if err != nil {
				t.Fatal(err)
			}
			defer queue.Close()
			if len(queue.losses.Losses) != 1 || queue.losses.Losses[0].Count != 2 || queue.losses.Losses[0].Reason != manifest.LossIntervals[0].Reason || queue.losses.Losses[0].StartMS != manifest.LossIntervals[0].StartMS || queue.losses.Losses[0].EndMS != manifest.LossIntervals[0].EndMS {
				t.Fatalf("writable age prune diverged from preview: ledger=%#v manifest=%#v", queue.losses.Losses, manifest.LossIntervals)
			}
			grant := recoveryGrant(t, manifest, now)
			pending, err := queue.ReadRecovery(grant, int(protocol.MaxRecoverySegmentBytes), protocol.MaxRecoveryReplayFrames)
			if err != nil || len(pending.Records) != 1 || pending.Records[0].Sequence != 3 {
				t.Fatalf("grant could not read eligible prefix after exact age prune: pending=%#v err=%v", pending, err)
			}
		})
	}
}

func TestRecoveryPreviewDoesNotSkipEligibleUnapprovedPrefix(t *testing.T) {
	now := time.Unix(1_789_473_600, 0)
	dir := t.TempDir()
	queue := openTest(t, dir, &now, 8<<20)
	if err := queue.Append(sample(now, 1)); err != nil {
		t.Fatal(err)
	}
	if err := queue.Append(sample(now.Add(time.Second), 2)); err != nil {
		t.Fatal(err)
	}
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}
	before := fileHashes(t, dir)
	queue, err := OpenReadOnly(dir, Options{Bytes: 8 << 20, Now: func() time.Time { return now.Add(time.Second) }})
	if err != nil {
		t.Fatal(err)
	}
	defer queue.Close()
	from := uint64(2)
	_, err = queue.PreviewRecovery(RecoveryPreviewOptions{DeploymentID: testID, HostID: testID, OriginalSecurityGeneration: testID, OriginalCollectorBootID: testID, CreatedMS: now.Add(time.Second).UnixMilli(), Definitions: recoveryDefinitions(testID), FromSequence: &from})
	if err == nil {
		t.Fatal("preview skipped an eligible physical prefix outside the selected grant scope")
	}
	if after := fileHashes(t, dir); !reflect.DeepEqual(before, after) {
		t.Fatal("refused prefix selection changed spool bytes")
	}
}
