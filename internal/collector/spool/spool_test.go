package spool

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const testID = "11111111-1111-4111-8111-111111111111"
const nextBoot = "22222222-2222-4222-8222-222222222222"

func sample(at time.Time, sequence uint64) Record {
	return Record{DeploymentID: testID, Generation: testID, SessionGeneration: 1, HostID: testID, BootID: testID, SourceID: testID, Sequence: sequence, ObservedMS: at.UnixMilli(), Payload: []byte("canonical-frame")}
}

func TestQuarantineSurvivesRestartWithoutAckOrPoisonRetry(t *testing.T) {
	now := time.Unix(1700000000, 0)
	dir := t.TempDir()
	s := openTest(t, dir, &now, 0)
	if err := s.Append(sample(now, 1)); err != nil {
		t.Fatal(err)
	}
	pending, err := s.ReadPending(testID, testID, true, 1<<20, 64)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Quarantine(pending.Cursor, "invalid_frame"); err != nil {
		t.Fatal(err)
	}
	if err := s.Ack(pending.Cursor); !errors.Is(err, ErrCursor) {
		t.Fatal("quarantined evidence was ACKed")
	}
	_ = s.Close()
	s = openTest(t, dir, &now, 0)
	if s.QuarantinedSegments() != 1 || len(s.segments) != 1 || s.segments[0].ack != 0 {
		t.Fatal("quarantine lost original unacknowledged bytes")
	}
	pending, err = s.ReadPending(testID, testID, true, 1<<20, 64)
	if err != nil || len(pending.Records) != 0 {
		t.Fatal("poison retried after restart")
	}
	if err := s.Append(sample(now, 2)); err != nil {
		t.Fatal(err)
	}
	pending, err = s.ReadPending(testID, testID, true, 1<<20, 64)
	if err != nil || len(pending.Records) != 1 || pending.Records[0].Sequence != 2 {
		t.Fatal("quarantine blocked new current frames")
	}
	now = now.Add(MaxAge)
	if _, err := s.ReadPending(testID, testID, false, 1<<20, 64); err != nil {
		t.Fatal(err)
	}
	losses, _ := s.Losses()
	if len(losses) != 1 || losses[0].Count != 2 || losses[0].Reason != "spool_age" {
		t.Fatal("expired quarantine did not record explicit loss")
	}
}

func TestOwnedPurgeRequiresStoppedCollectorAndPreservesUnknownNeighbor(t *testing.T) {
	now := time.Unix(1700000000, 0)
	dir := filepath.Join(t.TempDir(), "spool")
	s := openTest(t, dir, &now, 0)
	if err := s.Append(sample(now, 1)); err != nil {
		t.Fatal(err)
	}
	if err := RemoveOwned(context.Background(), dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("live spool removed: %v", err)
	}
	_ = s.Close()
	neighbor := filepath.Join(dir, "user-notes.txt")
	if err := os.WriteFile(neighbor, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveOwned(context.Background(), dir); err == nil {
		t.Fatal("unknown neighbor permitted successful purge")
	}
	content, _ := os.ReadFile(neighbor)
	if string(content) != "preserve" {
		t.Fatal("neighbor changed")
	}
	if err := os.Remove(neighbor); err != nil {
		t.Fatal(err)
	} // Remove only this test's own fixture.
	if err := RemoveOwned(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("known spool data retained after explicit purge")
	}
}

func openTest(t *testing.T, dir string, now *time.Time, size int64) *Spool {
	t.Helper()
	s, err := Open(dir, Options{Bytes: size, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestCrashReplayAndDurableAck(t *testing.T) {
	now := time.Unix(1700000000, 0)
	dir := t.TempDir()
	s := openTest(t, dir, &now, 0)
	if err := s.Append(sample(now, 1)); err != nil {
		t.Fatal(err)
	}
	first, err := s.ReadPending(testID, testID, true, 1<<20, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Records) != 1 {
		t.Fatalf("pending=%+v", first)
	}
	_ = s.Close() // A lost network ACK must leave the original frame intact.
	s = openTest(t, dir, &now, 0)
	replay, err := s.ReadPending(nextBoot, testID, false, 1<<20, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(replay.Records) != 1 || replay.Records[0].BootID != testID || replay.Records[0].Sequence != 1 {
		t.Fatalf("original identity lost: %+v", replay)
	}
	if err := s.Ack(first.Cursor); !errors.Is(err, ErrCursor) {
		t.Fatalf("accepted cursor from closed instance: %v", err)
	}
	if err := s.Ack(replay.Cursor); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = openTest(t, dir, &now, 0)
	replay, err = s.ReadPending(nextBoot, testID, false, 1<<20, 64)
	if err != nil || len(replay.Records) != 0 {
		t.Fatalf("ACK not durable: %+v %v", replay, err)
	}
}

func TestIncompleteTailOnlyIsTruncated(t *testing.T) {
	now := time.Unix(1700000000, 0)
	dir := t.TempDir()
	s := openTest(t, dir, &now, 0)
	if err := s.Append(sample(now, 1)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, s.segments[0].name)
	validSize := s.segments[0].size
	_ = s.Close()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write([]byte("RMT1\x00"))
	_ = f.Close()
	s = openTest(t, dir, &now, 0)
	if s.segments[0].size != validSize {
		t.Fatal("complete record was lost")
	}
	info, _ := os.Stat(path)
	if info.Size() != validSize {
		t.Fatal("partial tail not truncated")
	}
	_ = s.Close()
	f, _ = os.OpenFile(path, os.O_WRONLY, 0)
	_, _ = f.WriteAt([]byte{0xff}, headerBytes)
	_ = f.Close()
	if _, err := Open(dir, Options{}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt complete record accepted: %v", err)
	}
	info, _ = os.Stat(path)
	if info.Size() != validSize {
		t.Fatal("corruption discarded evidence")
	}
}

func TestOldSameBootReplayDoesNotBlockCurrent(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := openTest(t, t.TempDir(), &now, 0)
	if err := s.Append(sample(now, 1)); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := s.Append(sample(now, 2)); err != nil {
		t.Fatal(err)
	}
	current, err := s.ReadPending(testID, testID, true, 1<<20, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Records) != 1 || current.Records[0].Sequence != 2 {
		t.Fatalf("backlog blocked current: %+v", current)
	}
	if err := s.Ack(current.Cursor); err != nil {
		t.Fatal(err)
	}
	old, err := s.ReadPending(testID, testID, false, 1<<20, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(old.Records) != 1 || old.Records[0].Sequence != 1 {
		t.Fatalf("same boot backlog not replayed: %+v", old)
	}
}

func TestCapacityAndAgeLossRemainUntilControlAck(t *testing.T) {
	now := time.Unix(1700000000, 0)
	dir := t.TempDir()
	s := openTest(t, dir, &now, maxRecordBytes)
	one := sample(now, 1)
	one.Payload = bytes.Repeat([]byte("x"), MaxFrameBytes)
	if err := s.Append(one); err != nil {
		t.Fatal(err)
	}
	two := one
	two.Sequence = 2
	if err := s.Append(two); err != nil {
		t.Fatal(err)
	}
	losses, revision := s.Losses()
	if len(losses) != 1 || losses[0].Reason != "spool_capacity" || losses[0].Count != 1 {
		t.Fatalf("loss not recorded: %+v", losses)
	}
	_ = s.Close()
	s = openTest(t, dir, &now, maxRecordBytes)
	losses, again := s.Losses()
	if len(losses) != 1 || again != revision {
		t.Fatal("loss not durable")
	}
	now = now.Add(MaxAge)
	if _, err := s.ReadPending(testID, testID, false, 1<<20, 64); err != nil {
		t.Fatal(err)
	}
	if err := s.AckLosses(revision); !errors.Is(err, ErrCursor) {
		t.Fatal("stale control ACK erased a new loss")
	}
	losses, revision = s.Losses()
	if len(losses) != 2 {
		t.Fatalf("age loss missing: %+v", losses)
	}
	if err := s.AckLosses(revision); err != nil {
		t.Fatal(err)
	}
	losses, _ = s.Losses()
	if len(losses) != 0 {
		t.Fatal("control ACK failed")
	}
}

func TestBoundedLossPrefixACKLeavesRemainingIntervals(t *testing.T) {
	now := time.Unix(1700000000, 0)
	s := openTest(t, t.TempDir(), &now, 0)
	s.losses.Revision = 7
	s.losses.Losses = make([]Loss, 17)
	for index := range s.losses.Losses {
		s.losses.Losses[index] = Loss{SourceID: testID, StartMS: int64(index), EndMS: int64(index), Count: 1, Reason: "spool_capacity"}
	}
	if err := s.AckLossesPrefix(7, 16); err != nil {
		t.Fatal(err)
	}
	losses, revision := s.Losses()
	if revision != 8 || len(losses) != 1 || losses[0].StartMS != 16 {
		t.Fatalf("remaining loss state = revision %d, %+v", revision, losses)
	}
	if err := s.AckLossesPrefix(7, 1); !errors.Is(err, ErrCursor) {
		t.Fatal("stale prefix ACK erased retained evidence")
	}
}

func TestInterruptedEvictionDoesNotDoubleCount(t *testing.T) {
	now := time.Unix(1700000000, 0)
	dir := t.TempDir()
	s := openTest(t, dir, &now, 0)
	if err := s.Append(sample(now, 1)); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after loss journal fsync but before segment unlink.
	if err := s.recordSegmentLoss(s.segments[0], "spool_capacity"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s = openTest(t, dir, &now, 0)
	losses, _ := s.Losses()
	if len(losses) != 1 || losses[0].Count != 1 {
		t.Fatalf("loss counted twice: %+v", losses)
	}
	pending, err := s.ReadPending(testID, testID, true, 1<<20, 64)
	if err != nil || len(pending.Records) != 0 {
		t.Fatalf("eviction not recovered: %+v %v", pending, err)
	}
}

func TestExclusiveLockAndSymlinkRefusal(t *testing.T) {
	now := time.Unix(1700000000, 0)
	dir := t.TempDir()
	s := openTest(t, dir, &now, 0)
	if _, err := Open(dir, Options{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second collector acquired spool: %v", err)
	}
	_ = s.Close()
	if err := os.Remove(filepath.Join(dir, "offsets.json")); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(other, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "offsets.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{}); err == nil {
		t.Fatal("symlink accepted")
	}
	got, _ := os.ReadFile(other)
	if string(got) != "evidence" {
		t.Fatal("unrelated symlink target changed")
	}
}
