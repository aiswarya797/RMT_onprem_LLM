// Package spool retains collector frames until the hub acknowledges durable
// storage. Its private disk format is independent of the collector wire codec.
package spool

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"rmt.local/monitor/internal/config"
	"rmt.local/monitor/internal/domain"
)

const (
	MaxBytes        = 256 << 20
	MaxAge          = 24 * time.Hour
	MaxFrameBytes   = 256 << 10
	segmentBytes    = 4 << 20
	maxSegments     = 20000 // One five-second group per day, plus clock/restart churn.
	maxRecordBytes  = 352 << 10
	maxJournalBytes = 1 << 20
	headerBytes     = 40
)

var (
	ErrCorrupt  = errors.New("spool record or journal is corrupt; retained for inspection")
	ErrLocked   = errors.New("collector spool is already owned by another process")
	ErrCapacity = errors.New("spool cannot record another loss within its reserved journal")
	ErrCursor   = errors.New("spool acknowledgement does not match the pending prefix")
)

// Record keeps original ownership and time when replaying across collector
// restarts. Payload is an already validated, bounded canonical source frame.
type Record struct {
	DeploymentID      string `json:"deployment_id"`
	Generation        string `json:"security_generation"`
	SessionGeneration int64  `json:"session_generation"`
	HostID            string `json:"host_id"`
	BootID            string `json:"collector_boot_id"`
	SourceID          string `json:"source_id"`
	Sequence          uint64 `json:"sequence"`
	ObservedMS        int64  `json:"observed_ms"`
	Payload           []byte `json:"payload"`
}

type Loss struct {
	SourceID string `json:"source_id"`
	StartMS  int64  `json:"start_ms"`
	EndMS    int64  `json:"end_ms"`
	Count    uint64 `json:"lost_count"`
	Reason   string `json:"reason"`
}

type Options struct {
	// Lower limits support small deployments and deterministic capacity tests.
	Bytes int64
	Age   time.Duration
	Now   func() time.Time
}

type segment struct {
	name             string
	size, ack        int64
	firstMS          int64
	boot, generation string
}
type journal struct {
	Version     int               `json:"version"`
	Offsets     map[string]int64  `json:"offsets"`
	Quarantined map[string]string `json:"quarantined"`
}
type lossJournal struct {
	Version   int             `json:"version"`
	Revision  uint64          `json:"revision"`
	Losses    []Loss          `json:"losses"`
	Discarded map[string]bool `json:"discarded"`
}
type sealed struct {
	SHA256 string          `json:"sha256"`
	Data   json.RawMessage `json:"data"`
}

type Spool struct {
	mu          sync.Mutex
	dir         string
	lock        *os.File
	options     Options
	segments    []segment
	journal     journal
	losses      lossJournal
	active      string
	nextSegment uint64
	// At most four deployment-wide recovery grants may be active. A successful
	// streaming verification is retained only for this locked spool process so
	// each four-frame transfer does not rescan up to 256 MiB.
	recoveryVerified map[string]bool
	readOnly         bool
	closed           bool
	fault            error
}

// Cursor cannot be reconstructed from a hub-provided offset. A caller may
// acknowledge it only after checking the matching all-or-nothing durable ACK.
type Cursor struct {
	owner      *Spool
	segment    string
	start, end int64
}
type Pending struct {
	Records []Record
	Cursor  Cursor
	Bytes   int
}

func Open(dir string, options Options) (*Spool, error) {
	return open(dir, options, false)
}

// OpenReadOnly acquires the normal exclusive collector lock but never repairs,
// prunes, journals or otherwise changes spool bytes. A torn tail or unfinished
// prior deletion is reported for explicit recovery instead of being repaired
// as a side effect of preview.
func OpenReadOnly(dir string, options Options) (*Spool, error) {
	return open(dir, options, true)
}

func open(dir string, options Options, readOnly bool) (*Spool, error) {
	if options.Bytes == 0 {
		options.Bytes = MaxBytes
	}
	if options.Age == 0 {
		options.Age = MaxAge
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Bytes < maxRecordBytes || options.Bytes > MaxBytes || options.Age <= 0 || options.Age > MaxAge {
		return nil, fmt.Errorf("invalid spool limits")
	}
	if readOnly {
		if err := config.RejectSymlinkTree(dir); err != nil {
			return nil, err
		}
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return nil, errors.New("read-only spool directory is missing or not private")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Getuid() {
			return nil, errors.New("read-only spool directory is not owned by current user")
		}
	} else if err := config.EnsurePrivateDir(dir); err != nil {
		return nil, err
	}
	lockPath := filepath.Join(dir, "collector.lock")
	if err := config.RejectSymlinkTree(lockPath); err != nil {
		return nil, err
	}
	flags := os.O_RDWR
	if !readOnly {
		flags |= os.O_CREATE
	}
	lock, err := os.OpenFile(lockPath, flags, 0o600)
	if err != nil {
		return nil, err
	}
	if err = config.ValidatePrivateFile(lockPath); err != nil {
		lock.Close()
		return nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, ErrLocked
	}
	s := &Spool{dir: dir, lock: lock, options: options, journal: journal{Version: 1, Offsets: map[string]int64{}, Quarantined: map[string]string{}}, losses: lossJournal{Version: 1, Losses: []Loss{}, Discarded: map[string]bool{}}, recoveryVerified: map[string]bool{}, readOnly: readOnly}
	if err = s.recover(readOnly); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	_ = syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	return s.lock.Close()
}

func (s *Spool) ready() error {
	if s.closed {
		return os.ErrClosed
	}
	return s.fault
}

func (s *Spool) writable() error {
	if err := s.ready(); err != nil {
		return err
	}
	if s.readOnly {
		return errors.New("read-only spool inspection cannot mutate retained evidence")
	}
	return nil
}

func validID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func (r Record) validate() error {
	if !validID(r.DeploymentID) || !validID(r.Generation) || !validID(r.HostID) || !validID(r.BootID) || !validID(r.SourceID) || r.SessionGeneration < 1 || r.SessionGeneration > 1<<53-1 || r.ObservedMS < 0 || r.Sequence > 1<<53-1 || len(r.Payload) == 0 || len(r.Payload) > MaxFrameBytes {
		return fmt.Errorf("invalid spool frame metadata or size")
	}
	return nil
}

func (s *Spool) Append(record Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	if err := record.validate(); err != nil {
		return err
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if len(data) > maxRecordBytes {
		return fmt.Errorf("encoded spool record exceeds bound")
	}
	wireBytes := int64(headerBytes + len(data))
	if err := s.prune(wireBytes); err != nil {
		return err
	}
	var seg *segment
	if len(s.segments) > 0 {
		last := &s.segments[len(s.segments)-1]
		if last.name == s.active && last.size+wireBytes <= segmentBytes && last.boot == record.BootID && last.generation == record.Generation && record.ObservedMS >= last.firstMS && record.ObservedMS-last.firstMS < 5000 {
			seg = last
		}
	}
	if seg == nil {
		id, err := domain.NewUUID()
		if err != nil {
			return err
		}
		s.nextSegment++
		name := fmt.Sprintf("%019d-%s.seg", s.nextSegment, id)
		path := filepath.Join(s.dir, name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		if err = f.Sync(); err != nil {
			f.Close()
			return err
		}
		if err = f.Close(); err != nil {
			return err
		}
		if err = syncDir(s.dir); err != nil {
			return err
		}
		s.segments = append(s.segments, segment{name: name, firstMS: record.ObservedMS, boot: record.BootID, generation: record.Generation})
		s.active = name
		seg = &s.segments[len(s.segments)-1]
	}
	path := filepath.Join(s.dir, seg.name)
	if err := config.ValidatePrivateFile(path); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	header := make([]byte, headerBytes)
	copy(header, "RMT1")
	binary.BigEndian.PutUint32(header[4:8], uint32(len(data)))
	hash := sha256.Sum256(data)
	copy(header[8:], hash[:])
	_, err = f.Write(append(header, data...))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		s.fault = err
		return err
	} // Do not append behind a possibly incomplete record.
	seg.size += wireBytes
	return nil
}

// ReadPending returns a contiguous prefix of one segment and one boot. Current
// boot segments are selected newest first; callers drain these before replay.
// It never skips a record within a segment, so ACK cursors stay crash-safe.
func (s *Spool) ReadPending(boot, generation string, current bool, maxBytes, maxFrames int) (Pending, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return Pending{}, err
	}
	if maxBytes < MaxFrameBytes || maxBytes > 1<<20 || maxFrames < 1 || maxFrames > 64 {
		return Pending{}, fmt.Errorf("invalid pending limits")
	}
	if err := s.prune(0); err != nil {
		return Pending{}, err
	}
	for n := 0; n < len(s.segments); n++ {
		i := n
		if current {
			i = len(s.segments) - 1 - n
		}
		seg := s.segments[i]
		if s.journal.Quarantined[seg.name] != "" {
			continue
		}
		age := s.options.Now().UnixMilli() - seg.firstMS
		isCurrent := seg.boot == boot && age >= 0 && age <= 15000
		if seg.ack >= seg.size || seg.generation != generation || isCurrent != current {
			continue
		}
		f, err := os.Open(filepath.Join(s.dir, seg.name))
		if err != nil {
			return Pending{}, err
		}
		if _, err = f.Seek(seg.ack, io.SeekStart); err != nil {
			f.Close()
			return Pending{}, err
		}
		result := Pending{Records: []Record{}, Cursor: Cursor{owner: s, segment: seg.name, start: seg.ack, end: seg.ack}}
		for len(result.Records) < maxFrames {
			record, bytesRead, err := readRecord(f)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				f.Close()
				return Pending{}, err
			}
			if len(result.Records) > 0 && result.Bytes+len(record.Payload) > maxBytes {
				break
			}
			result.Records = append(result.Records, record)
			result.Bytes += len(record.Payload)
			result.Cursor.end += bytesRead
		}
		f.Close()
		return result, nil
	}
	return Pending{Records: []Record{}}, nil
}

func (s *Spool) Ack(cursor Cursor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	if cursor.owner != s {
		return ErrCursor
	}
	for i := range s.segments {
		seg := &s.segments[i]
		if seg.name != cursor.segment {
			continue
		}
		if s.journal.Quarantined[seg.name] != "" {
			return ErrCursor
		}
		if seg.ack == cursor.end {
			return nil
		}
		if seg.ack != cursor.start || cursor.end <= cursor.start || cursor.end > seg.size {
			return ErrCursor
		}
		s.journal.Offsets[seg.name] = cursor.end
		if err := writeSealed(filepath.Join(s.dir, "offsets.json"), s.journal); err != nil {
			s.fault = err
			return err
		}
		seg.ack = cursor.end
		return s.prune(0)
	}
	return ErrCursor
}

// Quarantine retains the segment without retrying poison or pretending the
// hub stored it. New segments continue. Normal bounded retention later emits
// an explicit loss if this retained evidence must be evicted.
func (s *Spool) Quarantine(cursor Cursor, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return err
	}
	if code != "invalid_frame" && code != "definition_incompatible" && code != "oversized_frame" {
		return errors.New("invalid quarantine code")
	}
	if cursor.owner != s {
		return ErrCursor
	}
	for _, seg := range s.segments {
		if seg.name != cursor.segment {
			continue
		}
		if seg.ack != cursor.start || cursor.end <= cursor.start || cursor.end > seg.size {
			return ErrCursor
		}
		s.journal.Quarantined[seg.name] = code
		if err := writeSealed(filepath.Join(s.dir, "offsets.json"), s.journal); err != nil {
			s.fault = err
			return err
		}
		if s.active == seg.name {
			s.active = ""
		}
		return nil
	}
	return ErrCursor
}

func (s *Spool) QuarantinedSegments() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.journal.Quarantined)
}

func (s *Spool) Losses() ([]Loss, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Loss(nil), s.losses.Losses...), s.losses.Revision
}

// AckLosses must follow the durable reserved-control-lane acknowledgement.
// A concurrent new loss invalidates this snapshot instead of erasing it.
func (s *Spool) AckLosses(revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackLossesPrefix(revision, len(s.losses.Losses))
}

// AckLossesPrefix removes only the bounded prefix included in a durable
// status acknowledgement. Remaining intervals stay queued for the next
// control-lane message instead of being starved behind the wire cap.
func (s *Spool) AckLossesPrefix(revision uint64, count int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackLossesPrefix(revision, count)
}

func (s *Spool) ackLossesPrefix(revision uint64, count int) error {
	if err := s.writable(); err != nil {
		return err
	}
	if revision != s.losses.Revision || count < 0 || count > len(s.losses.Losses) {
		return ErrCursor
	}
	next := lossJournal{Version: 1, Revision: revision + 1, Losses: append([]Loss(nil), s.losses.Losses[count:]...), Discarded: s.losses.Discarded}
	if err := writeSealed(filepath.Join(s.dir, "losses.json"), next); err != nil {
		return err
	}
	s.losses = next
	return nil
}

func readRecord(r io.Reader) (Record, int64, error) {
	header := make([]byte, headerBytes)
	_, err := io.ReadFull(r, header)
	if err != nil {
		return Record{}, 0, err
	}
	length := binary.BigEndian.Uint32(header[4:8])
	if string(header[:4]) != "RMT1" || length == 0 || length > maxRecordBytes {
		return Record{}, 0, ErrCorrupt
	}
	data := make([]byte, length)
	if _, err = io.ReadFull(r, data); err != nil {
		return Record{}, 0, err
	}
	hash := sha256.Sum256(data)
	if !bytes.Equal(hash[:], header[8:]) {
		return Record{}, 0, ErrCorrupt
	}
	var record Record
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&record); err != nil {
		return Record{}, 0, ErrCorrupt
	}
	if err = decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Record{}, 0, ErrCorrupt
	}
	if err = record.validate(); err != nil {
		return Record{}, 0, ErrCorrupt
	}
	return record, int64(headerBytes) + int64(length), nil
}

func writeSealed(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(data)
	encoded, err := json.Marshal(sealed{SHA256: hex.EncodeToString(hash[:]), Data: data})
	if err != nil {
		return err
	}
	if len(encoded) > maxJournalBytes {
		return ErrCapacity
	}
	return config.WritePrivateFile(path, encoded)
}

func readSealed(path string, value any) error {
	if err := config.ValidatePrivateFile(path); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxJournalBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxJournalBytes {
		return ErrCorrupt
	}
	var seal sealed
	if err := json.Unmarshal(data, &seal); err != nil {
		return ErrCorrupt
	}
	hash := sha256.Sum256(seal.Data)
	if seal.SHA256 != hex.EncodeToString(hash[:]) {
		return ErrCorrupt
	}
	decoder := json.NewDecoder(bytes.NewReader(seal.Data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrCorrupt
	}
	return nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (s *Spool) recover(readOnly bool) error {
	if readOnly {
		for _, name := range []string{"offsets.json", "losses.json"} {
			if err := config.ValidatePrivateFile(filepath.Join(s.dir, name)); err != nil {
				return fmt.Errorf("%w: recovery preview requires an intact %s", ErrCorrupt, name)
			}
		}
	}
	if err := readSealed(filepath.Join(s.dir, "offsets.json"), &s.journal); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if s.journal.Version != 1 || s.journal.Offsets == nil || len(s.journal.Offsets) > maxSegments {
		return ErrCorrupt
	}
	if s.journal.Quarantined == nil {
		s.journal.Quarantined = map[string]string{}
	}
	if len(s.journal.Quarantined) > maxSegments {
		return ErrCorrupt
	}
	if err := readSealed(filepath.Join(s.dir, "losses.json"), &s.losses); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if s.losses.Version != 1 || s.losses.Discarded == nil || len(s.losses.Discarded) > maxSegments {
		return ErrCorrupt
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	names := []string{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".seg") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	if len(names) > maxSegments {
		return ErrCorrupt
	}
	for i, name := range names {
		if len(name) != 60 || name[19] != '-' || !validID(name[20:56]) {
			return ErrCorrupt
		}
		serial, err := strconv.ParseUint(name[:19], 10, 64)
		if err != nil {
			return ErrCorrupt
		}
		if serial > s.nextSegment {
			s.nextSegment = serial
		}
		path := filepath.Join(s.dir, name)
		if err := config.ValidatePrivateFile(path); err != nil {
			return err
		}
		flags := os.O_RDONLY
		if !readOnly {
			flags = os.O_RDWR
		}
		f, err := os.OpenFile(path, flags, 0)
		if err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return err
		}
		if info.Size() > segmentBytes {
			f.Close()
			return ErrCorrupt
		}
		seg := segment{name: name, ack: s.journal.Offsets[name]}
		ackBoundary := seg.ack == 0
		for {
			record, n, readErr := readRecord(f)
			if errors.Is(readErr, io.EOF) {
				break
			}
			if errors.Is(readErr, io.ErrUnexpectedEOF) && i == len(names)-1 && seg.ack <= seg.size {
				if readOnly {
					f.Close()
					return fmt.Errorf("%w: torn spool tail requires explicit repair", ErrCorrupt)
				}
				if err := f.Truncate(seg.size); err != nil {
					f.Close()
					return err
				}
				if err := f.Sync(); err != nil {
					f.Close()
					return err
				}
				break
			}
			if readErr != nil {
				f.Close()
				return fmt.Errorf("%w: %s", ErrCorrupt, name)
			}
			if seg.size == 0 {
				seg.firstMS = record.ObservedMS
				seg.boot = record.BootID
				seg.generation = record.Generation
			}
			if seg.boot != record.BootID || seg.generation != record.Generation {
				f.Close()
				return ErrCorrupt
			}
			seg.size += n
			if seg.size == seg.ack {
				ackBoundary = true
			}
		}
		f.Close()
		if !ackBoundary || seg.ack < 0 || seg.ack > seg.size {
			return ErrCorrupt
		}
		s.segments = append(s.segments, seg)
	}
	// Finish any already journaled eviction without recounting its records.
	for _, seg := range append([]segment(nil), s.segments...) {
		if s.losses.Discarded[seg.name] {
			if readOnly {
				return fmt.Errorf("%w: journaled spool deletion requires explicit repair", ErrCorrupt)
			}
			if err := os.Remove(filepath.Join(s.dir, seg.name)); err != nil {
				return err
			}
			if err := syncDir(s.dir); err != nil {
				return err
			}
			for i := range s.segments {
				if s.segments[i].name == seg.name {
					s.segments = append(s.segments[:i], s.segments[i+1:]...)
					break
				}
			}
		}
	}
	live := map[string]bool{}
	for _, seg := range s.segments {
		live[seg.name] = true
	}
	for name := range s.journal.Offsets {
		if !live[name] {
			if readOnly {
				return fmt.Errorf("%w: stale spool offset requires explicit repair", ErrCorrupt)
			}
			delete(s.journal.Offsets, name)
		}
	}
	for name := range s.journal.Quarantined {
		if !live[name] {
			if readOnly {
				return fmt.Errorf("%w: stale spool quarantine requires explicit repair", ErrCorrupt)
			}
			delete(s.journal.Quarantined, name)
		}
	}
	for name := range s.losses.Discarded {
		if !live[name] {
			if readOnly {
				return fmt.Errorf("%w: stale spool loss marker requires explicit repair", ErrCorrupt)
			}
			delete(s.losses.Discarded, name)
		}
	}
	if readOnly {
		return nil
	}
	if err := writeSealed(filepath.Join(s.dir, "offsets.json"), s.journal); err != nil {
		return err
	}
	if err := writeSealed(filepath.Join(s.dir, "losses.json"), s.losses); err != nil {
		return err
	}
	// A missing file with a committed offset is a completed deletion; unacked
	// segments are never removed without first recording their loss separately.
	return s.prune(0)
}

func (s *Spool) prune(incoming int64) error {
	for {
		var used int64
		for _, seg := range s.segments {
			used += seg.size
		}
		index := -1
		reason := ""
		for i, seg := range s.segments {
			if seg.ack == seg.size {
				index = i
				break
			}
		}
		if index < 0 {
			for i, seg := range s.segments {
				if s.options.Now().UnixMilli()-seg.firstMS >= s.options.Age.Milliseconds() {
					index = i
					reason = "spool_age"
					break
				}
			}
		}
		if index < 0 && (used+incoming > s.options.Bytes || len(s.segments) >= maxSegments) && len(s.segments) > 0 {
			index = 0
			reason = "spool_capacity"
		}
		if index < 0 {
			return nil
		}
		seg := s.segments[index]
		if reason != "" {
			if err := s.recordSegmentLoss(seg, reason); err != nil {
				return err
			}
		}
		if err := os.Remove(filepath.Join(s.dir, seg.name)); err != nil {
			return err
		}
		if err := syncDir(s.dir); err != nil {
			s.fault = err
			return err
		}
		delete(s.journal.Offsets, seg.name)
		delete(s.journal.Quarantined, seg.name)
		if err := writeSealed(filepath.Join(s.dir, "offsets.json"), s.journal); err != nil {
			s.fault = err
			return err
		}
		s.segments = append(s.segments[:index], s.segments[index+1:]...)
		if s.active == seg.name {
			s.active = ""
		}
		delete(s.losses.Discarded, seg.name)
		if reason != "" {
			if err := writeSealed(filepath.Join(s.dir, "losses.json"), s.losses); err != nil {
				s.fault = err
				return err
			}
		}
	}
}

func (s *Spool) recordSegmentLoss(seg segment, reason string) error {
	if s.losses.Discarded[seg.name] {
		return nil
	}
	f, err := os.Open(filepath.Join(s.dir, seg.name))
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Seek(seg.ack, io.SeekStart); err != nil {
		return err
	}
	next := lossJournal{Version: 1, Revision: s.losses.Revision + 1, Losses: append([]Loss(nil), s.losses.Losses...), Discarded: map[string]bool{}}
	for name, discarded := range s.losses.Discarded {
		next.Discarded[name] = discarded
	}
	next.Discarded[seg.name] = true
	for {
		record, _, err := readRecord(f)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		index := -1
		for i, loss := range next.Losses {
			if loss.SourceID == record.SourceID && loss.Reason == reason {
				index = i
				break
			}
		}
		if index == -1 {
			next.Losses = append(next.Losses, Loss{SourceID: record.SourceID, StartMS: record.ObservedMS, EndMS: record.ObservedMS, Reason: reason})
			index = len(next.Losses) - 1
		}
		loss := &next.Losses[index]
		loss.Count++
		if record.ObservedMS < loss.StartMS {
			loss.StartMS = record.ObservedMS
		}
		if record.ObservedMS > loss.EndMS {
			loss.EndMS = record.ObservedMS
		}
	}
	if err := writeSealed(filepath.Join(s.dir, "losses.json"), next); err != nil {
		return err
	}
	s.losses = next
	return nil
}
