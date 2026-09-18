package spool

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"

	"rmt.local/monitor/internal/domain"
	"rmt.local/monitor/internal/protocol"
)

type RecoveryPreviewOptions struct {
	DeploymentID               string
	HostID                     string
	OriginalSecurityGeneration string
	OriginalCollectorBootID    string
	CreatedMS                  int64
	Definitions                protocol.RecoveryDefinitions
	SourceID                   string
	FromSequence               *uint64
	ToSequence                 *uint64
}

type RecoveryPending struct {
	Records []Record
	Cursor  Cursor
	Bytes   int
}

type recoveryRun struct {
	sourceID     string
	fromSequence uint64
	toSequence   uint64
	nextSequence uint64
	firstMS      int64
	lastMS       int64
	frameCount   int
	bytes        int64
	hasher       hash.Hash
}

func newRecoveryRun(record Record) *recoveryRun {
	return &recoveryRun{sourceID: record.SourceID, fromSequence: record.Sequence, toSequence: record.Sequence, nextSequence: record.Sequence, firstMS: record.ObservedMS, lastMS: record.ObservedMS, hasher: sha256.New()}
}

func writeRecoveryDescriptor(hasher hash.Hash, record Record) error {
	payloadHash := sha256.Sum256(record.Payload)
	return protocol.WriteRecoveryDescriptor(hasher, protocol.RecoveryDescriptor{SourceID: record.SourceID, Sequence: int64(record.Sequence), ObservedMS: record.ObservedMS, PayloadSHA256: hex.EncodeToString(payloadHash[:])})
}

func (run *recoveryRun) add(record Record) error {
	if record.SourceID != run.sourceID || record.Sequence != run.nextSequence {
		return errors.New("recovery run sequence mismatch")
	}
	if err := writeRecoveryDescriptor(run.hasher, record); err != nil {
		return err
	}
	run.toSequence = record.Sequence
	run.nextSequence = record.Sequence + 1
	run.frameCount++
	run.bytes += int64(len(record.Payload))
	if record.ObservedMS < run.firstMS {
		run.firstMS = record.ObservedMS
	}
	if record.ObservedMS > run.lastMS {
		run.lastMS = record.ObservedMS
	}
	return nil
}

func (run *recoveryRun) segment() protocol.RecoverySegment {
	return protocol.RecoverySegment{SourceID: run.sourceID, FromSequence: int64(run.fromSequence), ToSequence: int64(run.toSequence), FirstMS: run.firstMS, LastMS: run.lastMS, FrameCount: run.frameCount, Bytes: run.bytes, SegmentSHA256: hex.EncodeToString(run.hasher.Sum(nil))}
}

func (s *Spool) PreviewRecovery(options RecoveryPreviewOptions) (protocol.RecoveryManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(); err != nil {
		return protocol.RecoveryManifest{}, err
	}
	if options.DeploymentID == "" || options.HostID == "" || options.OriginalSecurityGeneration == "" || options.OriginalCollectorBootID == "" || options.CreatedMS < 0 {
		return protocol.RecoveryManifest{}, errors.New("invalid recovery preview identity")
	}
	now := s.options.Now().UnixMilli()
	if options.CreatedMS == 0 {
		options.CreatedMS = now
	}
	var run *recoveryRun
	segments := make([]protocol.RecoverySegment, 0, 32)
	sourceSeen := make(map[string]bool, 8)
	manifestOverflow := false
	totalFrames := 0
	totalBytes := int64(0)
	// Read-only preview models the exact age pruning that a later writable
	// apply performs, but retains every byte. This lets a wholly age-expired
	// physical file become an explicit loss interval rather than permanently
	// blocking a newer eligible file.
	losses := append([]Loss(nil), s.losses.Losses...)
	finish := func() {
		if run != nil {
			if len(segments) >= 4096 {
				manifestOverflow = true
			} else {
				segments = append(segments, run.segment())
			}
			run = nil
		}
	}
	stop := false
	for _, segment := range s.segments {
		if stop {
			break
		}
		if segment.ack >= segment.size {
			continue
		}
		if now-segment.firstMS >= s.options.Age.Milliseconds() {
			if segment.generation == options.OriginalSecurityGeneration && segment.boot == options.OriginalCollectorBootID {
				if err := appendVirtualRecoveryLoss(filepath.Join(s.dir, segment.name), segment.ack, &losses); err != nil {
					return protocol.RecoveryManifest{}, err
				}
			}
			continue
		}
		if segment.generation != options.OriginalSecurityGeneration || segment.boot != options.OriginalCollectorBootID {
			continue
		}
		file, err := os.Open(filepath.Join(s.dir, segment.name))
		if err != nil {
			return protocol.RecoveryManifest{}, err
		}
		if _, err = file.Seek(segment.ack, io.SeekStart); err != nil {
			file.Close()
			return protocol.RecoveryManifest{}, err
		}
		for {
			record, _, readErr := readRecord(file)
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				file.Close()
				return protocol.RecoveryManifest{}, readErr
			}
			selected := now-record.ObservedMS <= s.options.Age.Milliseconds() && record.ObservedMS <= now+60000 && (options.SourceID == "" || record.SourceID == options.SourceID) && (options.FromSequence == nil || record.Sequence >= *options.FromSequence) && (options.ToSequence == nil || record.Sequence <= *options.ToSequence)
			if !selected {
				finish()
				stop = true
				break
			}
			if !sourceSeen[record.SourceID] && len(sourceSeen) >= 8 {
				file.Close()
				return protocol.RecoveryManifest{}, errors.New("recovery preview exceeds eight-source manifest limit")
			}
			if run == nil || record.SourceID != run.sourceID || record.Sequence != run.nextSequence || run.frameCount >= protocol.MaxRecoverySegmentFrames || run.bytes+int64(len(record.Payload)) > protocol.MaxRecoverySegmentBytes {
				finish()
				run = newRecoveryRun(record)
			}
			if err := run.add(record); err != nil {
				file.Close()
				return protocol.RecoveryManifest{}, err
			}
			sourceSeen[record.SourceID] = true
			totalFrames++
			totalBytes += int64(len(record.Payload))
		}
		file.Close()
		// A grant segment never spans a physical spool file. This keeps every
		// durable recovery ACK aligned to one append-only cursor prefix.
		finish()
	}
	finish()
	if manifestOverflow {
		return protocol.RecoveryManifest{}, errors.New("recovery preview exceeds 4096 segment limit; select a smaller sequence range")
	}
	if totalFrames == 0 {
		return protocol.RecoveryManifest{}, errors.New("no eligible retained recovery records")
	}
	protocol.SortRecoverySegments(segments)
	sources := make([]string, 0, len(sourceSeen))
	for sourceID := range sourceSeen {
		sources = append(sources, sourceID)
	}
	sort.Strings(sources)
	definitions, err := recoveryDefinitionsForSources(options.Definitions, sourceSeen)
	if err != nil {
		return protocol.RecoveryManifest{}, err
	}
	lossIntervals := make([]protocol.RecoveryLoss, 0, len(losses))
	for _, loss := range losses {
		if loss.Count > uint64(protocol.MaxUint53) {
			return protocol.RecoveryManifest{}, errors.New("recovery loss count exceeds exact JSON integer range")
		}
		lossIntervals = append(lossIntervals, protocol.RecoveryLoss{StartMS: loss.StartMS, EndMS: loss.EndMS, LostCount: int64(loss.Count), Reason: loss.Reason})
	}
	manifest := protocol.RecoveryManifest{SchemaVersion: domain.SchemaVersion, DeploymentID: options.DeploymentID, HostID: options.HostID, OriginalSecurityGeneration: options.OriginalSecurityGeneration, OriginalCollectorBootID: options.OriginalCollectorBootID, CreatedMS: options.CreatedMS, TotalBytes: totalBytes, TotalFrames: totalFrames, Sources: sources, HistoricalDefinitions: definitions, Segments: segments, LossIntervals: lossIntervals}
	manifest.ManifestSHA256, _ = protocol.CanonicalRecoveryManifestHash(manifest)
	if err := manifest.Validate(); err != nil {
		return protocol.RecoveryManifest{}, err
	}
	encoded, _ := json.Marshal(manifest)
	if int64(len(encoded)) > protocol.MaxRecoveryManifestBytes {
		return protocol.RecoveryManifest{}, errors.New("recovery manifest exceeds 64 KiB; select a smaller sequence range")
	}
	return manifest, nil
}

func appendVirtualRecoveryLoss(path string, offset int64, losses *[]Loss) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return err
	}
	for {
		record, _, readErr := readRecord(file)
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		index := -1
		for candidate, loss := range *losses {
			if loss.SourceID == record.SourceID && loss.Reason == "spool_age" {
				index = candidate
				break
			}
		}
		if index < 0 {
			*losses = append(*losses, Loss{SourceID: record.SourceID, StartMS: record.ObservedMS, EndMS: record.ObservedMS, Reason: "spool_age"})
			index = len(*losses) - 1
		}
		loss := &(*losses)[index]
		loss.Count++
		if record.ObservedMS < loss.StartMS {
			loss.StartMS = record.ObservedMS
		}
		if record.ObservedMS > loss.EndMS {
			loss.EndMS = record.ObservedMS
		}
	}
}

func recoveryDefinitionsForSources(definitions protocol.RecoveryDefinitions, selected map[string]bool) (protocol.RecoveryDefinitions, error) {
	result := protocol.RecoveryDefinitions{HistoricalOnly: true, Sources: []protocol.InventorySource{}, Targets: []protocol.InventoryTarget{}, Models: []protocol.InventoryModel{}}
	targets := make(map[string]bool)
	for _, source := range definitions.Sources {
		if !selected[source.SourceID] {
			continue
		}
		source.Active = false
		result.Sources = append(result.Sources, source)
		if source.TargetID != nil {
			targets[*source.TargetID] = true
		}
	}
	if len(result.Sources) != len(selected) {
		return protocol.RecoveryDefinitions{}, errors.New("retained recovery source lacks a reviewed historical definition")
	}
	for _, target := range definitions.Targets {
		if targets[target.TargetID] {
			result.Targets = append(result.Targets, target)
		}
	}
	for _, model := range definitions.Models {
		if targets[model.TargetID] {
			model.ReportedLoaded = false
			result.Models = append(result.Models, model)
		}
	}
	return result, nil
}

func (s *Spool) ReadRecovery(grant protocol.RecoveryGrant, maxBytes, maxFrames int) (RecoveryPending, error) {
	if err := grant.Validate(); err != nil {
		return RecoveryPending{}, err
	}
	if maxBytes < 1 || maxBytes > int(protocol.MaxRecoverySegmentBytes) || maxFrames < 1 || maxFrames > protocol.MaxRecoveryReplayFrames {
		return RecoveryPending{}, errors.New("invalid recovery pending limits")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writable(); err != nil {
		return RecoveryPending{}, err
	}
	if err := s.prune(0); err != nil {
		return RecoveryPending{}, err
	}
	if now := s.options.Now().UnixMilli(); now > grant.ExpiresMS {
		return RecoveryPending{}, errors.New("recovery grant expired")
	}
	if !s.recoveryVerified[grant.GrantSHA256] {
		if err := s.verifyGrantSegmentsLocked(grant); err != nil {
			return RecoveryPending{}, err
		}
		if len(s.recoveryVerified) >= 4 {
			s.recoveryVerified = map[string]bool{}
		}
		s.recoveryVerified[grant.GrantSHA256] = true
	}
	validOwner := func(record Record) bool {
		if record.DeploymentID != grant.DeploymentID || record.HostID != grant.HostID || record.Generation != grant.OriginalSecurityGeneration || record.BootID != grant.OriginalCollectorBootID {
			return false
		}
		return true
	}
	approvedStart := func(record Record) *protocol.ApprovedRecoverySegment {
		for _, scope := range grant.ApprovedSegments {
			if scope.SourceID == record.SourceID && int64(record.Sequence) == scope.FromSequence {
				copy := scope
				return &copy
			}
		}
		return nil
	}
	for _, segment := range s.segments {
		if segment.ack >= segment.size || segment.generation != grant.OriginalSecurityGeneration || segment.boot != grant.OriginalCollectorBootID || s.journal.Quarantined[segment.name] != "" {
			continue
		}
		file, err := os.Open(filepath.Join(s.dir, segment.name))
		if err != nil {
			return RecoveryPending{}, err
		}
		if _, err = file.Seek(segment.ack, io.SeekStart); err != nil {
			file.Close()
			return RecoveryPending{}, err
		}
		result := RecoveryPending{Records: []Record{}, Cursor: Cursor{owner: s, segment: segment.name, start: segment.ack, end: segment.ack}}
		for len(result.Records) < maxFrames {
			record, readBytes, readErr := readRecord(file)
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				file.Close()
				return RecoveryPending{}, readErr
			}
			if !validOwner(record) {
				file.Close()
				return RecoveryPending{}, errors.New("recovery spool prefix owner conflicts with grant")
			}
			scope := approvedStart(record)
			if scope == nil {
				if len(result.Records) == 0 {
					file.Close()
					return RecoveryPending{}, errors.New("approved recovery scope does not begin at the physical spool prefix")
				}
				break
			}
			count := int(scope.ToSequence - scope.FromSequence + 1)
			if count > maxFrames-len(result.Records) {
				break
			}
			group := make([]Record, 0, count)
			groupBytes, groupWireBytes := 0, int64(0)
			for offset := 0; offset < count; offset++ {
				if offset > 0 {
					record, readBytes, readErr = readRecord(file)
					if readErr != nil {
						file.Close()
						return RecoveryPending{}, errors.New("reviewed recovery segment is not a complete physical prefix")
					}
				}
				if !validOwner(record) || record.SourceID != scope.SourceID || int64(record.Sequence) != scope.FromSequence+int64(offset) {
					file.Close()
					return RecoveryPending{}, errors.New("reviewed recovery segment is not a same-source physical run")
				}
				group = append(group, record)
				groupBytes += len(record.Payload)
				groupWireBytes += readBytes
			}
			if result.Bytes+groupBytes > maxBytes {
				if len(result.Records) == 0 {
					file.Close()
					return RecoveryPending{}, errors.New("single reviewed recovery segment exceeds transfer bound")
				}
				break
			}
			result.Records = append(result.Records, group...)
			result.Bytes += groupBytes
			result.Cursor.end += groupWireBytes
		}
		file.Close()
		if len(result.Records) > 0 {
			return result, nil
		}
		return RecoveryPending{}, errors.New("approved recovery scope does not contain a transferable physical prefix")
	}
	return RecoveryPending{}, nil
}

func (s *Spool) verifyGrantSegmentsLocked(grant protocol.RecoveryGrant) error {
	type verifier struct {
		scope protocol.ApprovedRecoverySegment
		next  int64
		hash  hash.Hash
		found bool
	}
	verifiers := make([]verifier, len(grant.ApprovedSegments))
	for index, scope := range grant.ApprovedSegments {
		verifiers[index] = verifier{scope: scope, next: scope.FromSequence, hash: sha256.New()}
	}
	for _, segment := range s.segments {
		if segment.ack >= segment.size || segment.generation != grant.OriginalSecurityGeneration || segment.boot != grant.OriginalCollectorBootID || s.journal.Quarantined[segment.name] != "" {
			continue
		}
		file, err := os.Open(filepath.Join(s.dir, segment.name))
		if err != nil {
			return err
		}
		if _, err = file.Seek(segment.ack, io.SeekStart); err != nil {
			file.Close()
			return err
		}
		for {
			record, _, readErr := readRecord(file)
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				file.Close()
				return readErr
			}
			for index := range verifiers {
				check := &verifiers[index]
				if check.scope.SourceID != record.SourceID || int64(record.Sequence) < check.scope.FromSequence || int64(record.Sequence) > check.scope.ToSequence {
					continue
				}
				if int64(record.Sequence) != check.next {
					file.Close()
					return errors.New("retained spool sequence conflicts with recovery grant")
				}
				check.found = true
				if err := writeRecoveryDescriptor(check.hash, record); err != nil {
					file.Close()
					return err
				}
				check.next++
				break
			}
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	for _, check := range verifiers {
		// A prior durable ACK may already have removed an approved segment.
		// Verify every still-retained segment completely; absent segments are
		// never sent and the hub receipt ledger remains authoritative.
		if check.found && (check.next != check.scope.ToSequence+1 || hex.EncodeToString(check.hash.Sum(nil)) != check.scope.SegmentSHA256) {
			return errors.New("retained spool bytes do not match reviewed recovery grant")
		}
	}
	return nil
}

func (s *Spool) AckRecovery(pending RecoveryPending, replay protocol.RecoveryReplay, ack protocol.RecoveryACK) error {
	if err := ack.Validate(replay); err != nil {
		return err
	}
	if len(pending.Records) != len(replay.Frames) {
		return errors.New("recovery acknowledgement does not cover pending spool prefix")
	}
	for index, record := range pending.Records {
		frame := replay.Frames[index]
		payloadHash := sha256.Sum256(record.Payload)
		if record.BootID != replay.OriginalCollectorBootID || record.SourceID != frame.OriginalSourceID || int64(record.Sequence) != frame.OriginalSequence || record.ObservedMS != frame.OriginalObservedMS || hex.EncodeToString(payloadHash[:]) != frame.OriginalPayloadSHA256 {
			return errors.New("recovery replay does not match pending spool prefix")
		}
	}
	for _, receipt := range ack.Receipts {
		if receipt.Disposition != "recovered" && receipt.Disposition != "duplicate" {
			return errors.New("nonterminal recovery receipt cannot advance spool")
		}
	}
	return s.Ack(pending.Cursor)
}
