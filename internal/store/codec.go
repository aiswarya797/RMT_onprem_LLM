package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/klauspost/compress/zstd"

	"rmt.local/monitor/internal/protocol"
)

const FrameCodec = "cbor-zstd-v1"

type FrameCodecV1 struct {
	encodeMode cbor.EncMode
	decodeMode cbor.DecMode
	encoder    *zstd.Encoder
	encodeMu   sync.Mutex
}

func NewFrameCodecV1() (*FrameCodecV1, error) {
	encodeMode, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("configure CBOR encoder: %w", err)
	}
	decodeOptions := cbor.DecOptions{MaxNestedLevels: protocol.MaxProtocolDepth, MaxArrayElements: 1024, MaxMapPairs: 1024, DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden}
	decodeMode, err := decodeOptions.DecMode()
	if err != nil {
		return nil, fmt.Errorf("configure CBOR decoder: %w", err)
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithWindowSize(1<<20))
	if err != nil {
		return nil, fmt.Errorf("configure zstd encoder: %w", err)
	}
	return &FrameCodecV1{encodeMode: encodeMode, decodeMode: decodeMode, encoder: encoder}, nil
}

func (c *FrameCodecV1) Close() {
	c.encodeMu.Lock()
	defer c.encodeMu.Unlock()
	c.encoder.Close()
}

func (c *FrameCodecV1) Encode(frame protocol.CollectorFrame) ([]byte, string, error) {
	c.encodeMu.Lock()
	defer c.encodeMu.Unlock()
	if err := frame.Validate(); err != nil {
		return nil, "", err
	}
	plain, err := c.encodeMode.Marshal(frame)
	if err != nil {
		return nil, "", fmt.Errorf("encode frame CBOR: %w", err)
	}
	if len(plain) > protocol.MaxFrameBytes {
		return nil, "", errors.New("canonical frame exceeds decoded limit")
	}
	compressed := c.encoder.EncodeAll(plain, make([]byte, 0, len(plain)))
	if len(compressed) > protocol.MaxFrameBytes {
		return nil, "", errors.New("compressed frame exceeds storage limit")
	}
	digest := sha256.Sum256(compressed)
	return compressed, hex.EncodeToString(digest[:]), nil
}

func (c *FrameCodecV1) Decode(compressed []byte) (protocol.CollectorFrame, error) {
	var frame protocol.CollectorFrame
	if len(compressed) > protocol.MaxFrameBytes {
		return frame, errors.New("compressed frame exceeds storage limit")
	}
	decoder, err := zstd.NewReader(bytes.NewReader(compressed), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(2<<20))
	if err != nil {
		return frame, fmt.Errorf("open zstd frame: %w", err)
	}
	defer decoder.Close()
	plain, err := io.ReadAll(io.LimitReader(decoder, protocol.MaxFrameBytes+1))
	if err != nil {
		return frame, fmt.Errorf("decode zstd frame: %w", err)
	}
	if len(plain) > protocol.MaxFrameBytes {
		return frame, errors.New("decoded frame exceeds limit")
	}
	if err := c.decodeMode.Unmarshal(plain, &frame); err != nil {
		return frame, fmt.Errorf("decode CBOR frame: %w", err)
	}
	if err := frame.Validate(); err != nil {
		return frame, fmt.Errorf("validate decoded frame: %w", err)
	}
	return frame, nil
}
