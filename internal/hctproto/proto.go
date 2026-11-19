// Package hctproto defines the wire protocol between the TAA process and the
// long-lived taa-hct-helper process that owns libhct.
//
// TAA itself stays a static, CGO-free binary; the HCT-backed operations run in
// a separate helper process reached over stdin/stdout. Frames are deliberately
// simple: a fixed 24-byte big-endian header followed by an opaque payload.
package hctproto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Magic is the four-byte frame prefix.
	Magic = "THCP"
	// Version is the protocol version implemented by both sides.
	Version uint16 = 1
	// HeaderSize is the fixed frame header length.
	HeaderSize = 24
	// MaxPayload bounds a single frame payload (64 MiB).
	MaxPayload = 64 << 20
)

// Frame status values. Zero means success; every other value is a failure the
// client must treat as fatal for the operation (never as an empty result).
const (
	StatusOK               uint16 = 0
	StatusInternal         uint16 = 1
	StatusBadRequest       uint16 = 2
	StatusUnknownOp        uint16 = 3
	StatusNotFound         uint16 = 4
	StatusAuthFailed       uint16 = 5
	StatusInvalidSignature uint16 = 6
)

// Operation codes.
const (
	OpHello uint16 = 1
	OpPing  uint16 = 2
	OpClose uint16 = 3

	OpSM2Keygen       uint16 = 10
	OpSM2Encrypt      uint16 = 11
	OpSM2Decrypt      uint16 = 12
	OpSM2SignDigest   uint16 = 13
	OpSM2VerifyDigest uint16 = 14

	OpSM3Init   uint16 = 20
	OpSM3Update uint16 = 21
	OpSM3Final  uint16 = 22
	OpSM3Abort  uint16 = 23
	OpSM3Sum    uint16 = 24

	OpHMACSM3Init   uint16 = 30
	OpHMACSM3Update uint16 = 31
	OpHMACSM3Final  uint16 = 32
	OpHMACSM3Abort  uint16 = 33

	OpGCMInit   uint16 = 40
	OpGCMAAD    uint16 = 41
	OpGCMUpdate uint16 = 42
	OpGCMFinal  uint16 = 43
	OpGCMAbort  uint16 = 44
	OpGCMSetTag uint16 = 45
)

// Header is the fixed part of a frame.
type Header struct {
	Version    uint16
	Op         uint16
	Status     uint16
	ReqID      uint64
	PayloadLen uint32
}

// Frame errors. Callers should treat all of them as protocol violations.
var (
	ErrBadMagic   = errors.New("hctproto: bad magic")
	ErrBadVersion = errors.New("hctproto: unsupported protocol version")
	ErrTooLarge   = errors.New("hctproto: payload exceeds limit")
	ErrTruncated  = errors.New("hctproto: truncated frame")
)

// Encode serialises a header and payload into one buffer. Callers must write
// the returned slice with a single Write so frames from concurrent goroutines
// cannot interleave.
func Encode(h Header, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrTooLarge
	}
	buf := make([]byte, HeaderSize+len(payload))
	copy(buf[0:4], Magic)
	binary.BigEndian.PutUint16(buf[4:6], h.Version)
	binary.BigEndian.PutUint16(buf[6:8], h.Op)
	binary.BigEndian.PutUint16(buf[8:10], h.Status)
	binary.BigEndian.PutUint16(buf[10:12], 0) // reserved
	binary.BigEndian.PutUint64(buf[12:20], h.ReqID)
	binary.BigEndian.PutUint32(buf[20:24], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)
	return buf, nil
}

// WriteFrame encodes and writes a complete frame.
func WriteFrame(w io.Writer, h Header, payload []byte) error {
	buf, err := Encode(h, payload)
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// ReadFrame reads one frame. It never allocates more than MaxPayload for the
// payload and rejects any frame that would exceed it.
func ReadFrame(r io.Reader) (Header, []byte, error) {
	var raw [HeaderSize]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Header{}, nil, fmt.Errorf("%w: %v", ErrTruncated, err)
		}
		return Header{}, nil, err
	}
	if string(raw[0:4]) != Magic {
		return Header{}, nil, ErrBadMagic
	}
	h := Header{
		Version: binary.BigEndian.Uint16(raw[4:6]),
		Op:      binary.BigEndian.Uint16(raw[6:8]),
		Status:  binary.BigEndian.Uint16(raw[8:10]),
		ReqID:   binary.BigEndian.Uint64(raw[12:20]),
	}
	h.PayloadLen = binary.BigEndian.Uint32(raw[20:24])
	if h.Version != Version {
		return Header{}, nil, fmt.Errorf("%w: %d", ErrBadVersion, h.Version)
	}
	if h.PayloadLen > MaxPayload {
		return Header{}, nil, ErrTooLarge
	}
	payload := make([]byte, h.PayloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Header{}, nil, fmt.Errorf("%w: %v", ErrTruncated, err)
	}
	return h, payload, nil
}

// StatusError builds the payload of a failed response: a UTF-8 message.
func StatusError(msg string) []byte { return []byte(msg) }

// Builder assembles little bits of a payload without repeated error handling.
type Builder struct {
	b []byte
}

// NewBuilder starts a payload builder with optional capacity.
func NewBuilder(capHint int) *Builder { return &Builder{b: make([]byte, 0, capHint)} }

func (b *Builder) U8(v uint8)   { b.b = append(b.b, v) }
func (b *Builder) U16(v uint16) { b.b = binary.BigEndian.AppendUint16(b.b, v) }
func (b *Builder) U32(v uint32) { b.b = binary.BigEndian.AppendUint32(b.b, v) }
func (b *Builder) U64(v uint64) { b.b = binary.BigEndian.AppendUint64(b.b, v) }
func (b *Builder) Bytes(p []byte) {
	b.b = append(b.b, p...)
}

// Len reports the number of bytes written so far.
func (b *Builder) Len() int { return len(b.b) }

// Payload returns the assembled payload.
func (b *Builder) Payload() []byte { return b.b }

// Reader parses a payload. Its methods never panic; the first failure is
// sticky and reported by Err. Callers may run every read and check Err once.
type Reader struct {
	b   []byte
	off int
	err error
}

// NewReader wraps a payload.
func NewReader(p []byte) *Reader { return &Reader{b: p} }

func (r *Reader) fail(format string, args ...any) {
	if r.err == nil {
		r.err = fmt.Errorf(format, args...)
	}
}

func (r *Reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) {
		r.fail("hctproto: payload too short: need %d bytes at offset %d, have %d", n, r.off, len(r.b))
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

func (r *Reader) U8() uint8 {
	p := r.take(1)
	if p == nil {
		return 0
	}
	return p[0]
}

func (r *Reader) U16() uint16 {
	p := r.take(2)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint16(p)
}

func (r *Reader) U32() uint32 {
	p := r.take(4)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint32(p)
}

func (r *Reader) U64() uint64 {
	p := r.take(8)
	if p == nil {
		return 0
	}
	return binary.BigEndian.Uint64(p)
}

// Bytes returns n bytes (a copy is not made; the slice aliases the payload).
func (r *Reader) Bytes(n int) []byte { return r.take(n) }

// Remaining reports how many bytes are left unread. Unlike Rest it does not
// consume them, so a caller can treat a trailing field as optional.
func (r *Reader) Remaining() int {
	if r.err != nil {
		return 0
	}
	return len(r.b) - r.off
}

// Rest returns everything not yet consumed. It is only meaningful when Err is
// nil.
func (r *Reader) Rest() []byte {
	if r.err != nil {
		return nil
	}
	out := r.b[r.off:]
	r.off = len(r.b)
	return out
}

// Err reports the first parse failure.
func (r *Reader) Err() error { return r.err }
