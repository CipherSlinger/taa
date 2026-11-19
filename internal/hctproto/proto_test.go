package hctproto

import (
	"bytes"
	"errors"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 1000)
	var buf bytes.Buffer
	if err := WriteFrame(&buf, Header{Version: Version, Op: OpSM2Encrypt, ReqID: 42}, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if buf.Len() != HeaderSize+len(payload) {
		t.Fatalf("frame size = %d, want %d", buf.Len(), HeaderSize+len(payload))
	}
	h, got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if h.Op != OpSM2Encrypt || h.ReqID != 42 || h.Status != StatusOK {
		t.Fatalf("header = %+v", h)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
	if buf.Len() != 0 {
		t.Fatalf("%d trailing bytes", buf.Len())
	}
}

func TestReadFrameRejectsBadMagic(t *testing.T) {
	frame := make([]byte, HeaderSize)
	copy(frame, "XXXX")
	_, _, err := ReadFrame(bytes.NewReader(frame))
	if !errors.Is(err, ErrBadMagic) {
		t.Fatalf("err = %v, want ErrBadMagic", err)
	}
}

func TestReadFrameRejectsVersion(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, Header{Version: Version + 1}, nil)
	_, _, err := ReadFrame(&buf)
	if !errors.Is(err, ErrBadVersion) {
		t.Fatalf("err = %v, want ErrBadVersion", err)
	}
}

func TestReadFrameRejectsOversized(t *testing.T) {
	raw := make([]byte, HeaderSize)
	copy(raw, Magic)
	raw[4], raw[5] = 0, byte(Version)
	raw[20], raw[21], raw[22], raw[23] = 0x07, 0xff, 0xff, 0xff // > 64 MiB
	_, _, err := ReadFrame(bytes.NewReader(raw))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestReadFrameRejectsTruncated(t *testing.T) {
	var buf bytes.Buffer
	_ = WriteFrame(&buf, Header{Version: Version, Op: OpPing}, []byte("abcdef"))
	full := buf.Bytes()

	if _, _, err := ReadFrame(bytes.NewReader(full[:HeaderSize-1])); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short header: err = %v, want ErrTruncated", err)
	}
	if _, _, err := ReadFrame(bytes.NewReader(full[:len(full)-1])); !errors.Is(err, ErrTruncated) {
		t.Fatalf("short payload: err = %v, want ErrTruncated", err)
	}
}

func TestEncodeRejectsOversizedPayload(t *testing.T) {
	if _, err := Encode(Header{}, make([]byte, MaxPayload+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}
}

func TestBuilderReaderRoundTrip(t *testing.T) {
	b := NewBuilder(16)
	b.U8(7)
	b.U16(0x1234)
	b.U32(0xdeadbeef)
	b.U64(0x0102030405060708)
	b.Bytes([]byte("tail"))

	r := NewReader(b.Payload())
	if r.U8() != 7 || r.U16() != 0x1234 || r.U32() != 0xdeadbeef || r.U64() != 0x0102030405060708 {
		t.Fatalf("scalar mismatch: %v", r.Err())
	}
	if got := string(r.Rest()); got != "tail" {
		t.Fatalf("rest = %q", got)
	}
	if err := r.Err(); err != nil {
		t.Fatalf("unexpected reader error: %v", err)
	}
}

func TestReaderFailureIsSticky(t *testing.T) {
	r := NewReader([]byte{1})
	_ = r.U32()
	if err := r.Err(); err == nil {
		t.Fatal("expected an error for a short read")
	}
	if got := r.U8(); got != 0 {
		t.Fatalf("read after failure returned %d", got)
	}
	if r.Rest() != nil {
		t.Fatal("Rest after failure should be nil")
	}
}

func FuzzReadFrame(f *testing.F) {
	var valid bytes.Buffer
	frame, _ := Encode(Header{Version: Version, Op: OpPing, ReqID: 1}, []byte("hi"))
	valid.Write(frame)
	f.Add(valid.Bytes())
	f.Add([]byte(Magic))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic; any error is acceptable.
		_, _, _ = ReadFrame(bytes.NewReader(data))
	})
}
