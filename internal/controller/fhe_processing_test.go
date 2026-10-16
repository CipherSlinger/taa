package controller

import (
	"strings"
	"testing"

	"taa/internal/fhe"
)

// newFHETestState builds the state of a server.type=fhe instance: a TAAState with
// a runner installed, which is the single switch fheEnabled keys on.
//
// The runner is a real one built with fhe.New against a temporary data dir. The
// tests here never call the FHE service, so no endpoint has to answer; the point
// is only that the pointer is non-nil.
func newFHETestState(t *testing.T) *TAAState {
	t.Helper()
	runner, err := fhe.New(fhe.Config{
		Endpoint:        "http://127.0.0.1:58996",
		DataDir:         t.TempDir(),
		KeyCacheDir:     t.TempDir(),
		CallbackBaseURL: "http://127.0.0.1:6001",
		CallbackToken:   "test-token",
		MaxEvalKeyBytes: fhe.DefaultMaxEvalKeyBytes,
		PollInterval:    fhe.DefaultPollInterval,
		RequestTimeout:  fhe.DefaultRequestTimeout,
		TaskTimeout:     fhe.DefaultTaskTimeout,
	}, nil)
	if err != nil {
		t.Fatalf("fhe.New: %v", err)
	}
	state := &TAAState{}
	state.SetFHERunner(runner)
	return state
}

// newTEETestState builds the state of a server.type=tee instance: no runner, so
// fheEnabled is false. That is exactly how app.buildFHERunner leaves a tee boot.
func newTEETestState() *TAAState {
	return &TAAState{}
}

const validEvalKeyHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestValidateFHEFields covers every branch of the field/instance-type matrix.
//
// Each rejection asserts on the message as well as on the fact of an error: the
// three messages mean three different operator mistakes, and a test that only
// checked for "some error" would pass even if the wrong branch fired.
func TestValidateFHEFields(t *testing.T) {
	const (
		msgTee  = "本实例类型为 tee，不接受 evalKeyUrl / evalKeyFileHash 字段"
		msgFHE  = "本实例类型为 fhe，evalKeyUrl 与 evalKeyFileHash 必须同时提供"
		msgHash = "evalKeyFileHash 必须是 64 位小写十六进制 SM3 摘要"
	)

	tests := []struct {
		name    string
		fhe     bool
		url     string
		hash    string
		wantErr string // "" means the request must be accepted
	}{
		{"tee with neither field is accepted", false, "", "", ""},
		{"tee with evalKeyUrl only is rejected", false, "http://keys/1.bin", "", msgTee},
		{"tee with evalKeyFileHash only is rejected", false, "", validEvalKeyHash, msgTee},
		{"tee with both fields is rejected", false, "http://keys/1.bin", validEvalKeyHash, msgTee},

		// Whitespace-only input must count as absent, which is what makes the
		// "only one provided" case below a real rejection rather than a blank
		// string that happened to be non-empty.
		{"tee with whitespace-only fields is accepted", false, "   ", "\t\n", ""},

		{"fhe with neither field is rejected", true, "", "", msgFHE},
		{"fhe with evalKeyUrl only is rejected", true, "http://keys/1.bin", "", msgFHE},
		{"fhe with evalKeyFileHash only is rejected", true, "", validEvalKeyHash, msgFHE},
		{"fhe with a whitespace-only url is rejected", true, "   ", validEvalKeyHash, msgFHE},
		{"fhe with a whitespace-only hash is rejected", true, "http://keys/1.bin", "  ", msgFHE},

		{"fhe with an uppercase hash is rejected", true, "http://keys/1.bin", strings.ToUpper(validEvalKeyHash), msgHash},
		{"fhe with a short hash is rejected", true, "http://keys/1.bin", validEvalKeyHash[:63], msgHash},
		{"fhe with a non-hex hash is rejected", true, "http://keys/1.bin", strings.Repeat("z", 64), msgHash},
		{"fhe with a path-traversal hash is rejected", true, "http://keys/1.bin", "../../etc/passwd", msgHash},

		{"fhe with both fields and a valid hash is accepted", true, "http://keys/1.bin", validEvalKeyHash, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := newTEETestState()
			if tc.fhe {
				state = newFHETestState(t)
			}

			err := state.validateFHEFields(importRequest{
				EvalKeyURL:      tc.url,
				EvalKeyFileHash: tc.hash,
			})

			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateFHEFields() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateFHEFields() = nil, want error %q", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("validateFHEFields() = %q, want %q", err.Error(), tc.wantErr)
			}
		})
	}
}
