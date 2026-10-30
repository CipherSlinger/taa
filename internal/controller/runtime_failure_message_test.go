package controller

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRuntimeFailureReasonCarriesProcessOutput(t *testing.T) {
	err := errors.New("runtimeConfig command exited with error: exit status 1")
	output := "epoch 1/3 loss=0.42\nTraceback (most recent call last):\n  File \"train.py\", line 7\nValueError: bad shape\n"

	reason := runtimeFailureReason(err, output)

	if !strings.HasPrefix(reason, "执行 runtimeConfig 失败: runtimeConfig command exited with error: exit status 1") {
		t.Fatalf("reason lost the executor error: %q", reason)
	}
	if !strings.Contains(reason, "ValueError: bad shape") {
		t.Fatalf("reason does not carry the process output: %q", reason)
	}
	if strings.Contains(reason, "...(已截断") {
		t.Fatalf("short output must not be marked truncated: %q", reason)
	}
}

func TestRuntimeFailureReasonWithoutOutput(t *testing.T) {
	err := errors.New("runtimeConfig command exited with error: exit status 137")
	for _, output := range []string{"", "   \n\t "} {
		reason := runtimeFailureReason(err, output)
		if reason != "执行 runtimeConfig 失败: runtimeConfig command exited with error: exit status 137" {
			t.Fatalf("empty output changed the reason: %q", reason)
		}
		if strings.Contains(reason, "进程输出") {
			t.Fatalf("empty output produced an output section: %q", reason)
		}
	}
}

func TestRuntimeFailureReasonKeepsOnlyTheTail(t *testing.T) {
	err := errors.New("runtimeConfig command exited with error: exit status 1")
	head := "HEAD-MARKER\n" + strings.Repeat("progress line\n", 2000)
	tail := "FATAL: out of memory"
	reason := runtimeFailureReason(err, head+tail)

	if !strings.Contains(reason, "FATAL: out of memory") {
		t.Fatal("the tail, which holds the actual cause, was dropped")
	}
	if strings.Contains(reason, "HEAD-MARKER") {
		t.Fatal("the head was kept; only the tail should survive the cap")
	}
	if !strings.Contains(reason, "已截断") {
		t.Fatal("a truncated message must say so")
	}
	if len(reason) > maxFailureOutputBytes+1024 {
		t.Fatalf("reason is %d bytes, far past the cap", len(reason))
	}
}

func TestLastBytesCutsOnRuneBoundary(t *testing.T) {
	// Every rune is three bytes, so a cut at an arbitrary byte offset lands in the
	// middle of a sequence and produces invalid UTF-8 unless it is pushed forward.
	s := strings.Repeat("测", 100)
	got := lastBytes(s, 100)

	if !utf8.ValidString(got) {
		t.Fatal("truncated output is not valid UTF-8")
	}
	if !strings.Contains(got, "已截断") {
		t.Fatal("expected a truncation notice")
	}
	if !strings.HasSuffix(got, "测") {
		t.Fatal("expected the tail to be kept")
	}
}
