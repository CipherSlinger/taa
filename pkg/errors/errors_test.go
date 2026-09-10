package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrors(t *testing.T) {
	err1 := New(CodeNotFound, "resource not found")
	if err1.Code() != CodeNotFound {
		t.Fatalf("expected code %d, got %d", CodeNotFound, err1.Code())
	}
	if err1.Message() != "resource not found" {
		t.Fatalf("unexpected message: %s", err1.Message())
	}

	baseErr := errors.New("underlying network failure")
	wrapped := Wrap(CodeInternal, "failed to download", baseErr)
	if wrapped.Code() != CodeInternal {
		t.Fatalf("expected code %d, got %d", CodeInternal, wrapped.Code())
	}
	if !Is(wrapped, baseErr) {
		t.Fatalf("expected Is(wrapped, baseErr) to be true")
	}
	if wrapped.Cause() != baseErr {
		t.Fatalf("expected cause to be baseErr")
	}

	code := CodeOf(wrapped)
	if code != CodeInternal {
		t.Fatalf("expected CodeOf to return %d, got %d", CodeInternal, code)
	}

	rawErr := fmt.Errorf("generic error")
	if CodeOf(rawErr) != CodeInternal {
		t.Fatalf("expected CodeOf raw error to return default CodeInternal")
	}
	if CodeOf(rawErr, 418) != 418 {
		t.Fatalf("expected CodeOf with default to return 418")
	}
	if CodeOf(nil) != CodeOK {
		t.Fatalf("expected CodeOf(nil) to return CodeOK")
	}
}
