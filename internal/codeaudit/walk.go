package codeaudit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// walkContext walks dir like filepath.Walk, with one cancellation rule for every
// walker in this package: the callback is not invoked once ctx is done, and a
// cancelled walk reports the context's own error rather than a walk failure. A
// cancelled walk is not a subtree that failed to read, and only the raw context
// error tells the caller it was cancelled rather than incomplete.
func walkContext(ctx context.Context, dir string, fn filepath.WalkFunc) error {
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		// Checked before the traversal error so cancellation is not reported as an
		// unreadable path.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fn(path, info, err)
	})
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("walk directory: %w", err)
	}
	return nil
}
