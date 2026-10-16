package controller

import (
	"fmt"
	"strings"

	"taa/internal/fhe"
)

// validateFHEFields enforces the two eval key fields against the instance type.
//
// On an fhe instance both are mandatory: this instance exists to run FHE tasks,
// so an import without them has no meaning. On a tee instance their presence is
// an error rather than something to ignore - silently dropping them would let the
// platform believe an FHE task was submitted when nothing was.
func (s *TAAState) validateFHEFields(req importRequest) error {
	hasURL := strings.TrimSpace(req.EvalKeyURL) != ""
	hasHash := strings.TrimSpace(req.EvalKeyFileHash) != ""

	if !s.fheEnabled() {
		if hasURL || hasHash {
			return fmt.Errorf("本实例类型为 tee，不接受 evalKeyUrl / evalKeyFileHash 字段")
		}
		return nil
	}
	if !hasURL || !hasHash {
		return fmt.Errorf("本实例类型为 fhe，evalKeyUrl 与 evalKeyFileHash 必须同时提供")
	}
	if !fhe.ValidHash(req.EvalKeyFileHash) {
		return fmt.Errorf("evalKeyFileHash 必须是 64 位小写十六进制 SM3 摘要")
	}
	return nil
}
