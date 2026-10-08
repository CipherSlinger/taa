package resource

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidateWheelhouse checks the unpacked layout of a dependency archive: it must contain
// requirements.txt and at least one .whl. A missing piece rejects the package outright --
// an offline install cannot complete a partial dependency closure, so failing here beats
// surfacing an ImportError at training time.
//
// The scan is deliberately flat (non-recursive): the platform contract is a flat wheelhouse
// with requirements.txt at the archive root, and pip's --find-links is not recursive either.
func ValidateWheelhouse(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("wheelhouse dir is required")
	}
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat wheelhouse: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("wheelhouse is not a directory: %s", dir)
	}

	// A directory named requirements.txt satisfies a bare os.Stat but makes pip fail with
	// "[Errno 21] Is a directory", so require a regular file here.
	reqInfo, err := os.Stat(filepath.Join(dir, "requirements.txt"))
	if err != nil {
		return fmt.Errorf("依赖包缺少 requirements.txt: %w", err)
	}
	if !reqInfo.Mode().IsRegular() {
		return fmt.Errorf("依赖包内的 requirements.txt 不是普通文件")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read wheelhouse: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// pip parses wheel filenames case-sensitively, so a ".WHL" file is invisible to it.
		// An EqualFold match here would accept an archive pip cannot install.
		if filepath.Ext(entry.Name()) == ".whl" {
			return nil
		}
	}
	return fmt.Errorf("依赖包内未找到任何 .whl 文件")
}
