package codeaudit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	taacrypto "taa/pkg/crypto"
)

// ResultCheckReport describes findings from checking exported results.
type ResultCheckReport struct {
	Passed   bool               `json:"passed"`
	Warnings []ResultCheckIssue `json:"warnings"`
}

// ResultCheckIssue is a single issue found in exported results.
type ResultCheckIssue struct {
	Check    string `json:"check"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

// ResultChecker compares every file in a result directory with every file in the
// training input directory by content hash. A result passes only when the two
// digest sets do not intersect: an identical digest means a result file is a
// byte-for-byte copy of a training input, which is the leakage this check exists
// to catch.
//
// The comparison is whole-file only. A result that embeds part of an input file
// (a CSV pasted into a notebook, a row set inside a model blob) has a different
// digest and is not detected; dropping the byte-pattern scan was a deliberate
// trade for a verdict that rests on exact evidence.
type ResultChecker struct {
	// InputDir is the directory holding the training inputs.
	InputDir string
}

// NewResultChecker creates a checker over inputDir.
func NewResultChecker(inputDir string) *ResultChecker {
	return &ResultChecker{InputDir: inputDir}
}

// CheckFile hashes one result file and reports it when its digest matches any
// input file. A zero-length result file carries no data and always passes.
func (rc *ResultChecker) CheckFile(resultPath string) (*ResultCheckReport, error) {
	inputHashes, err := rc.inputHashes()
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(resultPath)
	if err != nil {
		return nil, fmt.Errorf("stat result file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("result file is not a regular file: %s", resultPath)
	}
	if info.Size() == 0 {
		return &ResultCheckReport{Passed: true}, nil
	}

	_, digest, err := taacrypto.HashFileSM3(resultPath)
	if err != nil {
		return nil, fmt.Errorf("hash result file: %w", err)
	}

	var warnings []ResultCheckIssue
	if inputPath, ok := inputHashes[digest]; ok {
		warnings = append(warnings, hashMatchIssue(filepath.Base(resultPath), inputPath, digest))
	}
	return &ResultCheckReport{Passed: len(warnings) == 0, Warnings: warnings}, nil
}

// CheckDirectory inspects every regular file in a result directory.
//
// skipRootNames lists file names to ignore when they are direct children of
// resultDir. TAA's own report belongs there and is not a training artifact: it
// carries table previews by design, so hashing it could report the check's own
// bookkeeping as a leaked dataset file. Only direct children are skipped,
// matching the export packer's rule - a same-named file produced deeper in the
// tree is still checked, so nothing can travel in an export unchecked.
//
// Hidden files (dot-prefixed) and empty files are skipped in both trees: they
// carry no training data, and two unrelated empty files would otherwise share a
// digest and fail an otherwise clean run. Symlinks are not followed, so a link
// cannot pull a file from outside either directory into the comparison.
func (rc *ResultChecker) CheckDirectory(resultDir string, skipRootNames ...string) (*ResultCheckReport, error) {
	inputHashes, err := rc.inputHashes()
	if err != nil {
		return nil, err
	}

	root := filepath.Clean(resultDir)
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("stat result directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("result path is not a directory: %s", resultDir)
	}

	skip := make(map[string]bool, len(skipRootNames))
	for _, name := range skipRootNames {
		if name != "" {
			skip[name] = true
		}
	}

	var warnings []ResultCheckIssue
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if strings.HasPrefix(entry.Name(), ".") {
			return nil
		}
		if len(skip) > 0 && filepath.Dir(path) == root && skip[entry.Name()] {
			return nil
		}

		size, digest, err := taacrypto.HashFileSM3(path)
		if err != nil {
			return err
		}
		if size == 0 {
			return nil
		}
		inputPath, ok := inputHashes[digest]
		if !ok {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		warnings = append(warnings, hashMatchIssue(rel, inputPath, digest))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk result directory: %w", err)
	}

	return &ResultCheckReport{
		Passed:   len(warnings) == 0,
		Warnings: warnings,
	}, nil
}

// inputHashes returns digest -> path relative to InputDir for every input file,
// applying the same regular-file, hidden-file and empty-file rules as the result
// side so the two sets are comparable.
func (rc *ResultChecker) inputHashes() (map[string]string, error) {
	inputDir := strings.TrimSpace(rc.InputDir)
	if inputDir == "" {
		return nil, fmt.Errorf("training input directory is not configured")
	}
	info, err := os.Stat(inputDir)
	if err != nil {
		return nil, fmt.Errorf("stat training input directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("training input path is not a directory: %s", rc.InputDir)
	}

	hashes := make(map[string]string)
	err = filepath.WalkDir(inputDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if strings.HasPrefix(entry.Name(), ".") {
			return nil
		}

		size, digest, err := taacrypto.HashFileSM3(path)
		if err != nil {
			return err
		}
		if size == 0 {
			return nil
		}
		rel, err := filepath.Rel(inputDir, path)
		if err != nil {
			rel = path
		}
		if _, seen := hashes[digest]; !seen {
			hashes[digest] = rel
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk training input directory: %w", err)
	}
	return hashes, nil
}

func hashMatchIssue(resultPath, inputPath, digest string) ResultCheckIssue {
	return ResultCheckIssue{
		Check:    "file_hash_match",
		Detail:   fmt.Sprintf("结果文件 %s 与输入文件 %s 的 SM3 哈希相同 (%s)", resultPath, inputPath, digest),
		Severity: SeverityHigh,
	}
}
