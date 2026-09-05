package codeaudit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ResultCheckReport describes findings from checking exported results.
type ResultCheckReport struct {
	Passed   bool               `json:"passed"`
	Warnings []ResultCheckIssue `json:"warnings"`
}

// ResultCheckIssue is a single issue found in exported results.
type ResultCheckIssue struct {
	Check   string `json:"check"`
	Detail  string `json:"detail"`
	Severity string `json:"severity"`
}

// ResultChecker validates that exported training results do not contain
// plaintext training data.
type ResultChecker struct {
	// DataDir is the directory containing training data files.
	// If set, the checker computes fingerprints to detect data leakage.
	DataDir string
	// MaxResultBytes is the maximum expected size of a result file.
	// Results larger than this are flagged as suspicious.
	MaxResultBytes int64
}

// DefaultResultChecker returns a checker with sensible defaults.
func DefaultResultChecker() *ResultChecker {
	return &ResultChecker{
		MaxResultBytes: 500 * 1024 * 1024, // 500 MB
	}
}

// CheckFile inspects a single result file for plaintext data leakage.
func (rc *ResultChecker) CheckFile(resultPath string) (*ResultCheckReport, error) {
	info, err := os.Stat(resultPath)
	if err != nil {
		return nil, fmt.Errorf("stat result file: %w", err)
	}

	var warnings []ResultCheckIssue

	// ── Check 1: Size anomaly ──
	if rc.MaxResultBytes > 0 && info.Size() > rc.MaxResultBytes {
		warnings = append(warnings, ResultCheckIssue{
			Check:    "size_anomaly",
			Detail:   fmt.Sprintf("结果文件 %d 字节，超过预期上限 %d 字节，可能嵌入了额外数据", info.Size(), rc.MaxResultBytes),
			Severity: SeverityMedium,
		})
	}

	// ── Check 2: Plaintext sections in binary files ──
	content, err := os.ReadFile(resultPath)
	if err != nil {
		return nil, fmt.Errorf("read result file: %w", err)
	}
	plaintextHits := detectPlaintextSections(content)
	for _, hit := range plaintextHits {
		warnings = append(warnings, ResultCheckIssue{
			Check:    "plaintext_section",
			Detail:   fmt.Sprintf("结果文件中检测到明文段: %s", hit),
			Severity: SeverityHigh,
		})
	}

	// ── Check 3: Data fingerprint matching ──
	if rc.DataDir != "" {
		fingerprintHits, fpErr := rc.checkDataFingerprints(content)
		if fpErr == nil {
			for _, hit := range fingerprintHits {
				warnings = append(warnings, ResultCheckIssue{
					Check:    "data_fingerprint",
					Detail:   fmt.Sprintf("结果文件中检测到训练数据特征: %s", hit),
					Severity: SeverityHigh,
				})
			}
		}
	}

	passed := true
	for _, w := range warnings {
		if w.Severity == SeverityHigh {
			passed = false
			break
		}
	}

	return &ResultCheckReport{
		Passed:   passed,
		Warnings: warnings,
	}, nil
}

// CheckDirectory inspects all files in a result directory.
func (rc *ResultChecker) CheckDirectory(resultDir string) (*ResultCheckReport, error) {
	var allWarnings []ResultCheckIssue
	passed := true

	err := filepath.Walk(resultDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// Skip hidden files and common non-result files.
		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		report, checkErr := rc.CheckFile(path)
		if checkErr != nil {
			return nil // skip unreadable files
		}
		allWarnings = append(allWarnings, report.Warnings...)
		if !report.Passed {
			passed = false
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk result directory: %w", err)
	}

	return &ResultCheckReport{
		Passed:   passed,
		Warnings: allWarnings,
	}, nil
}

// ── Internal helpers ─────────────────────────────────────

// suspiciousPatterns are plaintext strings that should NOT appear in
// model weight files or encrypted result blobs.
var suspiciousPatterns = []struct {
	name    string
	pattern []byte
}{
	{"CSV header (training data)", []byte("id,label,image")},
	{"CSV header (patient data)", []byte("patient_id")},
	{"JSON data array", []byte(`"data":[`)},
	{"JSON samples array", []byte(`"samples":[`)},
	{"PEM private key", []byte("-----BEGIN")},
	{"AWS credentials", []byte("aws_secret_access_key")},
	{"database connection", []byte("postgresql://")},
	{"database connection", []byte("mysql://")},
	{"environment dump", []byte("SECRET_KEY=")},
	{"environment dump", []byte("API_KEY=")},
}

func detectPlaintextSections(content []byte) []string {
	var hits []string
	for _, sp := range suspiciousPatterns {
		if bytes.Contains(content, sp.pattern) {
			hits = append(hits, sp.name)
		}
	}
	return hits
}

// checkDataFingerprints compares the result content against known
// data file snippets. It reads the first 64 bytes of each data file
// as a fingerprint and checks if that fingerprint appears in the result.
func (rc *ResultChecker) checkDataFingerprints(resultContent []byte) ([]string, error) {
	if _, err := os.Stat(rc.DataDir); os.IsNotExist(err) {
		return nil, nil // no data dir to fingerprint against
	}

	var hits []string
	const fingerprintSize = 64

	err := filepath.Walk(rc.DataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() < fingerprintSize {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		// Only fingerprint data files, not code.
		switch ext {
		case ".csv", ".json", ".txt", ".xlsx", ".npy", ".npz", ".png", ".jpg", ".jpeg":
		default:
			return nil
		}

		f, openErr := os.Open(path)
		if openErr != nil {
			return nil
		}
		defer f.Close()

		fingerprint := make([]byte, fingerprintSize)
		n, readErr := f.Read(fingerprint)
		if readErr != nil || n < fingerprintSize {
			return nil
		}

		if bytes.Contains(resultContent, fingerprint) {
			hits = append(hits, fmt.Sprintf("与数据文件 %s 的前 %d 字节匹配", filepath.Base(path), fingerprintSize))
		}
		return nil
	})

	return hits, err
}
