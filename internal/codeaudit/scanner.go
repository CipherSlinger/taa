package codeaudit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Config controls scanner behavior.
type Config struct {
	Extensions  []string
	MaxFindings int
	SkipDirs    map[string]bool
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() Config {
	return Config{
		Extensions:  []string{".py"},
		MaxFindings: 200,
		SkipDirs: map[string]bool{
			".git": true, "__pycache__": true, ".idea": true,
			".vscode": true, "node_modules": true, "venv": true, ".venv": true,
		},
	}
}

// Scanner performs security analysis on Python source files.
type Scanner struct {
	rules  []Rule
	config Config
}

// NewScanner creates a scanner with the given rules and config.
func NewScanner(rules []Rule, config Config) *Scanner {
	return &Scanner{rules: rules, config: config}
}

// defaultScanner is compiled once and reused — regex patterns are immutable.
var (
	defaultScanner     *Scanner
	defaultScannerOnce sync.Once
)

// DefaultScanner returns the shared singleton scanner with default rules.
// Regex patterns are compiled once on first call.
func DefaultScanner() *Scanner {
	defaultScannerOnce.Do(func() {
		defaultScanner = NewScanner(DefaultRules(), DefaultConfig())
	})
	return defaultScanner
}

// NewDefaultScanner creates a fresh scanner (prefer DefaultScanner for hot paths).
func NewDefaultScanner() *Scanner {
	return NewScanner(DefaultRules(), DefaultConfig())
}

// ScanDirectory walks dir, scanning all matching files, and returns a Report.
func (s *Scanner) ScanDirectory(dir string) (*Report, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("scan directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	var findings []Finding
	filesCount := 0

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if s.config.SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !s.hasMatchingExtension(path) {
			return nil
		}

		filesCount++
		fileFindings, scanErr := s.ScanFile(path)
		if scanErr != nil {
			return nil
		}
		findings = append(findings, fileFindings...)

		if len(findings) >= s.config.MaxFindings {
			findings = findings[:s.config.MaxFindings]
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return s.buildReport(dir, filesCount, findings), nil
}

// ScanFile scans a single file and returns any findings.
func (s *Scanner) ScanFile(path string) ([]Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	lines := strings.Split(string(content), "\n")

	var findings []Finding
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		for _, rule := range s.rules {
			if s.matchRule(rule, line) {
				findings = append(findings, Finding{
					File:          path,
					Line:          i + 1,
					RuleID:        rule.ID,
					Category:      rule.Category,
					Severity:      rule.Severity,
					Description:   rule.Description,
					CodeSnippet:   trimmed,
					ContextBefore: contextWindow(lines, i-3, i),
					ContextAfter:  contextWindow(lines, i+1, i+4),
				})
				break
			}
		}
	}
	return findings, nil
}

func contextWindow(lines []string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start >= end {
		return ""
	}
	return strings.TrimSpace(strings.Join(lines[start:end], "\n"))
}

func (s *Scanner) hasMatchingExtension(path string) bool {
	ext := filepath.Ext(path)
	for _, e := range s.config.Extensions {
		if ext == e {
			return true
		}
	}
	return false
}

func (s *Scanner) matchRule(rule Rule, line string) bool {
	for _, pat := range rule.Patterns {
		if pat.MatchString(line) {
			return true
		}
	}
	return false
}

func (s *Scanner) buildReport(dir string, filesCount int, findings []Finding) *Report {
	highCount := 0
	mediumCount := 0
	for _, f := range findings {
		switch f.Severity {
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			mediumCount++
		}
	}
	return &Report{
		ScanTime:    time.Now().Format(time.RFC3339),
		ScannedDir:  dir,
		FilesCount:  filesCount,
		HighCount:   highCount,
		MediumCount: mediumCount,
		Passed:      highCount == 0,
		Findings:    findings,
	}
}

// ── High-level gate functions ────────────────────────────
//
// These are the single entry points for the TAA HTTP layer.
// Policy decisions (what severity blocks, what is allowed) live here,
// not in the HTTP handlers.

// CheckImport scans model code in dir. Returns (pass, report, error).
// A scan error is treated as a rejection — fail closed.
func CheckImport(dir string) (bool, *Report, error) {
	if dir == "" {
		return true, nil, nil
	}
	report, err := DefaultScanner().ScanDirectory(dir)
	if err != nil {
		return false, nil, err
	}
	return report.Passed, report, nil
}

// CheckExport inspects resultDir for plaintext data leakage against dataDir.
// Returns (pass, report, error). A check error is treated as a rejection.
func CheckExport(resultDir, dataDir string) (bool, *ResultCheckReport, error) {
	if resultDir == "" {
		return true, nil, nil
	}
	checker := DefaultResultChecker()
	checker.DataDir = dataDir
	report, err := checker.CheckDirectory(resultDir)
	if err != nil {
		return false, nil, err
	}
	return report.Passed, report, nil
}

// ScanDirectoryWithLines is like ScanDirectory but also returns per-file line counts.
// The lineCounts map is keyed by absolute file path.
func (s *Scanner) ScanDirectoryWithLines(dir string) (*Report, map[string]int, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("scan directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dir)
	}

	var findings []Finding
	filesCount := 0
	lineCounts := make(map[string]int)

	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if s.config.SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !s.hasMatchingExtension(path) {
			return nil
		}

		filesCount++

		// Count lines.
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		lines := strings.Split(string(content), "\n")
		lineCounts[path] = len(lines)

		// Scan for findings.
		fileFindings := s.scanLines(path, lines)
		findings = append(findings, fileFindings...)

		if len(findings) >= s.config.MaxFindings {
			findings = findings[:s.config.MaxFindings]
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("walk directory: %w", err)
	}

	return s.buildReport(dir, filesCount, findings), lineCounts, nil
}

// scanLines scans pre-read lines for findings. Extracted from ScanFile for reuse.
func (s *Scanner) scanLines(path string, lines []string) []Finding {
	var findings []Finding
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, rule := range s.rules {
			if s.matchRule(rule, line) {
				findings = append(findings, Finding{
					File:          path,
					Line:          i + 1,
					RuleID:        rule.ID,
					Category:      rule.Category,
					Severity:      rule.Severity,
					Description:   rule.Description,
					CodeSnippet:   trimmed,
					ContextBefore: contextWindow(lines, i-3, i),
					ContextAfter:  contextWindow(lines, i+1, i+4),
				})
				break
			}
		}
	}
	return findings
}
