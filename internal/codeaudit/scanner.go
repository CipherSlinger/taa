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
	truncated := false

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
			truncated = true
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}

	return s.buildReport(dir, filesCount, findings, truncated), nil
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
		if isCommentLine(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)

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

	// Only a file that produced a finding pays for a parse.
	applyScopeContext(findings, string(content))
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

// buildReport assembles the report for a completed walk. truncated records
// whether the finding cap was reached and the walk stopped early, so that what
// the report does not contain is visible from the report. It is recorded where
// truncation happens rather than inferred later from len(findings): with the
// current ">=" cap check the two would agree, but that agreement is a
// coincidence of this comparison, not a property the report should rest on.
func (s *Scanner) buildReport(dir string, filesCount int, findings []Finding, truncated bool) *Report {
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
		Truncated:   truncated,
	}
}

// withRoots records the full root list on a merged scan's report, and is the one
// place Directories is written. Both engines call it on their multi-root paths,
// so the field cannot be filled on one arm and forgotten on the other.
//
// It fills only when there is more than one root. A single-root report must stay
// byte-identical to one produced before multi-root existed: the parity tests
// compare whole reports, and an extra empty-or-singleton field would be a
// difference that has nothing to do with the scan.
func withRoots(r *Report, dirs []string) *Report {
	if r == nil || len(dirs) <= 1 {
		return r
	}
	roots := make([]string, len(dirs))
	copy(roots, dirs)
	r.Directories = roots
	return r
}

// ── High-level gate functions ────────────────────────────
//
// These are the single entry points for the TAA HTTP layer.
// Policy decisions (what severity blocks, what is allowed) live here,
// not in the HTTP handlers.

// CheckImport scans model code in dir. Returns (pass, report, error).
// A scan error is treated as a rejection — fail closed.
func CheckImport(dir string, engine StaticEngine) (bool, *Report, error) {
	if dir == "" {
		return true, nil, nil
	}
	if engine == nil {
		return false, nil, fmt.Errorf("static engine is not configured")
	}
	report, err := engine.ScanDirectory(dir)
	if err != nil {
		return false, nil, err
	}
	// A pass here means the scan looked and found nothing that blocks, so it is
	// withheld unless the scan can prove it looked.
	return report.Passed && report.ProvesCleanScan(), report, nil
}

// CheckExport inspects resultDir for plaintext data leakage against dataDir.
// Returns (pass, report, error). A check error is treated as a rejection.
func CheckExport(resultDir, dataDir string) (bool, *ResultCheckReport, error) {
	return CheckExportWithLimit(resultDir, dataDir, DefaultMaxResultBytes)
}

// CheckExportWithLimit inspects resultDir for plaintext data leakage against dataDir with a custom size limit.
// Returns (pass, report, error). A check error is treated as a rejection.
func CheckExportWithLimit(resultDir, dataDir string, maxResultBytes int64) (bool, *ResultCheckReport, error) {
	if resultDir == "" {
		return true, nil, nil
	}
	checker := NewResultChecker(dataDir, maxResultBytes)
	report, err := checker.CheckDirectory(resultDir)
	if err != nil {
		return false, nil, err
	}
	return report.Passed, report, nil
}

// ScanDirectoryWithLines is like ScanDirectory but also returns per-file line counts.
// The lineCounts map is keyed by absolute file path.
func (s *Scanner) ScanDirectoryWithLines(dir string) (*Report, map[string]int, error) {
	return s.ScanDirectoriesWithLines([]string{dir})
}

// ScanDirectoriesWithLines is ScanDirectoryWithLines for a scan whose input is
// more than one root. It walks the roots in the order given and returns one
// report assembled from all of them: the findings and the line counts are the
// union, ScannedDir is the first root, and the full list lands in
// Report.Directories.
//
// Every root is stat-checked before any walk. A missing root is an error rather
// than a skipped root: a scan that quietly ignored an input it was handed would
// report a pass it did not earn, and the report cannot show what it never
// looked at.
//
// There is one finding budget across all roots, not one per root. Dividing it
// per root would raise the effective ceiling, which the scanner does not get to
// decide — the cap is a configured policy. The walk stops at the first file that
// brings the accumulated count to the cap and does not touch the roots after it.
func (s *Scanner) ScanDirectoriesWithLines(dirs []string) (*Report, map[string]int, error) {
	if len(dirs) == 0 {
		return nil, nil, fmt.Errorf("scan directories: no directories given")
	}

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil {
			return nil, nil, fmt.Errorf("scan directory: %w", err)
		}
		if !info.IsDir() {
			return nil, nil, fmt.Errorf("%s is not a directory", dir)
		}
	}

	var findings []Finding
	filesCount := 0
	lineCounts := make(map[string]int)
	truncated := false

	// A root nested inside one already walked would have its files counted twice,
	// and a path already counted is skipped for the same reason. The roots are
	// given, not discovered, so a nested pair is a caller's input error that the
	// report should absorb rather than duplicate.
	accepted := make([]string, 0, len(dirs))
	seen := make(map[string]bool)

	for _, dir := range dirs {
		if _, covered := NewScanRoots(accepted).RootOf(dir); covered {
			continue
		}

		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
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
			key := cleanAbs(path)
			if seen[key] {
				return nil
			}
			seen[key] = true

			filesCount++

			// Count lines.
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			lines := strings.Split(string(content), "\n")
			lineCounts[path] = len(lines)

			// Scan for findings.
			fileFindings := s.scanLines(path, string(content), lines)
			findings = append(findings, fileFindings...)

			if len(findings) >= s.config.MaxFindings {
				findings = findings[:s.config.MaxFindings]
				truncated = true
				return filepath.SkipAll
			}
			return nil
		})
		if err != nil {
			return nil, nil, fmt.Errorf("walk directory: %w", err)
		}
		if truncated {
			break
		}

		accepted = append(accepted, dir)
	}

	return withRoots(s.buildReport(dirs[0], filesCount, findings, truncated), dirs), lineCounts, nil
}


// isCommentLine reports whether a line's first non-space character is '#'. It is
// the predicate both engines apply before attributing a finding to a line: a
// commented-out call is not code, and a report that names one is reporting
// something nobody can act on.
//
// It is shared rather than written twice because the two arms disagree about
// comments by construction. The regex arm matches line by line and can simply
// skip; the semgrep rules are pattern-regex, which has no notion of a comment and
// matches inside one. Without the same predicate on both sides, a text rule
// reports commented-out calls the regex arm never reports - a false positive that
// belongs to neither arm's rules but to the difference between the two engines.
func isCommentLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "#")
}

// scanLines scans pre-read lines for findings. Extracted from ScanFile for reuse.
// source is the file the lines were split from; the scanner needs the lines for
// line numbering and the text for the AST parse, and splitting it here would
// redo work the caller has already done.
func (s *Scanner) scanLines(path, source string, lines []string) []Finding {
	var findings []Finding
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if isCommentLine(line) {
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

	// Only a file that produced a finding pays for a parse.
	applyScopeContext(findings, source)
	return findings
}
