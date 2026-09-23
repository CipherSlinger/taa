package codeaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// defaultSemgrepBin is the CLI the adapter shells out to. It is resolved through
// PATH, which is where the container installs it.
const defaultSemgrepBin = "semgrep"

// DefaultSemgrepTimeout bounds one scan. A model import waits on this scan, so
// the deadline is what keeps a wedged CLI from hanging the import path; when it
// expires the scan fails and the import is rejected.
const DefaultSemgrepTimeout = 5 * time.Minute

// DefaultSemgrepMaxMemoryMB caps the memory one rule run may use, passed to
// semgrep as --max-memory.
//
// It is a fail-closed control, not a tuning knob. Measured on 1.177.0, a cap
// below what a rule run needs does not fail the scan: semgrep exits 0, still
// lists every target as scanned, and drops findings silently — 80 became 69
// with 134 entries in errors at a 20 MiB cap. The errors array is what catches
// that, and without any cap the same pressure is an OOM that takes the daemon
// down with it instead of rejecting one import.
//
// The value is set from measurement rather than from the container's size: a
// full 412-file scan peaked at ~165 MiB RSS, so 1 GiB is a wide margin above
// ordinary code while still bounding a pathological file, and it sits far below
// the 9.703 GiB memory domain semgrep shares with the rest of the container.
const DefaultSemgrepMaxMemoryMB = 1024

// DefaultSemgrepRulesPath is where the rules live relative to the repository
// root, which is the working directory of a `go run`/`go test` invocation. A
// deployment sets the path explicitly through EngineConfig.SemgrepRulesPath;
// this default exists so that the local path works without configuration, and
// NewEngine checks it so an unset path in a directory that has no rules fails at
// startup rather than on every import.
const DefaultSemgrepRulesPath = "models/audit/semgrep/rules/python/rules.yaml"

// semgrepEngine is the Tier 1 engine that matches with the Semgrep CLI instead
// of the built-in regular expressions.
//
// Three design decisions distinguish it from a thin exec wrapper:
//
// Severity, category and description come from the production rule table passed
// in as the scanner's rules, keyed on the semgrep rule's rule_family metadata —
// never from semgrep's own severity field. The two happen to agree on all
// thirteen rules of this corpus, so reading the wrong one is invisible on the
// corpus and would only surface after a rule changed. The table is the single
// source of truth, and a rule the table does not contain fails the scan rather
// than being assigned a default.
//
// The context window is rebuilt in Go from the file and the reported line
// number, using the same helper the regex engine uses. semgrep reports a
// snippet of its own, and using it would make the Tier 2 prompt depend on which
// engine produced the finding — which is precisely the difference the
// non-inferiority measurement is meant to be free of.
//
// The files to scan are passed explicitly rather than as a directory. Measured
// on semgrep 1.177.0, a directory target descends into venv/ and __pycache__/,
// which the regex engine skips, so the two engines would not agree on what the
// input even is. Passing the walked files makes the file set identical by
// construction, and it is also what makes the completeness check below possible.
type semgrepEngine struct {
	// scanner supplies the walk policy (which directories to skip, which
	// extensions to scan) and the rule table that severity is read from. It is
	// a source of policy, not a matcher: this engine never calls its ScanFile.
	scanner *Scanner
	// rulesPath is the --config argument: the semgrep rules file or directory.
	rulesPath string
	bin       string
	timeout   time.Duration
	// maxMemoryMB is the --max-memory argument. Zero would mean unlimited to
	// semgrep, so it is never left at zero: NewSemgrepEngine resolves the zero
	// value to DefaultSemgrepMaxMemoryMB.
	maxMemoryMB int

	// execFn is the process boundary. Production leaves it at runSemgrepCLI;
	// the tests replace it to pin the adapter's own logic without depending on
	// what the CLI does with a given input.
	execFn func(ctx context.Context, bin string, args []string) ([]byte, int, error)
}

// SemgrepLimits bounds one scan's resources. The zero value means the defaults,
// which is what a caller that has nothing to say about limits should pass.
type SemgrepLimits struct {
	// Timeout is the whole-scan deadline. Zero means DefaultSemgrepTimeout.
	Timeout time.Duration
	// MaxMemoryMB caps memory for a single file's rule run. Zero means
	// DefaultSemgrepMaxMemoryMB; there is no value that disables the cap,
	// because an unbounded scan under memory pressure fails the container
	// rather than the import.
	MaxMemoryMB int
}

// NewSemgrepEngine builds the adapter over the given policy and rules file.
func NewSemgrepEngine(scanner *Scanner, rulesPath string, limits SemgrepLimits) *semgrepEngine {
	timeout := limits.Timeout
	if timeout <= 0 {
		timeout = DefaultSemgrepTimeout
	}
	maxMemoryMB := limits.MaxMemoryMB
	if maxMemoryMB <= 0 {
		maxMemoryMB = DefaultSemgrepMaxMemoryMB
	}
	return &semgrepEngine{
		scanner:     scanner,
		rulesPath:   rulesPath,
		bin:         defaultSemgrepBin,
		timeout:     timeout,
		maxMemoryMB: maxMemoryMB,
		execFn:      runSemgrepCLI,
	}
}

// Name reports the engine identity.
func (e *semgrepEngine) Name() string { return EngineNameSemgrep }

// ── semgrep JSON shape ────────────────────────────────────
//
// Only the fields the adapter reads are declared. The payload has more, and
// leaving them out means a change to them cannot break the parse.

type semgrepOutput struct {
	Version string          `json:"version"`
	Results []semgrepResult `json:"results"`
	Errors  []semgrepError  `json:"errors"`
	Paths   struct {
		Scanned []string `json:"scanned"`
	} `json:"paths"`
}

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Severity string `json:"severity"`
		Metadata struct {
			Category   string `json:"category"`
			RuleFamily string `json:"rule_family"`
		} `json:"metadata"`
	} `json:"extra"`
}

type semgrepError struct {
	Code    int    `json:"code"`
	Level   string `json:"level"`
	Type    string `json:"type"`
	Message string `json:"message"`
}

// ── Scanning ──────────────────────────────────────────────

// ScanDirectory walks dir and matches the walked files with semgrep.
//
// An incomplete scan is returned as an error and never as a report. A report
// that exists will be read as a decision by something downstream, and the
// failure this guards against is the quiet one: semgrep exits 0 with an empty
// results array when it cannot read a target, so a reader that only consumes
// the report cannot tell "found nothing" from "never looked". The adapter
// therefore establishes completeness before it reports anything, and
// Report.ScanComplete is true on every report it does return.
func (e *semgrepEngine) ScanDirectory(dir string) (*Report, error) {
	report, _, err := e.scan(dir, false)
	return report, err
}

// ScanDirectoryWithLines is ScanDirectory plus a per-file line count, which the
// file-level LLM prompt needs. Both entry points go through scan, so neither
// can drift from the other's completeness checks.
func (e *semgrepEngine) ScanDirectoryWithLines(dir string) (*Report, map[string]int, error) {
	return e.scan(dir, true)
}

func (e *semgrepEngine) scan(dir string, withLineCounts bool) (*Report, map[string]int, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("scan directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("%s is not a directory", dir)
	}

	targets, err := e.walkTargets(dir)
	if err != nil {
		return nil, nil, err
	}

	var lineCounts map[string]int
	if withLineCounts {
		lineCounts = e.countLines(targets)
	}

	// A directory with nothing to scan is complete, not failed: there is no
	// input the scan could have missed, and semgrep is not invoked at all
	// because an empty target list would make it scan its own default root.
	if len(targets) == 0 {
		return e.stamp(e.scanner.buildReport(dir, 0, nil, false)), lineCounts, nil
	}

	output, err := e.run(targets)
	if err != nil {
		return nil, nil, err
	}

	findings, err := e.buildFindings(output, targets)
	if err != nil {
		return nil, nil, err
	}

	// Sort before capping, not after: the cap keeps the first N findings, so an
	// order that varies between runs would make a truncated scan keep a
	// different set each time and the reports stop being comparable.
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].RuleID < findings[j].RuleID
	})

	truncated := false
	if len(findings) > e.scanner.config.MaxFindings {
		findings = findings[:e.scanner.config.MaxFindings]
		truncated = true
	}

	// buildReport is shared with the regex engine so that HighCount, MediumCount
	// and Passed are computed by one piece of code. Passed is highCount == 0 on
	// both arms; a report that blocked on one engine's severities and not the
	// other's would make the two arms incomparable for reasons that have nothing
	// to do with matching.
	report := e.scanner.buildReport(dir, len(targets), findings, truncated)
	report.EngineVersion = output.Version
	report.ParserErrors = len(output.Errors)
	report.ProcessExitCode = 0
	return e.stamp(report), lineCounts, nil
}

// stamp records what the adapter knows about its own scan.
//
// ScanComplete is set explicitly rather than left to the zero value, whose
// meaning is the opposite. By the time a report exists every completeness check
// has passed, so this is true on every report this engine returns; an
// incomplete scan has already become an error.
func (e *semgrepEngine) stamp(report *Report) *Report {
	if report == nil {
		return nil
	}
	report.Engine = EngineNameSemgrep
	report.ScanComplete = true
	return report
}

// walkTargets returns the files to scan, in walk order.
//
// This repeats the walk the regex scanner performs rather than sharing it. The
// shared part is the policy — SkipDirs and Extensions come from the same Config,
// so a directory added there is skipped by both engines — while the walk itself
// is left alone because the regex scanner's walk stops early at the finding cap,
// and a scan that covers a different set of files depending on how many findings
// it has found is not a baseline anything should be measured against.
func (e *semgrepEngine) walkTargets(dir string) ([]string, error) {
	var targets []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if e.scanner.config.SkipDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !e.scanner.hasMatchingExtension(path) {
			return nil
		}
		targets = append(targets, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk directory: %w", err)
	}
	return targets, nil
}

// countLines reads each target to report its line count. A file that cannot be
// read is left out, which is the regex scanner's behaviour too.
func (e *semgrepEngine) countLines(targets []string) map[string]int {
	counts := make(map[string]int, len(targets))
	for _, path := range targets {
		content, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		counts[path] = len(strings.Split(string(content), "\n"))
	}
	return counts
}

// semgrepArgs is the argument vector, kept apart from the invocation so that the
// contract can be asserted without running anything.
func (e *semgrepEngine) semgrepArgs(targets []string) []string {
	args := []string{
		"scan",
		"--config", e.rulesPath,
		"--json",
		"--quiet",
		"--disable-version-check",
		// Without this semgrep consults .gitignore, which would make the files
		// scanned depend on the checkout rather than on the walk, so the same
		// code could scan differently in two environments.
		"--no-git-ignore",
		// Bounds one rule run. A run that exceeds it lands in the errors array,
		// which fails the scan; an unbounded run that exceeds the container's
		// memory takes every other process in the domain with it.
		"--max-memory", strconv.Itoa(e.maxMemoryMB),
	}
	return append(args, targets...)
}

// run invokes semgrep and turns every way the invocation can fail into an error.
func (e *semgrepEngine) run(targets []string) (*semgrepOutput, error) {
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	stdout, exitCode, err := e.execFn(ctx, e.bin, e.semgrepArgs(targets))
	if err != nil {
		return nil, fmt.Errorf("semgrep did not run: %w", err)
	}
	// A non-zero exit is not "found something": measured on 1.177.0, semgrep
	// exits 0 whether or not it reports findings. Any other status therefore
	// means the run itself failed, and its output must not be read as a result.
	if exitCode != 0 {
		return nil, fmt.Errorf("semgrep exited %d", exitCode)
	}

	var output semgrepOutput
	if err := json.Unmarshal(stdout, &output); err != nil {
		return nil, fmt.Errorf("parse semgrep output: %w", err)
	}

	// semgrep's own error list is the only signal for the case that matters
	// most: an unreadable target produces an empty results array and exit code
	// 0, so a reader that stops here reports a clean scan of code it never read.
	if len(output.Errors) > 0 {
		return nil, fmt.Errorf("semgrep reported %d error(s), first: %s (%s)",
			len(output.Errors), output.Errors[0].Message, output.Errors[0].Type)
	}

	// A run that reports no error and still did not read a file it was given is
	// the same failure by another route. The targets are known exactly because
	// they were passed explicitly, so the set can be compared rather than
	// trusted.
	scanned := make(map[string]bool, len(output.Paths.Scanned))
	for _, p := range output.Paths.Scanned {
		scanned[cleanAbs(p)] = true
	}
	var unread []string
	for _, target := range targets {
		if !scanned[cleanAbs(target)] {
			unread = append(unread, target)
		}
	}
	if len(unread) > 0 {
		return nil, fmt.Errorf("semgrep did not scan %d of %d file(s), first: %s",
			len(unread), len(targets), unread[0])
	}

	return &output, nil
}

// buildFindings maps the payload's results onto TAA findings.
func (e *semgrepEngine) buildFindings(output *semgrepOutput, targets []string) ([]Finding, error) {
	// Severity, category and description are read from the production rule
	// table, keyed on the family the semgrep rule declares.
	byID := make(map[string]Rule, len(e.scanner.rules))
	for _, r := range e.scanner.rules {
		byID[r.ID] = r
	}

	// semgrep returns the path it was given, but it is free to normalise one, so
	// the reported path is resolved back to the string the walk produced. The
	// file name in a finding has to be the same string on both arms or reports
	// stop being comparable and isTestFile starts disagreeing about the same
	// file.
	targetOf := make(map[string]string, len(targets))
	for _, t := range targets {
		targetOf[cleanAbs(t)] = t
	}

	// Findings are grouped by file so each file is read at most once, and so a
	// file semgrep names but the walk did not produce is caught.
	byFile := make(map[string][]semgrepResult)
	var fileOrder []string
	for _, res := range output.Results {
		key := cleanAbs(res.Path)
		if _, ok := targetOf[key]; !ok {
			return nil, fmt.Errorf("semgrep reported a finding in %s, which is not one of the %d file(s) it was given",
				res.Path, len(targets))
		}
		if _, seen := byFile[key]; !seen {
			fileOrder = append(fileOrder, key)
		}
		byFile[key] = append(byFile[key], res)
	}

	// Every unmapped family is collected before failing, so an operator fixing a
	// rules change sees all of it rather than one rule per run.
	var unmapped []string
	seenUnmapped := make(map[string]bool)
	for _, res := range output.Results {
		family := res.Extra.Metadata.RuleFamily
		if _, ok := byID[family]; ok {
			continue
		}
		if !seenUnmapped[family] {
			seenUnmapped[family] = true
			if family == "" {
				unmapped = append(unmapped, fmt.Sprintf("%s (no rule_family)", res.CheckID))
			} else {
				unmapped = append(unmapped, fmt.Sprintf("%s -> %s", family, res.CheckID))
			}
		}
	}
	if len(unmapped) > 0 {
		// An unmapped rule is not assigned a default severity. The default would
		// have to be MEDIUM to be safe, and MEDIUM is the level where the gate
		// and assist policies disagree, so the same misconfiguration would block
		// in one deployment and pass in another.
		return nil, fmt.Errorf("semgrep rules map to no TAA rule: %s", strings.Join(unmapped, ", "))
	}

	var findings []Finding
	for _, key := range fileOrder {
		path := targetOf[key]
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		lines := strings.Split(string(content), "\n")

		for _, res := range byFile[key] {
			rule := byID[res.Extra.Metadata.RuleFamily]

			// The line number indexes the file the adapter just read, so it is
			// checked rather than used: a line the file does not have cannot be
			// turned into a snippet or a context window, and an empty window
			// would send the LLM a finding with no code attached.
			if res.Start.Line < 1 || res.Start.Line > len(lines) {
				return nil, fmt.Errorf("semgrep reported line %d of %s, which has %d line(s)",
					res.Start.Line, path, len(lines))
			}
			i := res.Start.Line - 1

			findings = append(findings, Finding{
				File:   path,
				Line:   res.Start.Line,
				RuleID: rule.ID,
				// Category and Description come from the table so that a finding
				// reads the same downstream whichever engine produced it.
				Category:    rule.Category,
				Severity:    rule.Severity,
				Description: rule.Description,
				CodeSnippet: strings.TrimSpace(lines[i]),
				// The same window the regex engine builds, from the same helper:
				// contextWindow(lines, i-3, i) and contextWindow(lines, i+1, i+4).
				ContextBefore: contextWindow(lines, i-3, i),
				ContextAfter:  contextWindow(lines, i+1, i+4),
				EngineRuleID:  shortCheckID(res.CheckID),
				RuleFamily:    res.Extra.Metadata.RuleFamily,
			})
		}
	}
	return findings, nil
}

// shortCheckID reduces semgrep's check_id to the rule's own name.
//
// semgrep qualifies the id with the path of the rules file it came from, so the
// same rule reports as models.audit.semgrep.rules.python.taa-env-secret-python
// or as /etc/taa/rules.python.taa-env-secret-python depending on where the file
// sits. The last segment is the stable identity, and it is the form the design
// document names.
func shortCheckID(checkID string) string {
	if i := strings.LastIndex(checkID, "."); i >= 0 {
		return checkID[i+1:]
	}
	return checkID
}

// cleanAbs makes a path comparable regardless of how the two sides spelled it.
func cleanAbs(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return abs
}

// runSemgrepCLI is the production process boundary.
//
// A non-zero exit is returned as data rather than as an error, so the caller can
// tell "the CLI ran and failed" from "the CLI never ran"; only a failure to
// start the process, or an expired deadline, is an error here.
func runSemgrepCLI(ctx context.Context, bin string, args []string) ([]byte, int, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, -1, fmt.Errorf("scan deadline: %w (stderr: %s)", ctxErr, firstLine(stderr.String()))
	}
	if err == nil {
		return stdout.Bytes(), 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return stdout.Bytes(), exitErr.ExitCode(), nil
	}
	return nil, -1, fmt.Errorf("start %s: %w", bin, err)
}

// firstLine keeps an error message to one line of stderr, which is enough to
// name the cause without pasting a CLI's whole output into a log.
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if s == "" {
		return "no stderr"
	}
	return s
}
