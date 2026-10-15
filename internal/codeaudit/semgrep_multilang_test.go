package codeaudit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSemgrepEngine_MultiLanguageRules verifies that Semgrep engine can load
// a rules directory and scan multiple languages: Go, C/C++, Java, and Shell.
func TestSemgrepEngine_MultiLanguageRules(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep binary not installed on host, skipping CLI test")
	}

	rulesDir, err := filepath.Abs("../../models/audit/semgrep/rules")
	if err != nil {
		t.Fatalf("failed to resolve rules directory: %v", err)
	}
	if _, err := os.Stat(rulesDir); err != nil {
		t.Fatalf("rules directory %s does not exist: %v", rulesDir, err)
	}

	engine := NewSemgrepEngine(DefaultScanner(), rulesDir, SemgrepLimits{})

	tmpDir := t.TempDir()

	// 1. Go sample (CMD_001 and NET_001)
	goCode := `package main

import (
	"context"
	"net/http"
	"os/exec"
)

func run(c string) {
	exec.Command("sh", "-c", c).Run()
	exec.CommandContext(context.Background(), "bash", "-c", c).Run()
}

func fetch(url string) {
	http.Get(url)
	http.Post(url, "text/plain", nil)
	client := &http.Client{}
	client.Do(nil)
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte(goCode), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. C/C++ sample (CMD_001)
	cCode := `#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void execute_cmd(const char *cmd) {
	system(cmd);
	popen(cmd, "r");
	char *args[] = {"/bin/sh", NULL};
	execve("/bin/sh", args, NULL);
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.c"), []byte(cCode), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Java sample (CMD_001)
	javaCode := `public class Runner {
	public static void main(String[] args) throws Exception {
		Runtime.getRuntime().exec(args[0]);
		new ProcessBuilder("sh", "-c", args[0]).start();
	}
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.java"), []byte(javaCode), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Shell sample (CMD_001)
	shCode := `#!/bin/bash
eval "$1"
bash -c "$2"
sh -c "$3"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.sh"), []byte(shCode), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := engine.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if report.FilesCount != 4 {
		t.Fatalf("expected 4 files scanned, got %d", report.FilesCount)
	}

	// Verify we got findings for each language
	foundLangs := make(map[string]bool)
	ruleFamilies := make(map[string]bool)
	for _, f := range report.Findings {
		ext := filepath.Ext(f.File)
		foundLangs[ext] = true
		ruleFamilies[f.RuleID] = true
	}

	for _, ext := range []string{".go", ".c", ".java", ".sh"} {
		if !foundLangs[ext] {
			t.Errorf("expected security finding in %s file, but found none", ext)
		}
	}

	if !ruleFamilies["CMD_001"] {
		t.Errorf("expected CMD_001 findings, got %v", ruleFamilies)
	}
	if !ruleFamilies["NET_001"] {
		t.Errorf("expected NET_001 findings, got %v", ruleFamilies)
	}

	if len(report.Findings) < 10 {
		t.Fatalf("expected at least 10 multi-language findings across patterns, got %d", len(report.Findings))
	}
}

// ── GA-11 language coverage ──────────────────────────────
//
// The target set is semgrep's GA tier: C#, Go, Java, JavaScript, JSON, PHP,
// Python, Ruby, Scala, Terraform and TypeScript. Python was already covered;
// the rest are what these tests pin down. For JSON the covered extension is the
// notebook one only - see ga11SourceExtensions.

// rulesRelativeDir is the rules tree relative to this package directory, which
// is the working directory a `go test` run uses.
const rulesRelativeDir = "../../models/audit/semgrep/rules"

// ga11SourceExtensions is the extension set the walk must admit for the GA-11
// languages to be scanned at all. It is spelled out rather than derived from
// semgrep's language registry because the registry is semgrep's and the walk is
// ours: the two are free to disagree, and this list is what decides.
//
// JSON contributes ".ipynb" and not ".json", and the pair is the decision
// rather than two separate ones. Admitting ".json" would put every data file of
// a model package into a semgrep pass - the audit-100 benchmark alone carries
// 920 of them, and a tokenizer.json is megabytes of vocabulary that no rule
// reads. A notebook is the opposite case: the JSON is a container and its cell
// sources are code that executes, which is what the json pack reads, and the
// pack is gated to that one extension by a rule-level `paths: include`. So the
// walk admits the notebook, the pack refuses the data file, and
// TestIsSourceFileRejectsNonSource pins the ".json" half.
var ga11SourceExtensions = []string{
	// C#
	".cs",
	// Go
	".go",
	// Java
	".java",
	// JavaScript
	".cjs", ".js", ".jsx", ".mjs",
	// PHP
	".php", ".phtml", ".tpl",
	// Python
	".py", ".pyi",
	// Ruby
	".rb",
	// Scala
	".scala",
	// Terraform
	".hcl", ".tf", ".tfvars", ".tofu",
	// TypeScript
	".ts", ".tsx",
	// JSON (notebooks only, never ".json")
	".ipynb",
}

// TestIsSourceFileCoversGA11 pins the walk's admission of every GA-11
// extension. Before this, the switch admitted only .py .go .c .cpp .cu .h .hpp
// .java .sh - so a C#, JavaScript, TypeScript, PHP, Ruby, Scala or Terraform
// file in a model package was never handed to semgrep, and the rule packs that
// cover those languages had nothing to run on.
func TestIsSourceFileCoversGA11(t *testing.T) {
	e := NewSemgrepEngine(DefaultScanner(), "unused", SemgrepLimits{})
	for _, ext := range ga11SourceExtensions {
		// The path need not exist: isSourceFile decides on the extension alone,
		// which is the property under test.
		if path := "package/file" + ext; !e.isSourceFile(path) {
			t.Errorf("isSourceFile(%q) = false, want true: %s is a GA-11 source extension", path, ext)
		}
	}
}

// TestIsSourceFileRejectsNonSource keeps the walk off files that are not source.
// A semgrep pass over a safetensors or an ONNX blob is a scan that cannot finish
// inside the import deadline, and a .pyc is already-compiled bytes the source
// channel must not read as text.
//
// ".json" is here rather than in the covered list on purpose: it is the other
// half of the notebook decision. A JSON document is data, the benchmark's model
// packages carry hundreds of them, and the json pack is gated to ".ipynb" - so
// a ".json" file that reached semgrep would be scanned by nothing and cost the
// pass its budget for no finding.
func TestIsSourceFileRejectsNonSource(t *testing.T) {
	e := NewSemgrepEngine(NewScanner(nil, Config{Extensions: []string{".py"}}), "unused", SemgrepLimits{})
	for _, ext := range []string{".pt", ".bin", ".safetensors", ".onnx", ".pyc", ".so", ".png", ".gz", ".json"} {
		if path := "weights/model" + ext; e.isSourceFile(path) {
			t.Errorf("isSourceFile(%q) = true, want false: %s is not source", path, ext)
		}
	}
}

// TestDefaultRulesPathIsADirectory pins the load mechanism. Every pack declares
// its own `languages:`, and semgrep dispatches on that declaration, so one
// --config pointing at the rules tree loads all of them and applies each to its
// own language. Pointing at a single file - which is what this constant did
// when the only pack was python's - would silently leave every other pack
// unloaded no matter how many were added.
func TestDefaultRulesPathIsADirectory(t *testing.T) {
	if ext := filepath.Ext(DefaultSemgrepRulesPath); ext != "" {
		t.Errorf("DefaultSemgrepRulesPath = %q, want a directory: it ends in %q", DefaultSemgrepRulesPath, ext)
	}
	// The constant is relative to the repository root, which is two levels above
	// this package's directory.
	abs, err := filepath.Abs(filepath.Join("..", "..", DefaultSemgrepRulesPath))
	if err != nil {
		t.Fatalf("resolve %q: %v", DefaultSemgrepRulesPath, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		t.Fatalf("stat %s: %v", abs, err)
	}
	if !info.IsDir() {
		t.Fatalf("%s is not a directory", abs)
	}
	// It must name the same tree the CLI test validates, or one of the two tests
	// would be guarding a directory the other never reads.
	want, err := filepath.Abs(rulesRelativeDir)
	if err != nil {
		t.Fatalf("resolve %q: %v", rulesRelativeDir, err)
	}
	if abs != want {
		t.Errorf("DefaultSemgrepRulesPath resolves to %s, want %s", abs, want)
	}
}

// TestDefaultSkipDirsCoverBuildTrees pins the dependency trees the walk must not
// descend. Each is where a language ecosystem parks its dependencies: vendor for
// Go, target for Maven/Scala, bower_components for JavaScript. Scanning them
// would attribute a dependency's code to the package under audit, and would
// spend the scan budget on code the package does not ship.
func TestDefaultSkipDirsCoverBuildTrees(t *testing.T) {
	skip := DefaultConfig().SkipDirs
	for _, name := range []string{"vendor", "target", "dist", "build", ".tox", "bower_components", "Pods"} {
		if !skip[name] {
			t.Errorf("DefaultConfig().SkipDirs[%q] = false, want true", name)
		}
	}
	// The pre-existing entries must survive the addition.
	for _, name := range []string{".git", "__pycache__", "node_modules"} {
		if !skip[name] {
			t.Errorf("DefaultConfig().SkipDirs[%q] = false, want true: this entry predates the change", name)
		}
	}
}

// ruleIDLine matches a rule header in a rules file.
var ruleIDLine = regexp.MustCompile(`(?m)^\s*-\s*id:\s*(\S+)\s*$`)

// ruleFamilyLine matches a rule_family metadata entry in a rules file.
var ruleFamilyLine = regexp.MustCompile(`(?m)^\s*rule_family:\s*(\S+)\s*$`)

// ruleLanguagesLine matches the languages declaration of a rules file.
var ruleLanguagesLine = regexp.MustCompile(`(?m)^\s*languages:\s*\[(.+)\]\s*$`)

// ruleSeverityLine matches the severity of a single rule.
var ruleSeverityLine = regexp.MustCompile(`(?m)^\s*severity:\s*(\S+)\s*$`)

// semgrepSeverityWords maps a production severity to the word a semgrep rule
// file uses for it. Neither word is read by the engine, which takes severity
// from the table, so the mapping is a convention the packs are held to rather
// than a translation anything performs; keeping the two readings of one family
// equal is what makes reading the wrong one harmless.
func semgrepSeverityWords(severity string) (string, bool) {
	switch severity {
	case SeverityHigh:
		return "ERROR", true
	case SeverityMedium, SeverityLow:
		return "WARNING", true
	}
	return "", false
}

// TestRulePacksAreWellFormed lints every rule pack for the things that break a
// scan, plus the one that quietly misreports it. It is a text lint rather than
// a parse because the engine never parses rules - it hands --config to the
// semgrep CLI - so the only Go-side authority on the rule table is the
// rule_family each rule names.
//
// The load-bearing check is the family one. semgrep_engine.go reads
// Extra.Metadata.RuleFamily and collects a rule carrying no family into
// `unmapped`, which fails the whole scan; a family the production table does
// not contain fails it a few lines later. Neither is visible until a scan runs,
// and by then the failure is one report with no verdict rather than a message
// naming the pack that caused it.
//
// The severity check is the one that cannot fail a scan, which is why it needs
// a test: the engine takes severity from the table and never from the rule
// file, so a pack whose word disagrees reports correctly and lies to whoever
// reads it. The go pack carried ERROR on the two families the table calls
// medium until this assertion was added.
func TestRulePacksAreWellFormed(t *testing.T) {
	packs, err := filepath.Glob(filepath.Join(rulesRelativeDir, "*", "rules.yaml"))
	if err != nil {
		t.Fatalf("glob rule packs: %v", err)
	}
	if len(packs) == 0 {
		t.Fatalf("no rule packs under %s", rulesRelativeDir)
	}

	known := make(map[string]string)
	for _, r := range DefaultRules() {
		known[r.ID] = r.Severity
	}

	seen := make(map[string]string)
	for _, pack := range packs {
		content, err := os.ReadFile(pack)
		if err != nil {
			t.Fatalf("read %s: %v", pack, err)
		}
		text := string(content)

		if m := ruleLanguagesLine.FindStringSubmatch(text); m == nil {
			t.Errorf("%s: no languages: [...] declaration", pack)
		} else if strings.TrimSpace(m[1]) == "" {
			t.Errorf("%s: languages: [] is empty, so no file would ever match it", pack)
		}

		ids := ruleIDLine.FindAllStringSubmatchIndex(text, -1)
		if len(ids) == 0 {
			t.Errorf("%s: no rules", pack)
		}
		for i, m := range ids {
			id := text[m[2]:m[3]]
			// Blocks are sliced rather than counted. Comparing the number of
			// ids with the number of rule_family entries cannot see the pair of
			// edits that cancels out - two families under one rule and none
			// under another keeps both totals equal - and it is the rule with no
			// family that fails the whole scan at run time.
			end := len(text)
			if i+1 < len(ids) {
				end = ids[i+1][0]
			}
			families := ruleFamilyLine.FindAllStringSubmatch(text[m[0]:end], -1)
			if len(families) != 1 {
				t.Errorf("%s: rule %s carries %d rule_family entries, want exactly 1",
					pack, id, len(families))
				continue
			}
			family := families[0][1]
			severity, inTable := known[family]
			if !inTable {
				t.Errorf("%s: rule %s names rule_family %q, which is not in the production rule table",
					pack, id, family)
			} else if m := ruleSeverityLine.FindStringSubmatch(text[m[0]:end]); m == nil {
				t.Errorf("%s: rule %s declares no severity", pack, id)
			} else if want, ok := semgrepSeverityWords(severity); !ok {
				t.Errorf("%s: rule %s maps to severity %q, which this test cannot express as a semgrep word: "+
					"add it to semgrepSeverityWords rather than letting the packs drift", pack, id, severity)
			} else if m[1] != want {
				t.Errorf("%s: rule %s is severity %s while the table calls family %s %q, which semgrep spells %s: "+
					"the engine reads the table, so this file's word is only ever read by a human or by semgrep "+
					"run by hand, and the mismatch can sit here for as long as nobody runs either",
					pack, id, m[1], family, severity, want)
			}
			// The id names the family the rule is for and rule_family says what
			// the engine will resolve it to. A rule whose two disagree fires,
			// reports its own id, and carries another family's severity.
			named := ""
			for suffix, familyID := range ga11FamilyIDs {
				if strings.HasPrefix(id, "taa-"+suffix+"-") {
					named = familyID
					break
				}
			}
			switch {
			case named == "":
				t.Errorf("%s: rule id %q is not taa-<family>-<language> for any of the %d families",
					pack, id, len(ga11FamilyIDs))
			case named != family:
				t.Errorf("%s: rule %s is named for %s but declares rule_family %s: the engine reads severity "+
					"and category from that family, so the finding is reported as another family's",
					pack, id, named, family)
			}
			if !strings.HasPrefix(id, "taa-") {
				t.Errorf("%s: rule id %q does not start with taa-", pack, id)
			}
			if prev, dup := seen[id]; dup {
				t.Errorf("%s: rule id %q already used in %s", pack, id, prev)
			}
			seen[id] = pack
		}
	}
}

// TestRulePacksValidateWithSemgrep runs the authoritative parser over all packs
// at once. This is the check the text lint above cannot make: semgrep is what
// actually reads these files, and one malformed pack makes the whole --config
// fail, which turns every audit into a report with no verdict.
//
// Its summary line is read rather than only its exit code. The exit code says
// the tree parsed; the count says how much of it did, and comparing that count
// with the ids the lint found gives the two authorities over the same files a
// way to disagree. A pack semgrep skipped, or a rule it could not read, is a
// smaller number here - and it is otherwise invisible, because a truncated but
// valid rules file loads fewer rules and still scans cleanly.
func TestRulePacksValidateWithSemgrep(t *testing.T) {
	bin := semgrepCLI(t)
	rulesDir := repoSemgrepRules(t)
	out, err := exec.Command(bin, "--validate", "--config", rulesDir).CombinedOutput()
	if err != nil {
		t.Fatalf("semgrep --validate %s failed: %v\n%s", rulesDir, err, out)
	}
	sum := semgrepValidateSummary.FindStringSubmatch(string(out))
	if sum == nil {
		t.Fatalf("semgrep --validate printed no summary line to check:\n%s", out)
	}
	if sum[1] != "0" {
		t.Errorf("semgrep --validate reported %s configuration error(s):\n%s", sum[1], out)
	}
	if have, want := sum[2], strconv.Itoa(countRuleIDs(t)); have != want {
		t.Errorf("semgrep loaded %s rule(s) from the packs and the lint counted %s id(s): a rule the "+
			"lint sees and semgrep does not is a rule no scan will ever run", have, want)
	}
}

// semgrepValidateSummary matches the summary line of `semgrep --validate`:
// "Configuration is valid - found 0 configuration error(s), and 115 rule(s)."
var semgrepValidateSummary = regexp.MustCompile(`found (\d+) configuration error\(s\), and (\d+) rule\(s\)`)

// countRuleIDs counts the rule ids across every pack, which is the same walk the
// lint above makes and the number semgrep's own summary is compared against.
func countRuleIDs(t *testing.T) int {
	t.Helper()
	packs, err := filepath.Glob(filepath.Join(rulesRelativeDir, "*", "rules.yaml"))
	if err != nil {
		t.Fatalf("glob rule packs: %v", err)
	}
	total := 0
	for _, pack := range packs {
		content, err := os.ReadFile(pack)
		if err != nil {
			t.Fatalf("read %s: %v", pack, err)
		}
		total += len(ruleIDLine.FindAll(content, -1))
	}
	return total
}

// ── per-language samples ─────────────────────────────────
//
// Every pack carries a positive sample that must make each of its families
// fire, and a negative one - benign code of the same language, written with the
// shapes the pack must not fire on - that must produce nothing. The packs were
// written against these files, so this is the regression that keeps a later
// edit from quietly disabling a family: a family that stops matching fails
// here, which is the failure that matters most because it is otherwise silent.

// ga11FamilySuffixes is the family half of the rule id convention
// taa-<family>-<language>, for the thirteen families the full packs cover.
var ga11FamilySuffixes = []string{
	"cmd-exec", "net-general", "net-socket", "dyn-eval", "fil-probe",
	"env-secret", "obf-exec", "secret-exfiltration", "per-backdoor",
	"emb-data-dump", "emb-copy-export", "emb-log-dump", "emb-stego-weight",
}

// ga11FamilyIDs maps each family suffix to the rule id the production table
// gives that family, which is what a pack declares as its rule_family.
//
// It is written out here rather than read from DefaultRules() or from the packs
// on purpose: it is the independent side of the comparison. The binding it
// pins is the one that decides how a finding is treated - the engine looks the
// declared family up in the production table and takes severity, category and
// description from that entry - so a rule pointed at another family still
// fires, still carries its own rule id, and silently changes from MEDIUM to
// HIGH or the other way. Nothing else in this package compares the two sides.
var ga11FamilyIDs = map[string]string{
	"cmd-exec":            "CMD_001",
	"net-general":         "NET_001",
	"net-socket":          "NET_002",
	"dyn-eval":            "DYN_001",
	"fil-probe":           "FIL_001",
	"env-secret":          "ENV_001",
	"obf-exec":            "OBF_001",
	"secret-exfiltration": "EXF_001",
	"per-backdoor":        "PER_001",
	"emb-data-dump":       "EMB_001",
	"emb-copy-export":     "EMB_002",
	"emb-log-dump":        "EMB_003",
	"emb-stego-weight":    "EMB_004",
}

// ga11SampleFiles pairs each positive sample under testdata/ga11 with the
// negative beside it and the rule ids the positive must produce. The family
// list is per sample rather than global because the packs do not all cover the
// same thirteen: terraform and json cover five and two, and the JavaScript .js
// sample covers a subset because the .ts one beside it already pins the rest.
//
// The eleven packs of the GA-11 matrix are the ones listed here. Three packs on
// disk are deliberately absent, and the gap is named rather than left implied:
// python is the benchmark-backed pack whose parity is guarded end to end by
// TestGoEngineMatchesBenchmarkRegexArm (gated on TAA_CORPUS_PARITY=1), so a
// hand-written sample here would only restate weaker evidence; c and shell are
// the two Alpha packs this change does not touch, and their one and three
// rules are exercised by TestSemgrepEngine_MultiLanguageRules. A family that
// goes dead in any of those three is therefore not caught by the matrix below -
// that is the residual gap of this file, not an oversight to be rediscovered.
//
// The negatives are near misses rather than unrelated code, because the failure
// this test must catch is a predicate being widened or deleted. Each negative
// calls the sink of every family whose rule narrows on an argument and hands it
// an argument that fails that one predicate, so removing the predicate makes
// the file match and the test red. A negative that never called the API - which
// is what these three files were before - stays green through that same edit.
// The families whose rule matches the bare primitive with no predicate at all
// (cmd-exec, net-general, net-socket, dyn-eval, obf-exec, and the sinks they
// share with secret-exfiltration) have no predicate to delete, so no benign
// call exists for them; they are pinned by the positive alone, and the
// omissions are named in each negative file's header.
var ga11SampleFiles = []struct {
	language string
	families []string
	positive string
	negative string
}{
	{"csharp", ga11FamilySuffixes, "csharp/positive.cs", "csharp/negative.cs"},
	{"go", ga11FamilySuffixes, "go/positive.go", "go/negative.go"},
	{"java", ga11FamilySuffixes, "java/positive.java", "java/negative.java"},
	// The merged pack's two extensions. The .ts sample is the full thirteen; the
	// .js sample is a subset, and its rows are here so the pack cannot stop
	// reaching one of the two languages it declares.
	{"javascript", ga11FamilySuffixes, "javascript/positive.ts", "javascript/negative.ts"},
	{"javascript", []string{
		"cmd-exec", "net-general", "fil-probe", "env-secret", "secret-exfiltration",
	}, "javascript/positive.js", "javascript/negative.js"},
	// Two families, and the notebook extension is the only one the pack applies
	// to - see the decoy check in the test.
	{"json", []string{"cmd-exec", "env-secret"}, "json/positive.ipynb", "json/negative.ipynb"},
	{"php", ga11FamilySuffixes, "php/positive.php", "php/negative.php"},
	{"ruby", ga11FamilySuffixes, "ruby/positive.rb", "ruby/negative.rb"},
	{"scala", ga11FamilySuffixes, "scala/positive.scala", "scala/negative.scala"},
	// Five of thirteen: terraform has no primitive for the other eight, and the
	// pack lists them as structurally absent rather than writing dead rules.
	{"terraform", []string{
		"cmd-exec", "net-general", "env-secret", "secret-exfiltration", "emb-data-dump",
	}, "terraform/positive.tf", "terraform/negative.tf"},
}

// ga11SamplesDir holds the positive and negative samples, one directory per
// language.
const ga11SamplesDir = "testdata/ga11"

// ga11SampleDirs lists the sample directories in table order, without repeats.
// The javascript directory is one entry because its two rows - the .ts sample
// and the .js one beside it - live in the same directory.
func ga11SampleDirs() []string {
	var dirs []string
	seen := make(map[string]bool, len(ga11SampleFiles))
	for _, s := range ga11SampleFiles {
		dir := filepath.Dir(s.positive)
		if seen[dir] {
			continue
		}
		seen[dir] = true
		dirs = append(dirs, dir)
	}
	return dirs
}

// TestGA11PacksMatchTheirSamples scans each sample directory and asserts, per
// language, that the positive file fires exactly the families it should and the
// negative file fires none.
//
// One scan per language rather than one over the whole tree, and that shape is
// measured rather than stylistic. The engine caps a report at the scanner's
// MaxFindings - 200 by default - after sorting, and semgrep reports one finding
// per match rather than one per rule, so a file with several calls to the same
// shape produces several findings for one family. The whole sample tree
// therefore lands past the cap: measured through the engine, the 20 sample files
// produced 200 findings with Truncated set, and what the cap removed was the
// tail of the sorted list, which was exactly the last three languages
// alphabetically. Ruby kept its first three families, scala and terraform kept
// none, and the scan reported success - a family that stops matching and a
// family cut off by the cap are indistinguishable there. A per-language scan
// stays far below the cap, so the two can be told apart.
//
// Scanning the directories in place rather than copying them into t.TempDir() is
// what makes this a test of the real path: the engine walks the directory
// itself, decides which extensions are source, and passes semgrep the explicit
// file list. A sample that the walk stopped admitting therefore fails as a
// missing family rather than passing as an empty scan.
func TestGA11PacksMatchTheirSamples(t *testing.T) {
	semgrepCLI(t)
	rulesDir := repoSemgrepRules(t)

	for _, dir := range ga11SampleDirs() {
		t.Run(dir, func(t *testing.T) {
			engine := NewSemgrepEngine(DefaultScanner(), rulesDir, SemgrepLimits{})
			report, err := engine.ScanDirectory(filepath.Join(ga11SamplesDir, dir))
			if err != nil {
				t.Fatalf("scan %s: %v", filepath.Join(ga11SamplesDir, dir), err)
			}

			rows := 0
			for _, s := range ga11SampleFiles {
				if filepath.Dir(s.positive) == dir {
					rows++
				}
			}
			// Every sample file in the directory, and nothing else: a decoy that
			// should not be walked makes the count too high, and an extension the
			// walk stopped admitting makes it too low, both before any rule is
			// consulted.
			if want := rows * 2; report.FilesCount != want {
				t.Errorf("scanned %d file(s) under %s, want %d: the samples are the only source there",
					report.FilesCount, dir, want)
			}
			// The cap is production's and one language's samples stay well below
			// it. A truncated scan here means the fixture grew past it, which is
			// the one case where this test could pass with a family missing.
			if report.Truncated {
				t.Errorf("%s hit the %d-finding cap: the tail of the report is missing",
					dir, DefaultScanner().config.MaxFindings)
			}

			byFile := make(map[string][]Finding, len(report.Findings))
			for _, f := range report.Findings {
				name := filepath.Base(f.File)
				byFile[name] = append(byFile[name], f)
			}

			for _, s := range ga11SampleFiles {
				if filepath.Dir(s.positive) != dir {
					continue
				}
				pos, neg := filepath.Base(s.positive), filepath.Base(s.negative)

				want := make(map[string]bool, len(s.families))
				for _, family := range s.families {
					want["taa-"+family+"-"+s.language] = true
				}
				got := make(map[string]bool, len(byFile[pos]))
				for _, f := range byFile[pos] {
					got[f.EngineRuleID] = true
					if !want[f.EngineRuleID] {
						t.Errorf("%s:%d: %s fired on the positive sample but is not one of its families",
							pos, f.Line, f.EngineRuleID)
					}
					// The rule id is only what fired; RuleID is what the engine
					// resolved rule_family to, and that is what carries the
					// severity. Both are checked because the pack lint can only
					// read the file, while this is the binding a scan acts on.
					family := strings.TrimSuffix(strings.TrimPrefix(f.EngineRuleID, "taa-"), "-"+s.language)
					if id, ok := ga11FamilyIDs[family]; !ok {
						t.Errorf("%s:%d: %s does not name a family in the matrix", pos, f.Line, f.EngineRuleID)
					} else if f.RuleID != id {
						t.Errorf("%s:%d: %s resolved to %s, want %s: rule_family decides the severity and "+
							"category of every finding, so a rule pointed at another family is a severity change",
							pos, f.Line, f.EngineRuleID, f.RuleID, id)
					}
				}
				for id := range want {
					if !got[id] {
						t.Errorf("%s: %s did not fire on the positive sample: the family is dead", pos, id)
					}
				}

				if hits := byFile[neg]; len(hits) > 0 {
					ids := make([]string, 0, len(hits))
					for _, f := range hits {
						ids = append(ids, fmt.Sprintf("%s:%d %s", neg, f.Line, f.EngineRuleID))
					}
					t.Errorf("the negative sample produced %d finding(s):\n  %s",
						len(hits), strings.Join(ids, "\n  "))
				}
			}
		})
	}

	// The walk refusing ".json" is one half of the notebook decision, and the
	// per-directory scan above is where it is asserted: the json directory holds
	// three files and only two of them are samples, so a FilesCount of 2 there
	// is the decoy having been left alone.
	//
	// The other half is the pack filtering itself to ".ipynb", which is
	// invisible from Go because semgrep applies it, and the check for it is a
	// controlled pair rather than one scan. The obvious assertion - hand semgrep
	// the decoy, see no findings - measures nothing on its own: measured on
	// 1.177.0, a file that every rule excludes by a paths filter does not appear
	// in paths.scanned at all, so the run answers scanned=[] with no results and
	// no errors, and "no findings" is then a statement about a file nothing
	// read. The pair is decoy.json beside a byte-identical copy named
	// decoy.ipynb: same bytes, so the extension is the only variable, one read
	// and matched, the other neither.
	//
	// Only the .ipynb half lives in its own directory, because a third file in
	// the json directory would change the sample count asserted above. The copy
	// is not shaped like a notebook and does not need to be: the pack is text
	// only and never parses the document, so the experiment only has to hold the
	// bytes equal.
	decoyJSON := filepath.Join(ga11SamplesDir, "json", "decoy.json")
	decoyIPYNB := filepath.Join(ga11SamplesDir, "jsonfilter", "decoy.ipynb")
	asData, err := os.ReadFile(decoyJSON)
	if err != nil {
		t.Fatalf("read %s: %v", decoyJSON, err)
	}
	asNotebook, err := os.ReadFile(decoyIPYNB)
	if err != nil {
		t.Fatalf("read %s: %v", decoyIPYNB, err)
	}
	if !bytes.Equal(asData, asNotebook) {
		t.Fatalf("%s and %s are no longer the same bytes, so the pair below no longer isolates the "+
			"extension and its result stops meaning anything", decoyJSON, decoyIPYNB)
	}

	if got := directScan(t, rulesDir, decoyJSON); len(got.Results) != 0 {
		t.Errorf("the json pack matched a plain .json data file: %d finding(s), first %s",
			len(got.Results), shortCheckID(got.Results[0].CheckID))
	}
	notebook := directScan(t, rulesDir, decoyIPYNB)
	if len(notebook.Paths.Scanned) != 1 {
		t.Fatalf("semgrep scanned %d target(s) when handed the notebook twin, want 1: the twin is what "+
			"makes the pairing an experiment, and it has to be read for its findings to count",
			len(notebook.Paths.Scanned))
	}
	if len(notebook.Results) == 0 {
		t.Errorf("the json pack matched nothing in the notebook twin, so these bytes are matchable by " +
			"nothing and the silence over the .json copy says nothing about the filter")
	}

	// And the two halves are one decision rather than two settings that happen
	// to agree: the engine refuses to report a scan it did not read. Were the
	// walk to admit ".json", the decoy would reach semgrep as a target, the
	// filter would drop it, and this completeness check would turn the mismatch
	// into a failed scan - loudly, instead of reporting a clean pass over a file
	// no rule ever saw.
	decoyEngine := NewSemgrepEngine(DefaultScanner(), rulesDir, SemgrepLimits{})
	if _, err := decoyEngine.run([]string{decoyJSON}); err == nil {
		t.Errorf("the engine scanned %s without complaint: a target the pack filters out must fail the "+
			"completeness check, not be reported as scanned", decoyJSON)
	} else if !strings.Contains(err.Error(), "did not scan") {
		t.Errorf("scanning %s failed with %q, want the completeness error", decoyJSON, err)
	}
}

// directScan runs the packs over one file through the CLI instead of through
// the engine. It is the only way to see what semgrep itself decided about the
// file: the engine rejects any target it did not read, so it cannot report the
// case where semgrep read nothing, which is exactly the case the decoy pair
// turns on.
func directScan(t *testing.T, rulesDir, target string) semgrepOutput {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	stdout, code, err := runSemgrepCLI(ctx, "semgrep", []string{
		"scan", "--config", rulesDir, "--json", "--quiet",
		"--disable-version-check", "--no-git-ignore", target,
	})
	if err != nil {
		t.Fatalf("run semgrep on %s: %v", target, err)
	}
	if code != 0 {
		t.Fatalf("semgrep exited %d on %s", code, target)
	}
	var out semgrepOutput
	if err := json.Unmarshal(stdout, &out); err != nil {
		t.Fatalf("parse semgrep output for %s: %v", target, err)
	}
	return out
}

// ── upstream fixture smoke ───────────────────────────────
//
// This is the only check that runs the packs over code written by someone else.
// The embedded samples above prove a family can fire; they cannot prove the
// pack survives a real package, because they were written to be matched.
//
// WHAT IT PROVES: every pack loads, runs over real code of its language without
// an error, reads every file it was handed, and matches at least one line of
// upstream code - so the family covers something outside its own sample.
//
// WHAT IT DOES NOT PROVE: that TAA's target patterns were found. These are the
// test fixtures of *upstream's* rules - small, sometimes synthetic, and written
// to exercise Semgrep Inc's rules rather than TAA's. A smoke pass here is not a
// benchmark, carries no non-inferiority claim, and must not be read as one.
// The per-language benchmark of §6 of the design spec is separate work.
//
// The corpora are on-disk research material and are not shipped with the
// repository, so this test skips unless TAA_UPSTREAM_FIXTURES names their root:
//
//	TAA_UPSTREAM_FIXTURES=../../models/audit/holdout-sources \
//	    go test ./internal/codeaudit/ -run TestRulePacksSmokeUpstreamFixtures -v -timeout 60m
//
// Measured cost is about 0.85 s per file (89 Go files: 76 s), which is why the
// deadline is raised below and why this cannot run unconditionally: the
// terraform subtree alone is 366 files.
const upstreamFixturesEnv = "TAA_UPSTREAM_FIXTURES"

// TestRulePacksSmokeUpstreamFixtures scans each language's fixture subtree.
//
// A directory is handed to the engine, which is the production shape: the
// engine walks it itself and passes semgrep an explicit file list with
// --no-git-ignore. That last flag is load-bearing here in a way it is not in
// production. These corpora ship their own .gitignore and .semgrepignore, and
// measured on 1.177.0 a directory handed to semgrep directly scans nothing:
// `results: 0, errors: []`, exit code 0 - a clean-looking report over an empty
// file set, which is exactly what a smoke test must not be able to call a pass.
// The assertions below are what make that impossible: a run that read no file,
// or read files and matched nothing, fails rather than passes quietly.
func TestRulePacksSmokeUpstreamFixtures(t *testing.T) {
	semgrepCLI(t)
	root := os.Getenv(upstreamFixturesEnv)
	if root == "" {
		t.Skipf("%s is unset; the corpora are on-disk research material and are not shipped."+
			"\nSet it to the directory holding semgrep-rules-develop/ and codeql/ to run this smoke,"+
			"\ne.g. %s=../../models/audit/holdout-sources go test ./internal/codeaudit/"+
			" -run TestRulePacksSmokeUpstreamFixtures -v -timeout 60m",
			upstreamFixturesEnv, upstreamFixturesEnv)
	}

	rulesDir, err := filepath.Abs(rulesRelativeDir)
	if err != nil {
		t.Fatalf("resolve rules dir: %v", err)
	}

	fixtures := []struct {
		language string
		subtree  string
		// suffix is the language part of the rule ids this subtree must produce.
		// Only this language's files are admitted under it, so a finding carrying
		// another language's suffix means the walk or the pack dispatch is wrong.
		suffix string
	}{
		// The reference pack: codeql's fixtures are the only Python corpus on disk,
		// and holding it to the same bar says whether a pack that has been in
		// production keeps matching real code.
		{"python", "codeql", "-python"},
		{"csharp", "semgrep-rules-develop/csharp", "-csharp"},
		{"go", "semgrep-rules-develop/go", "-go"},
		{"java", "semgrep-rules-develop/java", "-java"},
		// The javascript pack covers .js, .jsx, .mjs, .cjs, .ts and .tsx, which is
		// why the subtree holds both js and ts fixtures and why there is no
		// separate typescript entry.
		{"javascript", "semgrep-rules-develop/javascript", "-javascript"},
		{"php", "semgrep-rules-develop/php", "-php"},
		{"ruby", "semgrep-rules-develop/ruby", "-ruby"},
		{"scala", "semgrep-rules-develop/scala", "-scala"},
		{"terraform", "semgrep-rules-develop/terraform", "-terraform"},
	}

	// What a reader of this output should take away, stated in the output rather
	// than left to the section comment. Python is the one language with a
	// benchmark behind it - the PyPI holdout whose manifest lives beside the
	// corpora. The languages below it have embedded samples and their own
	// upstream fixtures, and nothing else: a green run here says the packs load,
	// run and match outside their own samples, which is a smoke result and not a
	// non-inferiority one. Reading it as verified is the misreading this line
	// exists to prevent.
	var smokeOnly []string
	for _, fx := range fixtures {
		if fx.language != "python" {
			smokeOnly = append(smokeOnly, fx.language)
		}
	}
	t.Logf("coverage status: python = benchmark-backed; %s = smoke-only, no holdout corpus yet",
		strings.Join(smokeOnly, ", "))

	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.language, func(t *testing.T) {
			dir := filepath.Join(root, fx.subtree)
			if _, err := os.Stat(dir); err != nil {
				t.Skipf("fixture subtree is not on disk: %v", err)
			}

			engine := NewSemgrepEngine(DefaultScanner(), rulesDir,
				SemgrepLimits{Timeout: 20 * time.Minute})

			start := time.Now()
			report, err := engine.ScanDirectory(dir)
			if err != nil {
				t.Fatalf("scan %s: %v", dir, err)
			}
			elapsed := time.Since(start)

			// The two ways this can pass without having done anything.
			if report.FilesCount == 0 {
				t.Fatalf("scanned 0 files under %s: the subtree holds admitted source, "+
					"so either the walk or the extension list is wrong", dir)
			}
			if len(report.Findings) == 0 {
				t.Fatalf("scanned %d file(s) under %s and matched nothing: the pack "+
					"covers no line of this language's upstream code", report.FilesCount, dir)
			}

			// Two kinds of finding arrive here and only one of them came from a
			// pack. The CPG pass synthesises cross-service findings, and those
			// carry no engine rule id because no rule produced them - a Python
			// subtree is the one that can produce them - so they are counted
			// separately rather than read as a rule from another language.
			families := make(map[string]int)
			synthesised := 0
			var foreign []string
			for _, f := range report.Findings {
				families[f.RuleID]++
				if f.EngineRuleID == "" {
					synthesised++
					continue
				}
				if !strings.HasSuffix(f.EngineRuleID, fx.suffix) {
					foreign = append(foreign, fmt.Sprintf("%s (%s) in %s",
						f.EngineRuleID, f.RuleID, filepath.Base(f.File)))
				}
			}
			if len(foreign) > 0 {
				t.Errorf("findings under %s carry another language's rule:\n  %s",
					dir, strings.Join(foreign, "\n  "))
			}
			if synthesised > 0 {
				t.Logf("%s: %d finding(s) synthesised by the CPG pass, which no pack produced",
					fx.language, synthesised)
			}

			// The family counts are a view of what the report kept, not of what
			// the packs found: past the scanner's MaxFindings the engine caps
			// after sorting, and a subtree of real code is well past it. The
			// truncated flag is logged beside them so a reader knows which of
			// the two they are looking at.
			t.Logf("%s: %d file(s) scanned, %d finding(s) across %d family(ies) in %s (truncated=%v)\n  %v",
				fx.language, report.FilesCount, len(report.Findings), len(families),
				elapsed.Round(time.Second), report.Truncated, families)
		})
	}
}
