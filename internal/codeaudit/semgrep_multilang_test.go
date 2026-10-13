package codeaudit

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
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
// the rest are what these tests pin down. JSON is deliberately absent from the
// extension list below - see ga11SourceExtensions.

// rulesRelativeDir is the rules tree relative to this package directory, which
// is the working directory a `go test` run uses.
const rulesRelativeDir = "../../models/audit/semgrep/rules"

// ga11SourceExtensions is the extension set the walk must admit for the GA-11
// languages to be scanned at all. It is spelled out rather than derived from
// semgrep's language registry because the registry is semgrep's and the walk is
// ours: the two are free to disagree, and this list is what decides.
//
// JSON (".json", ".ipynb") is deliberately not here yet. Admitting ".json"
// would put every data file of a model package into a semgrep pass - the
// audit-100 benchmark alone carries 920 of them, and a tokenizer.json is
// megabytes of vocabulary that no rule reads. Notebooks need cell extraction
// rather than a JSON parse, which is a separate piece of work; until then JSON
// coverage would be a pass over the wrong bytes at real cost.
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
func TestIsSourceFileRejectsNonSource(t *testing.T) {
	e := NewSemgrepEngine(NewScanner(nil, Config{Extensions: []string{".py"}}), "unused", SemgrepLimits{})
	for _, ext := range []string{".pt", ".bin", ".safetensors", ".onnx", ".pyc", ".so", ".png", ".gz"} {
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

// TestRulePacksAreWellFormed lints every rule pack for the three things that
// break a scan. It is a text lint rather than a parse because the engine never
// parses rules - it hands --config to the semgrep CLI - so the only Go-side
// authority on the rule table is the rule_family each rule names.
//
// The load-bearing check is the last one. semgrep_engine.go reads
// Extra.Metadata.RuleFamily and collects a rule carrying no family into
// `unmapped`, which fails the whole scan; a family the production table does
// not contain fails it a few lines later. Neither is visible until a scan runs,
// and by then the failure is one report with no verdict rather than a message
// naming the pack that caused it.
func TestRulePacksAreWellFormed(t *testing.T) {
	packs, err := filepath.Glob(filepath.Join(rulesRelativeDir, "*", "rules.yaml"))
	if err != nil {
		t.Fatalf("glob rule packs: %v", err)
	}
	if len(packs) == 0 {
		t.Fatalf("no rule packs under %s", rulesRelativeDir)
	}

	known := make(map[string]bool)
	for _, r := range DefaultRules() {
		known[r.ID] = true
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

		ids := ruleIDLine.FindAllStringSubmatch(text, -1)
		families := ruleFamilyLine.FindAllStringSubmatch(text, -1)
		if len(ids) == 0 {
			t.Errorf("%s: no rules", pack)
		}
		if len(ids) != len(families) {
			t.Errorf("%s: %d rule id(s) but %d rule_family entry(ies): every rule needs a family",
				pack, len(ids), len(families))
		}

		for _, m := range ids {
			id := m[1]
			if !strings.HasPrefix(id, "taa-") {
				t.Errorf("%s: rule id %q does not start with taa-", pack, id)
			}
			if prev, dup := seen[id]; dup {
				t.Errorf("%s: rule id %q already used in %s", pack, id, prev)
			}
			seen[id] = pack
		}
		for _, m := range families {
			if family := m[1]; !known[family] {
				t.Errorf("%s: rule_family %q is not in the production rule table", pack, family)
			}
		}
	}
}

// TestRulePacksValidateWithSemgrep runs the authoritative parser over all packs
// at once. This is the check the text lint above cannot make: semgrep is what
// actually reads these files, and one malformed pack makes the whole --config
// fail, which turns every audit into a report with no verdict.
func TestRulePacksValidateWithSemgrep(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep binary not installed on host, skipping CLI test")
	}
	rulesDir, err := filepath.Abs(rulesRelativeDir)
	if err != nil {
		t.Fatalf("resolve rules dir: %v", err)
	}
	out, err := exec.Command("semgrep", "--validate", "--config", rulesDir).CombinedOutput()
	if err != nil {
		t.Fatalf("semgrep --validate %s failed: %v\n%s", rulesDir, err, out)
	}
	if !strings.Contains(string(out), "0 configuration error") {
		t.Errorf("semgrep --validate did not report a clean configuration:\n%s", out)
	}
}
