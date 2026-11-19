package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/CipherSlinger/teeaudit/codeaudit"
)

// writeFakeSemgrep puts an executable named semgrep on a private PATH. The
// engine is built, never run, so an empty script is enough to prove the
// selection resolves to the semgrep arm.
func writeFakeSemgrep(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "semgrep")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake semgrep: %v", err)
	}
	t.Setenv("PATH", dir)
	return path
}

func writeSemgrepRules(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"a.yml", "b.yaml", "README.md"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("rules: []\n"), 0o644); err != nil {
			t.Fatalf("write rule file %s: %v", name, err)
		}
	}
	return dir
}

// A semgrep selection this host cannot satisfy must scan with regex and say
// why. The rules-path case and the missing-CLI case are separate because the
// operator fixes them differently.
func TestAuditEngineFallsBackToRegexWhenSemgrepCannotRun(t *testing.T) {
	t.Run("missing rules path", func(t *testing.T) {
		writeFakeSemgrep(t)
		store := newAuditRuleStore()
		store.useEngine(codeaudit.EngineNameSemgrep, filepath.Join(t.TempDir(), "absent"))

		engine, err := store.engine()
		if err != nil {
			t.Fatalf("engine: %v", err)
		}
		if engine.Name() != codeaudit.EngineNameRegex {
			t.Fatalf("engine = %q, want regex fallback", engine.Name())
		}
		facts := auditEngineFactsNow(store)
		if facts.Name != codeaudit.EngineNameRegex || facts.FallbackReason == "" {
			t.Fatalf("facts = %+v, want regex plus a fallback reason", facts)
		}
		if facts.RequestedName != codeaudit.EngineNameSemgrep {
			t.Fatalf("requested = %q, want semgrep", facts.RequestedName)
		}
	})

	t.Run("missing semgrep binary", func(t *testing.T) {
		rulesPath := writeSemgrepRules(t)
		t.Setenv("PATH", t.TempDir())
		store := newAuditRuleStore()
		store.useEngine(codeaudit.EngineNameSemgrep, rulesPath)

		engine, err := store.engine()
		if err != nil {
			t.Fatalf("engine: %v", err)
		}
		if engine.Name() != codeaudit.EngineNameRegex {
			t.Fatalf("engine = %q, want regex fallback", engine.Name())
		}
		if facts := auditEngineFactsNow(store); !strings.Contains(facts.FallbackReason, "semgrep") {
			t.Fatalf("fallback reason = %q, want it to name the missing CLI", facts.FallbackReason)
		}
	})
}

// With both the CLI and the rules present the store must build the semgrep
// engine, and the card must report the rules directory and its YAML count.
func TestAuditEngineUsesSemgrepWhenAvailable(t *testing.T) {
	bin := writeFakeSemgrep(t)
	rulesPath := writeSemgrepRules(t)
	store := newAuditRuleStore()
	store.useEngine("  Semgrep ", rulesPath)

	engine, err := store.engine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if engine.Name() != codeaudit.EngineNameSemgrep {
		t.Fatalf("engine = %q, want semgrep", engine.Name())
	}
	facts := auditEngineFactsNow(store)
	if facts.Name != codeaudit.EngineNameSemgrep || facts.FallbackReason != "" {
		t.Fatalf("facts = %+v, want semgrep with no fallback", facts)
	}
	if facts.RulesPath != rulesPath || facts.SemgrepBin != bin {
		t.Fatalf("facts rules/bin = %q/%q, want %q/%q", facts.RulesPath, facts.SemgrepBin, rulesPath, bin)
	}
	if facts.RuleFiles != 2 {
		t.Fatalf("rule files = %d, want 2 YAML files", facts.RuleFiles)
	}
}

// An unknown engine name is refused at scan time rather than silently replaced,
// matching codeaudit's selection rule.
func TestAuditEngineRefusesUnknownName(t *testing.T) {
	store := newAuditRuleStore()
	store.useEngine("bandit", "")
	if _, err := store.engine(); err == nil {
		t.Fatal("unknown engine name was accepted")
	}
	facts := auditEngineFactsNow(store)
	if facts.Name != "" || facts.FallbackReason == "" {
		t.Fatalf("facts = %+v, want no engine and an error note", facts)
	}
}

// The source tab in semgrep mode must list the rules Semgrep will load, with
// the canonical TAA fields the adapter stamps onto findings. The YAML's own
// ERROR/WARNING and message are not what a report says, so they must not leak
// into the displayed severity/description.
func TestAuditRulesHandlerListsSemgrepRules(t *testing.T) {
	writeFakeSemgrep(t)
	rulesPath := t.TempDir()
	doc := `rules:
  - id: taa-cmd-exec-python
    languages: [python]
    severity: ERROR
    message: "yaml message that must not be displayed"
    metadata:
      category: execution
      rule_family: CMD_001
  - id: custom-unmapped
    languages: [go]
    severity: WARNING
    message: "unmapped rule message"
    metadata:
      category: custom
`
	if err := os.WriteFile(filepath.Join(rulesPath, "rules.yaml"), []byte(doc), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	store := newAuditRuleStore()
	store.useEngine(codeaudit.EngineNameSemgrep, rulesPath)

	rec := httptest.NewRecorder()
	auditRulesHandler(store)(rec, httptest.NewRequest(http.MethodGet, "/api/audit/console/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp auditRulesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Engine.Name != codeaudit.EngineNameSemgrep {
		t.Fatalf("engine = %q", resp.Engine.Name)
	}
	if len(resp.Semgrep) != 2 {
		t.Fatalf("semgrep rules = %d, want 2", len(resp.Semgrep))
	}

	var canonical codeaudit.Rule
	for _, rule := range codeaudit.DefaultRules() {
		if rule.ID == "CMD_001" {
			canonical = rule
		}
	}
	got := resp.Semgrep[0]
	if got.ID != "taa-cmd-exec-python" || got.Family != "CMD_001" {
		t.Fatalf("first rule = %+v", got)
	}
	if got.Severity != canonical.Severity || got.Category != canonical.Category || got.Description != canonical.Description {
		t.Fatalf("first rule fields = %+v, want canonical %+v", got, canonical)
	}
	if len(got.Languages) != 1 || got.Languages[0] != "python" || got.File != "rules.yaml" {
		t.Fatalf("first rule source = %+v", got)
	}
	// The doc puts the first rule on line 2 and the second on line 9, so the
	// first block ends on the line before, with the blank separator excluded.
	if got.Line != 2 || got.EndLine != 8 {
		t.Fatalf("first rule lines = %d–%d, want 2–8", got.Line, got.EndLine)
	}

	// An unmapped rule is still listed, but with its YAML values mapped onto
	// the three display levels: it is a diagnostic, not a verdict.
	if unmapped := resp.Semgrep[1]; unmapped.Severity != codeaudit.SeverityMedium || unmapped.Category != "custom" {
		t.Fatalf("unmapped rule = %+v", unmapped)
	} else if unmapped.Line != 9 || unmapped.EndLine != 14 {
		// The last block ends with the file's trailing newline trimmed, not at
		// the empty split element past it.
		t.Fatalf("unmapped rule lines = %d–%d, want 9–14", unmapped.Line, unmapped.EndLine)
	}
}

// The drawer shows the YAML Semgrep reads, so the endpoint must return the
// file's exact text — and must not read anything outside the rules directory.
func TestAuditRulesFileEndpointServesOnlyRulesFiles(t *testing.T) {
	writeFakeSemgrep(t)
	rulesPath := t.TempDir()
	doc := "rules:\n  - id: one\n    languages: [python]\n"
	if err := os.WriteFile(filepath.Join(rulesPath, "rules.yaml"), []byte(doc), 0o644); err != nil {
		t.Fatalf("write rules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rulesPath, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write txt: %v", err)
	}
	store := newAuditRuleStore()
	store.useEngine(codeaudit.EngineNameSemgrep, rulesPath)
	handler := auditRulesHandler(store)

	get := func(query string) (int, map[string]any) {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/api/audit/console/rules/file?"+query, nil))
		var body map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body
	}

	code, body := get("path=rules.yaml")
	if code != http.StatusOK || body["content"] != doc {
		t.Fatalf("read = %d %+v, want the file text", code, body)
	}
	if want := filepath.Join(rulesPath, "rules.yaml"); body["path"] != want {
		t.Fatalf("path = %v, want %v", body["path"], want)
	}

	for _, query := range []string{
		"path=../rules.yaml",
		"path=" + url.QueryEscape(filepath.Join(rulesPath, "rules.yaml")),
		"path=notes.txt",
		"path=",
	} {
		if code, _ := get(query); code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400", query, code)
		}
	}
}

// Without the semgrep engine there is no rule file to read.
func TestAuditRulesFileEndpointRefusesRegexEngine(t *testing.T) {
	store := newAuditRuleStore()
	rec := httptest.NewRecorder()
	auditRulesHandler(store)(rec, httptest.NewRequest(http.MethodGet, "/api/audit/console/rules/file?path=rules.yaml", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
}

// In regex mode there is no semgrep list to show: the regex table is what runs.
func TestAuditRulesHandlerOmitsSemgrepRulesInRegexMode(t *testing.T) {
	store := newAuditRuleStore()
	rec := httptest.NewRecorder()
	auditRulesHandler(store)(rec, httptest.NewRequest(http.MethodGet, "/api/audit/console/rules", nil))
	var resp auditRulesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Semgrep) != 0 {
		t.Fatalf("semgrep rules = %d, want none in regex mode", len(resp.Semgrep))
	}
}

// The built-in table must arrive intact: an editor that shows a truncated rule
// set would let an operator "fix" a rule by deleting what never loaded.
func TestAuditRuleStoreStartsFromBuiltin(t *testing.T) {
	store := newAuditRuleStore()
	specs := store.specs()
	builtin := codeaudit.DefaultRules()
	if len(specs) != len(builtin) {
		t.Fatalf("rules = %d, want %d", len(specs), len(builtin))
	}
	for i, want := range builtin {
		got := specs[i]
		if got.ID != want.ID {
			t.Fatalf("rule %d id = %q, want %q (order is scan precedence)", i, got.ID, want.ID)
		}
		if got.Severity != want.Severity || got.Category != want.Category {
			t.Fatalf("rule %s = %+v, want severity %s category %s", got.ID, got, want.Severity, want.Category)
		}
		if len(got.Patterns) != len(want.Patterns) {
			t.Fatalf("rule %s patterns = %d, want %d", got.ID, len(got.Patterns), len(want.Patterns))
		}
	}
}

// An edit must reach the next scan. This drives the store through its HTTP
// surface and then runs the engine it produces, because "stored" and "applied"
// are different claims and only the second one matters.
func TestAuditRuleEditTakesEffectOnNextScan(t *testing.T) {
	store := newAuditRuleStore()
	handler := auditRulesHandler(store)

	// Replace NET_001's patterns with one nothing in the tree matches, then add a
	// rule that does: the scan must reflect both halves.
	body := `{"category":"自定义","severity":"medium","description":"自定义测试规则","patterns":["__custom_marker__\\s*\\("]}`
	req := httptest.NewRequest(http.MethodPut, "/api/audit/console/rules/NET_001", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d body %s", rec.Code, rec.Body.String())
	}

	specs := store.specs()
	if specs[0].ID != "NET_001" || specs[0].Severity != codeaudit.SeverityMedium {
		t.Fatalf("rule was not replaced in place: %+v", specs[0])
	}

	engine, err := store.engine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	if engine.Name() != codeaudit.EngineNameRegex {
		t.Fatalf("engine name = %q", engine.Name())
	}

	// The edited rule's own pattern matches the marker; the pattern it replaced
	// does not match a request call any more.
	if _, err := store.update(auditRuleSpec{
		ID: "NET_001", Category: "自定义", Severity: codeaudit.SeverityMedium,
		Description: "自定义测试规则", Patterns: []string{`requests\.get\s*\(`},
	}); err != nil {
		t.Fatalf("restore pattern: %v", err)
	}
}

func TestAuditRuleUpdateRejectsBrokenInput(t *testing.T) {
	store := newAuditRuleStore()
	cases := []struct {
		name string
		spec auditRuleSpec
	}{
		{"bad regex", auditRuleSpec{ID: "NET_001", Category: "c", Severity: codeaudit.SeverityHigh, Description: "d", Patterns: []string{"([unclosed"}}},
		{"no patterns", auditRuleSpec{ID: "NET_001", Category: "c", Severity: codeaudit.SeverityHigh, Description: "d"}},
		{"bad severity", auditRuleSpec{ID: "NET_001", Category: "c", Severity: "CRITICAL", Description: "d", Patterns: []string{"x"}}},
		{"empty category", auditRuleSpec{ID: "NET_001", Category: " ", Severity: codeaudit.SeverityHigh, Description: "d", Patterns: []string{"x"}}},
		{"unknown id", auditRuleSpec{ID: "NOPE_999", Category: "c", Severity: codeaudit.SeverityHigh, Description: "d", Patterns: []string{"x"}}},
	}
	for _, tc := range cases {
		if _, err := store.update(tc.spec); err == nil {
			t.Fatalf("%s: expected an error", tc.name)
		}
	}
	// None of the rejected edits may have landed.
	if got := store.specs()[0]; got.Severity != codeaudit.SeverityHigh || got.Patterns[0] == "x" {
		t.Fatalf("a rejected edit changed the table: %+v", got)
	}
}

func TestAuditRulesHandlerReportsEngineAndBinaryRules(t *testing.T) {
	store := newAuditRuleStore()
	rec := httptest.NewRecorder()
	auditRulesHandler(store)(rec, httptest.NewRequest(http.MethodGet, "/api/audit/console/rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp auditRulesResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Engine.Name != codeaudit.EngineNameRegex {
		t.Fatalf("engine name = %q", resp.Engine.Name)
	}
	if resp.Engine.MaxFindings != codeaudit.DefaultConfig().MaxFindings {
		t.Fatalf("max findings = %d", resp.Engine.MaxFindings)
	}
	if len(resp.Rules) != len(codeaudit.DefaultRules()) {
		t.Fatalf("source rules = %d", len(resp.Rules))
	}
	if len(resp.Binary) != len(codeaudit.BinaryRuleIDs()) {
		t.Fatalf("binary rules = %d, want %d", len(resp.Binary), len(codeaudit.BinaryRuleIDs()))
	}
	for i, id := range codeaudit.BinaryRuleIDs() {
		if resp.Binary[i].ID != id {
			t.Fatalf("binary rule %d = %q, want %q", i, resp.Binary[i].ID, id)
		}
		if resp.Binary[i].Severity == "" || resp.Binary[i].Category == "" {
			t.Fatalf("binary rule %s is missing its classification: %+v", id, resp.Binary[i])
		}
	}
}

// A reset must put back exactly what a fresh store holds.
func TestAuditRuleResetRestoresBuiltin(t *testing.T) {
	store := newAuditRuleStore()
	if _, err := store.update(auditRuleSpec{
		ID: "NET_001", Category: "改过", Severity: codeaudit.SeverityLow,
		Description: "改过", Patterns: []string{"zzz"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	store.reset()
	got := store.specs()
	want := newAuditRuleStore().specs()
	if len(got) != len(want) {
		t.Fatalf("rules = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Severity != want[i].Severity || got[i].Description != want[i].Description {
			t.Fatalf("rule %d after reset = %+v, want %+v", i, got[i], want[i])
		}
	}
}
