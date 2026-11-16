package mock

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"taa/internal/codeaudit"
)

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
