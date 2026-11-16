package mock

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"

	"taa/internal/codeaudit"
)

// auditRuleSpec is one Tier 1 rule as the workbench shows and edits it.
//
// Patterns is the text the compiled matcher was built from rather than the
// matcher itself, so an edit starts from what is actually running. The order of
// the rule list is the engine's scan order and is load-bearing: the scanner
// reports the first rule a line matches, so a rule earlier in this list owns a
// line two rules could describe.
type auditRuleSpec struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"`
}

// auditBinaryRule is the read-only half of the rule list. The binary channel's
// families are declared beside the evidence readers rather than in the source
// rule table, and their patterns are claims about symbol tables, DT_NEEDED
// entries and pickle targets — not text a line of Python could match. They are
// listed here so the workbench shows the whole rule set, and they are not
// editable because changing one changes what a binary has to look like to be
// reported.
type auditBinaryRule struct {
	ID          string `json:"id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// auditEngineFacts describes the static engine's fixed configuration. Only the
// rules are editable; these come from codeaudit's defaults and are reported so
// a reader can tell what a rule is matched against.
type auditEngineFacts struct {
	Name           string   `json:"name"`
	Extensions     []string `json:"extensions"`
	MaxFindings    int      `json:"maxFindings"`
	SkipDirs       []string `json:"skipDirs"`
	SourceRules    int      `json:"sourceRules"`
	BinaryRules    int      `json:"binaryRules"`
	CommentSkipped bool     `json:"commentSkipped"`
}

type auditRulesResponse struct {
	Engine auditEngineFacts  `json:"engine"`
	Rules  []auditRuleSpec   `json:"rules"`
	Binary []auditBinaryRule `json:"binary"`
}

// auditRuleStore holds the rule set the next scan will use. It starts as the
// built-in table and is edited in place; nothing is persisted, for the same
// reason the prompt is not: the workbench is a comparison tool and an edit is
// usually weighed against a run made moments earlier.
type auditRuleStore struct {
	mu    sync.Mutex
	rules []auditRuleSpec
}

func newAuditRuleStore() *auditRuleStore {
	s := &auditRuleStore{}
	s.resetLocked()
	return s
}

func (s *auditRuleStore) resetLocked() {
	builtin := codeaudit.DefaultRules()
	rules := make([]auditRuleSpec, 0, len(builtin))
	for _, r := range builtin {
		patterns := make([]string, 0, len(r.Patterns))
		for _, p := range r.Patterns {
			patterns = append(patterns, p.String())
		}
		rules = append(rules, auditRuleSpec{
			ID:          r.ID,
			Category:    r.Category,
			Severity:    r.Severity,
			Description: r.Description,
			Patterns:    patterns,
		})
	}
	s.rules = rules
}

// reset restores the built-in table.
func (s *auditRuleStore) reset() {
	s.mu.Lock()
	s.resetLocked()
	s.mu.Unlock()
}

// specs returns a copy of the current rule list.
func (s *auditRuleStore) specs() []auditRuleSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]auditRuleSpec, len(s.rules))
	for i, r := range s.rules {
		patterns := make([]string, len(r.Patterns))
		copy(patterns, r.Patterns)
		r.Patterns = patterns
		out[i] = r
	}
	return out
}

// validateRule checks an edit before it is stored. Every rejection names the
// field, because the editor posts one rule at a time and a bare "invalid" would
// leave the operator looking at four inputs.
func validateRule(spec auditRuleSpec) (auditRuleSpec, error) {
	spec.ID = strings.TrimSpace(spec.ID)
	spec.Category = strings.TrimSpace(spec.Category)
	spec.Description = strings.TrimSpace(spec.Description)
	spec.Severity = strings.ToUpper(strings.TrimSpace(spec.Severity))

	switch spec.Severity {
	case codeaudit.SeverityHigh, codeaudit.SeverityMedium, codeaudit.SeverityLow:
	default:
		return spec, fmt.Errorf("级别必须是 HIGH、MEDIUM 或 LOW")
	}
	if spec.Category == "" {
		return spec, fmt.Errorf("类别不能为空")
	}
	if spec.Description == "" {
		return spec, fmt.Errorf("说明不能为空")
	}

	patterns := make([]string, 0, len(spec.Patterns))
	for _, p := range spec.Patterns {
		p = strings.TrimRight(p, "\r")
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return spec, fmt.Errorf("正则表达式无效：%s", err.Error())
		}
		patterns = append(patterns, p)
	}
	if len(patterns) == 0 {
		return spec, fmt.Errorf("至少需要一条匹配模式")
	}
	spec.Patterns = patterns
	return spec, nil
}

// update replaces one rule by id and returns the stored form.
func (s *auditRuleStore) update(spec auditRuleSpec) (auditRuleSpec, error) {
	spec, err := validateRule(spec)
	if err != nil {
		return auditRuleSpec{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.rules {
		if s.rules[i].ID != spec.ID {
			continue
		}
		s.rules[i] = spec
		return spec, nil
	}
	return auditRuleSpec{}, fmt.Errorf("规则 %s 不存在", spec.ID)
}

// compile renders the current table into the engine's rules. It cannot fail on
// saved state — update compiles every pattern before storing it — but it is
// still returned as an error so a scan reports a broken table rather than
// silently matching less than the operator configured.
func (s *auditRuleStore) compile() ([]codeaudit.Rule, error) {
	specs := s.specs()
	rules := make([]codeaudit.Rule, 0, len(specs))
	for _, spec := range specs {
		patterns := make([]*regexp.Regexp, 0, len(spec.Patterns))
		for _, p := range spec.Patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("规则 %s: %w", spec.ID, err)
			}
			patterns = append(patterns, re)
		}
		rules = append(rules, codeaudit.Rule{
			ID:          spec.ID,
			Category:    spec.Category,
			Severity:    spec.Severity,
			Description: spec.Description,
			Patterns:    patterns,
		})
	}
	return rules, nil
}

// engine builds a scanner over the current table so an edit takes effect on the
// next scan. The engine is construction-cheap: the patterns are compiled once
// here and the scan itself is an in-memory match.
func (s *auditRuleStore) engine() (codeaudit.StaticEngine, error) {
	rules, err := s.compile()
	if err != nil {
		return nil, err
	}
	return codeaudit.NewRegexEngine(rules, codeaudit.DefaultConfig()), nil
}

// binaryRules resolves the binary channel's families for display. The matcher
// is the same resolver the scanner uses, so the list cannot disagree with what
// a scan would apply.
func binaryRules() []auditBinaryRule {
	matcher, err := codeaudit.NewBinaryMatcher()
	if err != nil {
		return nil
	}
	resolved := matcher.Rules()
	out := make([]auditBinaryRule, 0, len(resolved))
	for _, r := range resolved {
		out = append(out, auditBinaryRule{
			ID:          r.ID,
			Category:    r.Category,
			Severity:    r.Severity,
			Description: r.Description,
		})
	}
	// Sorted by id for display. The matcher's own order is scan precedence, which
	// only matters to which family names an ambiguous line; a reading list is
	// easier to search when it is alphabetical.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func auditEngineFactsNow(store *auditRuleStore) auditEngineFacts {
	cfg := codeaudit.DefaultConfig()
	skipDirs := make([]string, 0, len(cfg.SkipDirs))
	for name, skip := range cfg.SkipDirs {
		if skip {
			skipDirs = append(skipDirs, name)
		}
	}
	sort.Strings(skipDirs)
	return auditEngineFacts{
		Name:           codeaudit.EngineNameRegex,
		Extensions:     cfg.Extensions,
		MaxFindings:    cfg.MaxFindings,
		SkipDirs:       skipDirs,
		SourceRules:    len(store.specs()),
		BinaryRules:    len(binaryRules()),
		CommentSkipped: true,
	}
}

// auditRulesHandler serves the engine's rule set: read it, edit one source
// rule, or restore the built-in table.
//
//	GET  /api/audit/console/rules          → the whole set plus engine facts
//	PUT  /api/audit/console/rules/{id}     → replace one source rule
//	POST /api/audit/console/rules/reset    → restore the built-in table
func auditRulesHandler(store *auditRuleStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/audit/console/rules")
		path = strings.TrimPrefix(path, "/")

		switch {
		case path == "" && r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, auditRulesResponse{
				Engine: auditEngineFactsNow(store),
				Rules:  store.specs(),
				Binary: binaryRules(),
			})

		case path == "reset" && (r.Method == http.MethodPost || r.Method == http.MethodPut):
			store.reset()
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":    true,
				"rules": store.specs(),
			})

		case path != "" && (r.Method == http.MethodPut || r.Method == http.MethodPost):
			var body auditRuleSpec
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求体不是合法 JSON: " + err.Error()})
				return
			}
			body.ID = path
			updated, err := store.update(body)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "rule": updated})

		case path == "":
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "仅支持 GET 方法"})

		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "接口不存在"})
		}
	}
}
