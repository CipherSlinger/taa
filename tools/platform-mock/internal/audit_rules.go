package mock

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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
//
// Name is the engine the next scan will actually run, which is not always the
// one that was configured: semgrep needs both its CLI and its rules on the
// host, and a missing one falls back to regex. RequestedName and
// FallbackReason keep that decision visible instead of leaving the reader to
// wonder why the card says regex.
type auditEngineFacts struct {
	Name           string   `json:"name"`
	RequestedName  string   `json:"requestedName,omitempty"`
	FallbackReason string   `json:"fallbackReason,omitempty"`
	RulesPath      string   `json:"rulesPath,omitempty"`
	SemgrepBin     string   `json:"semgrepBin,omitempty"`
	RuleFiles      int      `json:"ruleFiles,omitempty"`
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
//
// It also carries the operator's engine selection. The regex table only feeds
// the regex engine; when semgrep is selected the table stays editable but does
// not take part in the scan.
type auditRuleStore struct {
	mu    sync.Mutex
	rules []auditRuleSpec
	// engineName is the configured engine: codeaudit.EngineNameRegex or
	// codeaudit.EngineNameSemgrep. resolveEngine decides whether semgrep can
	// actually run here.
	engineName string
	// rulesPath is semgrep's --config target. Ignored by the regex engine.
	rulesPath string
}

// newAuditRuleStore builds a store on the regex baseline. Tests and any caller
// that does not select an engine get the built-in table; the workbench's
// production constructor calls useEngine with the configured choice.
func newAuditRuleStore() *auditRuleStore {
	s := &auditRuleStore{engineName: codeaudit.EngineNameRegex}
	s.resetLocked()
	return s
}

// useEngine records the operator's engine selection. It is not validated here:
// resolveEngine reports an unusable selection at the next scan, and the engine
// card shows the same answer, so a broken flag has one place to look.
func (s *auditRuleStore) useEngine(name, rulesPath string) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		// An unset selection means the baseline, which keeps a hand-built
		// Config{} (tests, embedded use) on the regex engine instead of failing
		// every scan.
		name = codeaudit.EngineNameRegex
	}
	s.mu.Lock()
	s.engineName = name
	s.rulesPath = strings.TrimSpace(rulesPath)
	s.mu.Unlock()
}

// requestedEngineName reports the selection as configured.
func (s *auditRuleStore) requestedEngineName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.engineName
}

// resolveEngine turns the selection into the engine configuration the next
// scan will use. A semgrep selection that cannot run here resolves to the regex
// baseline and returns the reason; an unknown name resolves to an error, which
// matches codeaudit.NewEngine refusing a name rather than silently scanning
// with something else.
func (s *auditRuleStore) resolveEngine() (codeaudit.EngineConfig, string, error) {
	s.mu.Lock()
	name, rulesPath := s.engineName, s.rulesPath
	s.mu.Unlock()

	switch name {
	case codeaudit.EngineNameRegex:
		return codeaudit.EngineConfig{Name: codeaudit.EngineNameRegex}, "", nil

	case codeaudit.EngineNameSemgrep:
		// The CLI is resolved through PATH, the same way the adapter finds it
		// when it runs, so this check answers exactly what a scan would hit.
		reason := ""
		switch {
		case rulesPath == "":
			reason = "未配置 Semgrep 规则目录"
		default:
			if _, err := os.Stat(rulesPath); err != nil {
				reason = "Semgrep 规则路径不可用：" + err.Error()
			} else if _, err := exec.LookPath("semgrep"); err != nil {
				reason = "PATH 中找不到 semgrep 可执行文件"
			}
		}
		if reason != "" {
			return codeaudit.EngineConfig{Name: codeaudit.EngineNameRegex}, reason, nil
		}
		return codeaudit.EngineConfig{
			Name:             codeaudit.EngineNameSemgrep,
			SemgrepRulesPath: rulesPath,
		}, "", nil

	default:
		return codeaudit.EngineConfig{}, "", fmt.Errorf(
			"不支持的静态引擎 %q：只能是 semgrep 或 regex", name)
	}
}

// countRuleFiles counts the YAML rule files semgrep will load. A single file
// counts as one; a directory is walked for .yml/.yaml. Errors and odd paths
// report zero rather than failing the card: the count is orientation, not a
// decision.
func countRuleFiles(path string) int {
	if path == "" {
		return 0
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if !info.IsDir() {
		return 1
	}
	count := 0
	_ = filepath.WalkDir(path, func(_ string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(entry.Name())) {
		case ".yml", ".yaml":
			count++
		}
		return nil
	})
	return count
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

// engine builds the scanner the next scan will run. The regex arm is built
// over the current editable table, so an edit takes effect on the next scan;
// the semgrep arm is built by codeaudit's selection point from the configured
// rules path, and only after resolveEngine has confirmed it can run here.
func (s *auditRuleStore) engine() (codeaudit.StaticEngine, error) {
	selection, _, err := s.resolveEngine()
	if err != nil {
		return nil, err
	}
	if selection.Name == codeaudit.EngineNameSemgrep {
		return codeaudit.NewEngine(selection)
	}
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

	selection, fallback, err := store.resolveEngine()
	facts := auditEngineFacts{
		Name:           selection.Name,
		RequestedName:  store.requestedEngineName(),
		FallbackReason: fallback,
		Extensions:     cfg.Extensions,
		MaxFindings:    cfg.MaxFindings,
		SkipDirs:       skipDirs,
		SourceRules:    len(store.specs()),
		BinaryRules:    len(binaryRules()),
		CommentSkipped: true,
	}
	if err != nil {
		// The scan will fail at the static step; the card says why instead of
		// presenting the requested name as if it were running.
		facts.Name = ""
		facts.FallbackReason = err.Error()
		return facts
	}
	if selection.Name == codeaudit.EngineNameSemgrep {
		facts.RulesPath = selection.SemgrepRulesPath
		if bin, err := exec.LookPath("semgrep"); err == nil {
			facts.SemgrepBin = bin
		}
		facts.RuleFiles = countRuleFiles(selection.SemgrepRulesPath)
		// Semgrep decides which lines its rules claim; the regex engine's
		// first-match-wins ordering and its comment skipping do not apply.
		facts.CommentSkipped = false
	}
	return facts
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
