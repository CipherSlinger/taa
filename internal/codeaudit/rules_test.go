package codeaudit

import "testing"

// scanSnippet writes content to a temporary .py file and returns the raw
// findings for it, without the aggregation exemptions (test-file, EMB_003)
// that ClassifyFindingRisk applies later.
func scanSnippet(t *testing.T, content string) []Finding {
	t.Helper()
	dir := t.TempDir()
	path := writeTestFile(t, dir, "snippet.py", content)
	findings, err := NewDefaultScanner().ScanFile(path)
	if err != nil {
		t.Fatalf("scan snippet: %v", err)
	}
	return findings
}

func hasRule(findings []Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

// TestEnv001DetectsUppercaseSecretNames pins ENV_001 against the corpus's
// secret-theft family, which reads variables named in upper case.
//
// The rule's alternation lists lower-case words (secret, token, api_key,
// password, ...) and the patterns are compiled without (?i), so an upper-case
// name matches nothing: os.getenv("AWS_SECRET_ACCESS_KEY") produced no finding
// at all. That is not a missed nicety — the M3 family of the audit corpus is
// defined by exactly this read, and the production engine found zero findings
// on four of its samples.
//
// The Python scanner the comparison evidence was gathered with
// (models/examples/code_security_analyzer.py) compiles these same patterns with
// (?i), and tests/test_code_security_analyzer_v2.py:81 asserts both AWS_SECRET
// and API_KEY match. These cases mirror that test so the two rule tables cannot
// drift again unnoticed.
func TestEnv001DetectsUppercaseSecretNames(t *testing.T) {
	cases := []struct {
		name    string
		snippet string
		want    bool
	}{
		// Upper-case names: the case the Go table was missing.
		{"os.getenv upper case", `key = os.getenv("AWS_SECRET_ACCESS_KEY", "")`, true},
		{"os.environ.get upper case", `secret = os.environ.get('AWS_SECRET')`, true},
		{"os.environ subscript upper case", `api_key = os.environ['API_KEY']`, true},
		{"mixed case", `return os.environ.get("Session_Token", "")`, true},
		// The benign sibling sample in the corpus, which the Python arm flags
		// and the Go arm did not.
		{"B3-04 session timeout", `return os.environ.get("SESSION_TIMEOUT", "3600")`, true},
		// Lower-case names already worked; they must keep working.
		{"lower case token", `token = os.environ.get("api_key")`, true},

		// The other direction: (?i) must not turn this into "any environment
		// access". That is a different, deliberately broader rule, and widening
		// ENV_001 to it here would silently change what the engine reports.
		{"plain PATH", `p = os.environ.get("PATH", "")`, false},
		{"plain HOME subscript", `h = os.environ["HOME"]`, false},
		{"non-secret name", `d = os.environ.get("DATA_DIR", "/tmp")`, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasRule(scanSnippet(t, tc.snippet), "ENV_001")
			if got != tc.want {
				if tc.want {
					t.Errorf("ENV_001 did not fire on %q; the rule misses this read", tc.snippet)
				} else {
					t.Errorf("ENV_001 fired on %q; the rule now matches every environment access", tc.snippet)
				}
			}
		})
	}
}
