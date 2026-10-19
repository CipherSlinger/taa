package mock

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"taa/pkg/logger"
)

// taaLogLevelCase is one log line handed to the browser-side level detector.
type taaLogLevelCase struct {
	Name string `json:"name"`
	Line string `json:"line"`
	Want string `json:"want"`
}

// logLevelResult is the detector's verdict for one case, as reported by node:
// the level detectLogLevel returns, and the level the rendered row advertises
// through its data-level attribute, which is what the filter buttons read.
type logLevelResult struct {
	Name     string `json:"name"`
	Got      string `json:"got"`
	Rendered string `json:"rendered"`
}

// TestTaaLogLevelClassification drives the production static/js/logs.js level
// detector under node against lines produced by the daemon's own formatter.
//
// The console has no structured level to read: /v1/taa/taaLog carries only
// seq+message, and the level lives inside the text as the "[LEVEL]" token of
// Entry.FormatMessage. So the detector must parse that token; text scanning is
// only a fallback for lines that carry no token. The audit-start line contains
// "failClosed=true" and the export line contains "warnings=", so keyword
// scanning alone reports both as ERROR/WARN while the daemon logged them INFO.
//
// The test runs the real file rather than a Go reimplementation, so it keeps
// failing until the detector actually reads the prefix, whatever shape the
// implementation takes.
func TestTaaLogLevelClassification(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH; skipping browser-side log level test")
	}

	cases := []taaLogLevelCase{
		{
			// Regression: "failClosed=true" contains "FAIL".
			Name: "audit start with failClosed enabled",
			Line: logger.Entry{
				Level:     logger.LevelInfo,
				Component: "audit",
				Message: "开始模型代码审计: engine=semgrep, dir=/root/taa/models, " +
					"llmEnabled=true, failClosed=true",
			}.FormatMessage(),
			Want: "INFO",
		},
		{
			// Same trap, the other branch of the flag.
			Name: "audit start with failClosed disabled",
			Line: logger.Entry{
				Level:     logger.LevelInfo,
				Component: "audit",
				Message: "开始模型代码审计: engine=semgrep, dir=/root/taa/models, " +
					"llmEnabled=false, failClosed=false",
			}.FormatMessage(),
			Want: "INFO",
		},
		{
			Name: "audit completed",
			Line: logger.Entry{
				Level:     logger.LevelInfo,
				Component: "audit",
				Message:   "审计完成: passed=true, riskLevel=LOW, totalFindings=5",
			}.FormatMessage(),
			Want: "INFO",
		},
		{
			Name: "audit blocked with the LLM unavailable",
			Line: logger.Entry{
				Level:     logger.LevelError,
				Component: "audit",
				Message:   "LLM 服务不可用，按 fail-closed 策略上报失败: endpoint=https://llm:6002",
			}.FormatMessage(),
			Want: "ERROR",
		},
		{
			// Regression: "warnings=" contains "WARN".
			Name: "export result check passed with warnings",
			Line: logger.Entry{
				Level:     logger.LevelInfo,
				Component: "export",
				Message:   "结果安全检查通过 (warnings=3)",
			}.FormatMessage(),
			Want: "INFO",
		},
		{
			Name: "import warning",
			Line: logger.Entry{
				Level:     logger.LevelWarn,
				Component: "import",
				Message:   "模型压缩包缺少 checksum，回退扫描模型目录",
			}.FormatMessage(),
			Want: "WARN",
		},
		{
			Name: "debug entry keeps its own level",
			Line: logger.Entry{
				Level:     logger.LevelDebug,
				Component: "state",
				Message:   "训练控制状态转储",
			}.FormatMessage(),
			Want: "DEBUG",
		},
		{
			// Fallback: a keyword-bearing line that carries no prefix at all.
			Name: "prefixless line mentioning ERROR",
			Line: "训练进程输出: ERROR out of memory",
			Want: "ERROR",
		},
		{
			Name: "prefixless line mentioning WARN",
			Line: "训练进程输出: WARN dataloader worker slow",
			Want: "WARN",
		},
		{
			Name: "prefixless plain line",
			Line: "训练进程输出: step 100 loss=0.5",
			Want: "INFO",
		},
		{
			// Boundary: a leading timestamp without a level token must not be
			// mistaken for the daemon's prefix.
			Name: "timestamp without a level token",
			Line: "[2026-10-09 02:56:20] raw output without a level token",
			Want: "INFO",
		},
	}

	results := runLogLevelDetector(t, nodePath, cases)

	for i, res := range results {
		want := cases[i]
		if res.Name != want.Name {
			t.Fatalf("result %d name = %q, want %q (harness order changed)", i, res.Name, want.Name)
		}
		if res.Got != want.Want {
			t.Errorf("detectLogLevel(%s) = %s, want %s\n  line: %s", want.Name, res.Got, want.Want, want.Line)
		}
		if res.Rendered != want.Want {
			t.Errorf("rendered row for %s advertises level %s, want %s\n  line: %s", want.Name, res.Rendered, want.Want, want.Line)
		}
	}
}

// TestTaaLogLevelDetectorKeepsFallback pins that the keyword scan still runs for
// lines the daemon did not format, so the prefix parser cannot silently swallow
// input it does not understand.
func TestTaaLogLevelDetectorKeepsFallback(t *testing.T) {
	nodePath, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not found in PATH; skipping browser-side log level test")
	}

	cases := []taaLogLevelCase{
		{Name: "unknown text", Line: "something failed to start", Want: "ERROR"},
		{Name: "panic text", Line: "PANIC: runtime error", Want: "ERROR"},
		{Name: "fatal text", Line: "FATAL: cannot continue", Want: "ERROR"},
	}

	for _, res := range runLogLevelDetector(t, nodePath, cases) {
		for _, want := range cases {
			if res.Name != want.Name {
				continue
			}
			if res.Got != want.Want {
				t.Errorf("detectLogLevel(%s) = %s, want %s", want.Name, res.Got, want.Want)
			}
			if res.Rendered != want.Want {
				t.Errorf("rendered row for %s advertises level %s, want %s", want.Name, res.Rendered, want.Want)
			}
		}
	}
}

// runLogLevelDetector loads the production logs.js (plus drawer.js, which
// supplies the escapeHtml it renders with) in node behind minimal DOM stubs, and
// classifies every case line with the file's own detectLogLevel and
// renderTaaLogEntry.
func runLogLevelDetector(t *testing.T, nodePath string, cases []taaLogLevelCase) []logLevelResult {
	t.Helper()

	payload, err := json.Marshal(cases)
	if err != nil {
		t.Fatalf("marshal cases: %v", err)
	}

	jsSource, err := staticFS.ReadFile("static/js/logs.js")
	if err != nil {
		t.Fatalf("read static/js/logs.js: %v", err)
	}
	escapeSource, err := staticFS.ReadFile("static/js/drawer.js")
	if err != nil {
		t.Fatalf("read static/js/drawer.js: %v", err)
	}

	// The stubs cover everything these files touch at load time; the DOM-facing
	// functions under test are never invoked, so they stay inert.
	harness := fmt.Sprintf(`// Generated by logs_level_test.go: run the production detector in node.
globalThis.window = globalThis;
globalThis.document = {
  addEventListener() {},
  querySelectorAll() { return []; },
  getElementById() { return null; },
};
globalThis.fetch = () => Promise.reject(new Error('network disabled in test'));

%s

%s

const CASES = %s;
const renderedLevel = (line) => {
  const html = renderTaaLogEntry({ seq: 1, message: line });
  const m = /data-level="([^"]*)"/.exec(html);
  return m ? m[1] : '';
};
process.stdout.write(JSON.stringify(
  CASES.map(c => ({ name: c.name, got: detectLogLevel(c.line), rendered: renderedLevel(c.line) })),
));
`, escapeSource, jsSource, payload)

	harnessPath := filepath.Join(t.TempDir(), "logs_level_harness.js")
	if err := os.WriteFile(harnessPath, []byte(harness), 0o600); err != nil {
		t.Fatalf("write node harness: %v", err)
	}

	out, err := exec.Command(nodePath, harnessPath).CombinedOutput()
	if err != nil {
		t.Fatalf("node harness failed: %v\noutput: %s", err, out)
	}

	var results []logLevelResult
	if err := json.Unmarshal(out, &results); err != nil {
		t.Fatalf("decode harness output %q: %v", out, err)
	}
	if len(results) != len(cases) {
		t.Fatalf("harness classified %d lines, want %d", len(results), len(cases))
	}
	return results
}
