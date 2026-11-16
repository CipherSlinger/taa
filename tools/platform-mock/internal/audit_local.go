package mock

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CipherSlinger/teetls"

	"taa/internal/codeaudit"
	"taa/internal/resource"
)

// localAuditInstanceKey is the job-store bucket every workbench audit is
// written to. The workbench does not talk to a TAA instance, so the fixed key
// keeps it usable with nothing registered. Real reportAudit callbacks keep
// writing their own dockerId buckets and never appear here.
const localAuditInstanceKey = "local"

// localAuditRunner executes a submitted archive in this process with the same
// audit design TAA runs: Tier 1 static scan, the binary channel, optional Tier 2
// adjudication and the conclusion. Only one audit runs at a time: the pipeline
// is CPU-bound and the mock is a development tool, so a second submission is
// answered with 409 rather than queued behind an unbounded wait.
type localAuditRunner struct {
	jobs *auditJobStore
	// rules is the editable table the next scan runs with. The engine is built
	// from it per audit rather than once at startup, so an edit takes effect on
	// the next run without a restart.
	rules    *auditRuleStore
	binary   codeaudit.BinaryConfig
	console  *llmConsole
	workRoot string
	// files keeps the archives the workbench has been given, so a run can be
	// repeated from the file area without uploading the bytes again.
	files *auditFileStore
	// keys is the workbench's own SM2 pair. Uploads are sealed to it and the
	// audit opens them with it, which is how the mock reproduces TAA's
	// ciphertext ingress without a platform or a registered instance.
	keys *workbenchKeys

	mu     sync.Mutex
	busy   bool
	cancel context.CancelFunc
	prompt string

	// auditFn is a seam for the tests; production points at the real pipeline.
	auditFn func(context.Context, string, codeaudit.StaticEngine, codeaudit.AuditConfig, codeaudit.LLMClient) (*codeaudit.AuditReport, error)
}

func newLocalAuditRunner(jobs *auditJobStore, cfg Config, console *llmConsole) *localAuditRunner {
	if jobs == nil {
		jobs = globalAuditJobs
	}
	root := cfg.UploadDir
	if root == "" {
		root = os.TempDir()
	}
	if abs, err := filepath.Abs(root); err == nil {
		root = abs
	}
	filesDir := filepath.Join(root, "audit-files")
	rules := newAuditRuleStore()
	// The workbench reports the engine it actually runs. A semgrep selection
	// that this host cannot satisfy resolves back to regex per scan, with the
	// reason shown in the engine card.
	rules.useEngine(cfg.AuditEngine, cfg.SemgrepRules)
	return &localAuditRunner{
		jobs:     jobs,
		rules:    rules,
		binary:   codeaudit.DefaultBinaryConfig(),
		console:  console,
		workRoot: root,
		files:    newAuditFileStore(filesDir),
		// The pair lives beside the file area it opens. A workbench with no
		// writable upload directory still constructs: ready() then reports false
		// and the submit handler refuses with a clear message instead of
		// auditing plaintext.
		keys:    newWorkbenchKeys(filesDir),
		auditFn: codeaudit.GenerateAuditReport,
	}
}

// gatewayReachable dials the TEE-TLS listener without performing the handshake.
// It answers the only question that matters before a long request: is anything
// listening?
func gatewayReachable(endpoint string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", endpoint, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// acquire takes the single-runner slot. The caller that receives true owns the
// matching release, either directly (validation failed before the goroutine
// started) or through start (the goroutine releases when it settles).
func (r *localAuditRunner) acquire() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy {
		return false
	}
	r.busy = true
	return true
}

func (r *localAuditRunner) release() {
	r.mu.Lock()
	r.busy = false
	r.mu.Unlock()
}

// promptText returns the operator's override. Empty means the built-in
// instruction text is used.
func (r *localAuditRunner) promptText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.prompt
}

// effectivePromptText is what the prompt editor shows: the override when one is
// set, otherwise the built-in instruction text that the next audit would send.
func (r *localAuditRunner) effectivePromptText() string {
	if text := r.promptText(); text != "" {
		return text
	}
	return codeaudit.DefaultFindingPrompt()
}

func (r *localAuditRunner) setPrompt(text string) {
	text = strings.TrimSpace(text)
	// Saving the default text back is the same as clearing the override, and
	// keeps an unchanged textarea from becoming a pointless custom prompt.
	if text == strings.TrimSpace(codeaudit.DefaultFindingPrompt()) {
		text = ""
	}
	r.mu.Lock()
	r.prompt = text
	r.mu.Unlock()
}

// stop cancels an in-flight audit. It does not wait: the audit's own defer
// releases the slot and removes its working directory, and the server is
// shutting down either way.
func (r *localAuditRunner) stop() {
	r.mu.Lock()
	cancel := r.cancel
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

// llmConfig resolves the Tier 2 gateway the console would use. An empty
// endpoint means the step is skipped rather than failed: the workbench stays
// useful with no TEE-LLM deployment, and the user chose "connect if reachable,
// otherwise skip". FailClosed is therefore always false here, unlike TAA.
func (r *localAuditRunner) llmConfig() (codeaudit.LLMConfig, codeaudit.LLMClient) {
	cfg := codeaudit.LLMConfig{Enabled: false, PromptOverride: r.promptText()}
	if r.console == nil {
		return cfg, nil
	}
	endpoint := r.console.teeTLSEndpoint()
	if endpoint == "" {
		return cfg, nil
	}
	// A configured-but-unreachable gateway must not hold the single audit slot:
	// the request carries no deadline (a CPU verdict can take minutes), so a
	// dropped SYN would otherwise sit in the AI step until the OS gives up.
	// This is only a reachability probe; a reachable gateway still gets the
	// long-running request TAA uses.
	if !gatewayReachable(endpoint, 2*time.Second) {
		log.Printf("local audit: LLM gateway %s unreachable, AI step will be skipped", endpoint)
		return cfg, nil
	}
	settings := r.console.settingsSnapshot()
	model := r.console.state.get().Model
	if model == "" {
		model = codeaudit.DefaultLLMConfig().Model
	}
	cfg = codeaudit.LLMConfig{
		Enabled:            true,
		AttestationEnabled: true,
		Endpoint:           "https://" + endpoint,
		Model:              model,
		// Zero disables the per-request deadline for the same reason TAA leaves
		// it unset: a CPU-only verdict can take minutes and a short deadline is
		// misreported as the gateway being unavailable.
		Timeout:                 0,
		FailClosed:              false,
		CircuitBreakerThreshold: 3,
		CooldownSec:             30,
		PromptOverride:          r.promptText(),
		TEETLS: &teetls.Config{
			Mode:            teetls.AttestationMode(settings.Mode),
			SkipChainVerify: settings.SkipChainVerify,
		},
	}
	client, err := codeaudit.NewInferenceClient(cfg)
	if err != nil {
		log.Printf("local audit: LLM gateway unavailable, AI step will be skipped: %v", err)
		return codeaudit.LLMConfig{Enabled: false, PromptOverride: r.promptText()}, nil
	}
	return cfg, client
}

// start runs one audit in the background. The caller has already taken the
// runner slot and recorded the pending job; ownership of both moves here.
//
// workDir is the submission's temporary directory: archivePath is the sealed
// archive inside it, dataKeyCipher is the SM2 envelope over its SM4 key, and
// the extracted tree goes to workDir/src. Success and failure both remove
// workDir, so a refused audit leaves nothing behind.
func (r *localAuditRunner) start(workDir, archivePath, dataKeyCipher, requestID, taskID string) {
	r.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.mu.Unlock()

	go func() {
		defer cancel()
		defer r.release()
		defer os.RemoveAll(workDir)

		r.run(ctx, workDir, archivePath, dataKeyCipher, requestID, taskID)
	}()
}

func (r *localAuditRunner) run(ctx context.Context, workDir, archivePath, dataKeyCipher, requestID, taskID string) {
	// receive covers the handler's own work: the archive is sealed and staged by
	// the time this runs.
	r.jobs.setStage(localAuditInstanceKey, requestID, "receive", auditStepDone)
	r.jobs.setStage(localAuditInstanceKey, requestID, "extract", auditStepActive)

	// Opening the envelope is part of extract: same step, same failure handling,
	// because a key that does not fit the ciphertext is an ingress failure, not
	// an audit failure.
	plainPath := archivePath
	if dataKeyCipher != "" {
		plainPath = filepath.Join(workDir, "package.plain")
		if _, err := r.keys.openFile(archivePath, plainPath, dataKeyCipher); err != nil {
			reason := "解封审计包失败: " + err.Error()
			log.Printf("local audit %s: %s", requestID, reason)
			r.jobs.failAt(localAuditInstanceKey, requestID, "extract", reason)
			return
		}
	}

	srcDir := filepath.Join(workDir, "src")
	if err := resource.ExtractArchiveToDir(srcDir, plainPath); err != nil {
		reason := "解压归档失败: " + err.Error()
		log.Printf("local audit %s: %s", requestID, reason)
		r.jobs.failAt(localAuditInstanceKey, requestID, "extract", reason)
		return
	}

	llmCfg, client := r.llmConfig()
	// An AI step that cannot be adjudicated is reported as skipped, not failed:
	// the static and binary verdict still stands.
	aiEnabled := llmCfg.Enabled && client != nil
	current := "extract"

	onStage := func(stage string) {
		switch stage {
		case codeaudit.StageStatic:
			r.jobs.setStage(localAuditInstanceKey, requestID, current, auditStepDone)
			current = "static"
			r.jobs.setStage(localAuditInstanceKey, requestID, current, auditStepActive)
		case codeaudit.StageBinary:
			r.jobs.setStage(localAuditInstanceKey, requestID, current, auditStepDone)
			current = "binary"
			r.jobs.setStage(localAuditInstanceKey, requestID, current, auditStepActive)
		case codeaudit.StageAI:
			r.jobs.setStage(localAuditInstanceKey, requestID, current, auditStepDone)
			if aiEnabled {
				current = "ai"
				r.jobs.setStage(localAuditInstanceKey, requestID, current, auditStepActive)
			} else {
				current = "conclude"
				r.jobs.setStage(localAuditInstanceKey, requestID, "ai", auditStepSkipped)
			}
		case codeaudit.StageConclude:
			if current != "conclude" {
				r.jobs.setStage(localAuditInstanceKey, requestID, current, auditStepDone)
			}
			current = "conclude"
			r.jobs.setStage(localAuditInstanceKey, requestID, current, auditStepActive)
		}
	}

	// The engine is built here, per audit, from the table as it stands now: an
	// operator who edits a rule while the previous run is finishing expects the
	// next run to use it, and a startup-built engine would silently ignore it.
	engine, err := r.rules.engine()
	if err != nil {
		reason := "静态扫描引擎不可用: " + err.Error()
		log.Printf("local audit %s: %s", requestID, reason)
		r.jobs.failAt(localAuditInstanceKey, requestID, "static", reason)
		return
	}

	audit, err := r.auditFn(ctx, srcDir, engine,
		codeaudit.AuditConfig{LLM: llmCfg, Binary: r.binary, OnStage: onStage},
		client)
	if err != nil {
		reason := "审计失败: " + err.Error()
		log.Printf("local audit %s: %s", requestID, reason)
		r.jobs.failAt(localAuditInstanceKey, requestID, current, reason)
		return
	}
	if audit == nil {
		reason := "审计失败: 未产出报告"
		r.jobs.failAt(localAuditInstanceKey, requestID, current, reason)
		return
	}

	// The AI step's final state is decided here, not by the hook: the hook fires
	// before adjudication, and whether anything was actually adjudicated is only
	// known from the finished report.
	aiRan := aiEnabled && !audit.ScanMetadata.LLMDegraded && len(audit.FileReports) > 0
	if aiRan {
		r.jobs.setStage(localAuditInstanceKey, requestID, "ai", auditStepDone)
	} else {
		r.jobs.setStage(localAuditInstanceKey, requestID, "ai", auditStepSkipped)
	}

	code := 0
	if !audit.Conclusion.Passed {
		code = 1
	}
	raw, err := marshalLocalAuditReport(audit)
	if err != nil {
		r.jobs.failAt(localAuditInstanceKey, requestID, "conclude", "生成审计报告失败: "+err.Error())
		return
	}
	r.jobs.record(localAuditInstanceKey, requestID, taskID, code, raw)
	log.Printf("local audit %s: settled code=%d passed=%v risk=%s findings=%d",
		requestID, code, audit.Conclusion.Passed, audit.Conclusion.RiskLevel, audit.Statistics.Total())
}

// localAuditProjection is the report shape TAA reports to the platform:
// conclusion, file_reports and duration_ms, and nothing else. Keeping the mock
// on that projection means a workbench verdict and a real TAA verdict have the
// same shape in the job list.
type localAuditProjection struct {
	Conclusion  codeaudit.AuditConclusion `json:"conclusion"`
	FileReports []codeaudit.FileReport    `json:"file_reports"`
	DurationMS  int64                     `json:"duration_ms"`
}

func marshalLocalAuditReport(audit *codeaudit.AuditReport) (string, error) {
	data, err := json.Marshal(localAuditProjection{
		Conclusion:  audit.Conclusion,
		FileReports: audit.FileReports,
		DurationMS:  audit.ScanMetadata.ScanDurationMs,
	})
	if err != nil {
		return "", fmt.Errorf("marshal audit report: %w", err)
	}
	return string(data), nil
}
