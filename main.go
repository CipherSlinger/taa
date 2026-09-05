package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"taa/internal/attestation"
	"taa/internal/codeaudit"
	"taa/internal/controller"

	teecrypto "taa/crypto"
)

const (
	fixedAttestationFile   = "attestation.report"
	fixedAttestationHelper = "./attestation/get-attestation"
	fixedAttestationMode   = "auto"
)

type taaKeyPair struct {
	PrivateKey   *teecrypto.SM2PrivateKey
	PublicKeyPEM string
}

type startupConfig struct {
	Addr               string
	EnableSecurityScan bool
	ModelDir           string
	EnableResultCheck  bool
	DataDir            string
	ResultDir          string
	EnableLLM          bool
	LLMEndpoint        string
	LLMModel           string
	LLMPolicy          string
	LLMFailClosed      bool
}

func parseStartupFlags(args []string) (startupConfig, error) {
	fs := flag.NewFlagSet("taa", flag.ContinueOnError)
	addr := fs.String("addr", ":6001", "HTTP listen address")
	enableSecurityScan := fs.Bool("security-scan", envBool("SECURITY_SCAN", true), "enable source code security scan on model import")
	modelDir := fs.String("model-dir", envDefault("MODEL_DIR", "/opt/taa/models"), "directory where imported model code is stored (type=1)")
	enableResultCheck := fs.Bool("result-check", envBool("RESULT_CHECK", true), "enable plaintext data leakage check on result export")
	dataDir := fs.String("data-dir", envDefault("DATA_DIR", "/opt/taa/data"), "directory where imported data is stored (type=2 test data, type=3 training data)")
	resultDir := fs.String("result-dir", envDefault("RESULT_DIR", "/opt/taa/results"), "directory where training results are stored")

	// LLM verifier configuration.
	enableLLM := fs.Bool("security-llm-verify", envBool("SECURITY_LLM_VERIFY", true), "enable LLM semantic verification on suspicious findings")
	llmEndpoint := fs.String("security-llm-endpoint", envDefault("SECURITY_LLM_ENDPOINT", "http://127.0.0.1:11434"), "local LLM inference endpoint (Ollama/llama.cpp)")
	llmModel := fs.String("security-llm-model", envDefault("SECURITY_LLM_MODEL", "qwen2.5-coder:0.5b"), "model name for LLM verifier")
	llmPolicy := fs.String("security-llm-policy", envDefault("SECURITY_LLM_POLICY", "assist"), "LLM policy: assist (informational) or gate (can downgrade findings)")
	llmFailClosed := fs.Bool("security-llm-fail-closed", envBool("SECURITY_LLM_FAIL_CLOSED", true), "block import if LLM verifier is unavailable")

	var flagArgs []string
	if len(args) > 1 {
		flagArgs = args[1:]
	}
	if err := fs.Parse(flagArgs); err != nil {
		return startupConfig{}, err
	}

	return startupConfig{
		Addr:               *addr,
		EnableSecurityScan: *enableSecurityScan,
		ModelDir:           *modelDir,
		EnableResultCheck:  *enableResultCheck,
		DataDir:            *dataDir,
		ResultDir:          *resultDir,
		EnableLLM:          *enableLLM,
		LLMEndpoint:        *llmEndpoint,
		LLMModel:           *llmModel,
		LLMPolicy:          *llmPolicy,
		LLMFailClosed:      *llmFailClosed,
	}, nil
}

func main() {
	cfg, err := parseStartupFlags(os.Args)
	if err != nil {
		log.Fatal(err)
	}

	if cfg.EnableLLM {
		ensureQwenAvailable(cfg.LLMEndpoint, cfg.LLMModel)
	}

	keyPair, err := generateTAAKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	platformIP := os.Getenv("PLATFORM_IP")
	dockerID := os.Getenv("DOCKER_ID")

	// 生成 USERDATA
	timestamp := time.Now().Unix()
	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("generated userdata: taa SM2 public key raw X||Y")
	log.Printf("  input: taaPublicKey(%d bytes) + dockerId(%s) + platformIP(%s) + timestamp(%d)",
		len(keyPair.PublicKeyPEM), dockerID, platformIP, timestamp)
	log.Printf("  userdata (64 bytes hex): %x", userData)

	log.Printf("generating attestation report: helper=%q output=%s", fixedAttestationHelper, fixedAttestationFile)
	if err := attestation.Generate(context.Background(), attestation.Config{
		OutputPath: fixedAttestationFile,
		HelperPath: fixedAttestationHelper,
		Mode:       fixedAttestationMode,
		UserData:   userData,
	}); err != nil {
		log.Printf("WARNING: generating attestation report failed, continuing with empty report: %v", err)
		if writeErr := os.WriteFile(fixedAttestationFile, nil, 0o600); writeErr != nil {
			log.Fatalf("write empty attestation report: %v", writeErr)
		}
	} else {
		log.Printf("attestation report ready: %s", fixedAttestationFile)
	}

	log.Printf("notifying platform register: platform=%s dockerId=%s attestation=%s timestamp=%d", platformIP, dockerID, fixedAttestationFile, timestamp)
	if err := controller.NoticeRegister(context.Background(), platformIP, dockerID, fixedAttestationFile, keyPair.PublicKeyPEM, timestamp); err != nil {
		log.Printf("WARNING: platform register failed, continuing startup: %v", err)
	} else {
		log.Printf("platform register completed")
	}
	logGeneratedTAAKeyPair(keyPair)

	sec := controller.SecurityConfig{
		ScanEnabled: cfg.EnableSecurityScan,
		ModelDir:    cfg.ModelDir,
		ResultCheck: cfg.EnableResultCheck,
		DataDir:     cfg.DataDir,
		ResultDir:   cfg.ResultDir,
		LLM: codeaudit.LLMConfig{
			Enabled:     cfg.EnableLLM,
			Endpoint:    cfg.LLMEndpoint,
			Model:       cfg.LLMModel,
			Timeout:     60 * time.Second,
			MaxFindings: 20,
			Policy:      cfg.LLMPolicy,
			FailClosed:  cfg.LLMFailClosed,
		},
	}
	// 确保所有资源目录存在
	for _, dir := range []string{sec.ModelDir, sec.DataDir, sec.ResultDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Fatalf("create directory %s: %v", dir, err)
		}
	}

	state := controller.NewTAAState(fixedAttestationFile, platformIP, dockerID, fixedAttestationHelper, fixedAttestationMode, keyPair.PrivateKey, userData, sec)

	if sec.ScanEnabled {
		log.Printf("security scan enabled: model-dir=%s", sec.ModelDir)
		if sec.LLM.Enabled {
			log.Printf("  LLM verifier enabled: model=%s endpoint=%s policy=%s fail-closed=%v",
				sec.LLM.Model, sec.LLM.Endpoint, sec.LLM.Policy, sec.LLM.FailClosed)
		}
	}
	if sec.ResultCheck {
		log.Printf("result check enabled: data-dir=%s result-dir=%s", sec.DataDir, sec.ResultDir)
	}

	mux := http.NewServeMux()
	controller.RegisterRoutes(mux, state)

	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("taa service listening on %s", cfg.Addr)

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envDefault(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v == "true"
}

// ensureQwenAvailable 检查 qwen (ollama) 服务是否可用，不可用时尝试启动。
// 启动失败仅打印警告，不阻塞 TAA 启动。
func ensureQwenAvailable(endpoint, model string) {
	log.Printf("checking qwen service: endpoint=%s model=%s", endpoint, model)

	// 1. 检查是否已经可用
	if isOllamaReady(endpoint, model) {
		log.Printf("qwen service already available")
		return
	}

	// 2. 尝试启动 ollama
	log.Printf("qwen service not available, attempting to start...")

	ollamaDir := envDefault("OLLAMA_DIR", "")
	if ollamaDir == "" {
		// 默认路径：容器内 TAA 工作目录下的 ollama 包
		// deploy.sh 部署到 $CON_WORKDIR/ollama-qwen2.5-coder-0.5b
		candidates := []string{
			"/root/taa/ollama-qwen2.5-coder-0.5b",
			"/root/taadebug/ollama-qwen2.5-coder-0.5b",
		}
		for _, c := range candidates {
			if fi, err := os.Stat(c); err == nil && fi.IsDir() {
				ollamaDir = c
				break
			}
		}
	}

	if ollamaDir == "" {
		log.Printf("WARNING: qwen 启动失败: 未找到 ollama 包目录 (设置 OLLAMA_DIR 环境变量指定路径)")
		log.Printf("WARNING: 代码审计将仅使用静态扫描，LLM 语义分析不可用")
		return
	}

	startScript := ollamaDir + "/start-ollama.sh"
	if _, err := os.Stat(startScript); err != nil {
		log.Printf("WARNING: qwen 启动失败: 未找到启动脚本 %s", startScript)
		return
	}

	// 启动 ollama 进程（后台运行）
	cmd := exec.Command("sh", "-c", fmt.Sprintf("cd %s && OLLAMA_HOST=%s nohup ./start-ollama.sh > /tmp/ollama.log 2>&1 &", ollamaDir, endpoint))
	if err := cmd.Run(); err != nil {
		log.Printf("WARNING: qwen 启动命令执行失败: %v", err)
		log.Printf("WARNING: 代码审计将仅使用静态扫描，LLM 语义分析不可用")
		return
	}
	log.Printf("ollama start command executed, waiting for readiness...")

	// 3. 等待就绪（最多 120 秒，每 2 秒检查一次）
	const maxWait = 120 * time.Second
	const interval = 2 * time.Second
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		if isOllamaReady(endpoint, model) {
			log.Printf("qwen service started successfully")
			return
		}
		time.Sleep(interval)
	}

	log.Printf("WARNING: qwen 服务在 %v 内未就绪，代码审计将仅使用静态扫描", maxWait)
	log.Printf("WARNING: ollama 日志: 请检查 /tmp/ollama.log")
}

// isOllamaReady 检查 ollama 服务是否就绪且模型已加载。
func isOllamaReady(endpoint, model string) bool {
	// endpoint 可能含 http:// 前缀，也可能不含
	base := endpoint
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(base + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}

	// 检查模型是否已加载（可选，因为模型可能还没拉取）
	body, _ := io.ReadAll(resp.Body)
	// 简单检查模型名是否出现在 tags 响应中
	return strings.Contains(string(body), model) || model == ""
}

// deriveUserData generates the 64-byte USERDATA field for the attestation report.
// It stores the TAA SM2 public key as raw X||Y coordinates.
func deriveUserData(pub *teecrypto.SM2PublicKey) ([]byte, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("TAA SM2 public key is required")
	}
	userData := make([]byte, 64)
	copy(userData[32-len(pub.X.Bytes()):32], pub.X.Bytes())
	copy(userData[64-len(pub.Y.Bytes()):], pub.Y.Bytes())
	return userData, nil
}

func generateTAAKeyPair() (*taaKeyPair, error) {
	priv, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate TAA SM2 key pair: %w", err)
	}

	pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal TAA SM2 public key: %w", err)
	}

	return &taaKeyPair{PrivateKey: priv, PublicKeyPEM: string(pubPEM)}, nil
}

func logGeneratedTAAKeyPair(keyPair *taaKeyPair) {
	if keyPair == nil {
		return
	}
	log.Printf("generated TAA SM2 public key:\n%s", keyPair.PublicKeyPEM)
}
