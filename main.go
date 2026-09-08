package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	teecrypto "taa/crypto"
	"taa/internal/attestation"
	"taa/internal/codeaudit"
	"taa/internal/config"
	"taa/internal/controller"
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

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.LoadStartupConfig(config.DefaultFileName)
	if err != nil {
		return err
	}

	if cfg.EnableLLM {
		ensureQwenAvailable(cfg.LLMEndpoint, cfg.LLMModel, cfg.LLMDir)
	}

	keyPair, err := generateTAAKeyPair()
	if err != nil {
		return err
	}

	platformIP := cfg.PlatformIP
	dockerID := cfg.DockerID

	timestamp := time.Now().Unix()
	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	logUserDataSummary(platformIP, dockerID, keyPair.PublicKeyPEM, timestamp, userData)

	if err := prepareAttestationReport(userData); err != nil {
		return err
	}

	if err := registerPlatform(platformIP, dockerID, keyPair.PublicKeyPEM, timestamp); err != nil {
		log.Printf("WARNING: platform register failed, continuing startup: %v", err)
	} else {
		log.Printf("platform register completed")
	}
	logGeneratedTAAKeyPair(keyPair)

	sec := buildSecurityConfig(cfg)
	if err := ensureSecurityDirectories(sec); err != nil {
		return err
	}
	logSecurityConfig(sec)

	state := controller.NewTAAState(fixedAttestationFile, platformIP, dockerID, fixedAttestationHelper, fixedAttestationMode, keyPair.PrivateKey, userData, sec)

	server := newTAAServer(cfg.Addr, state)
	log.Printf("taa service listening on %s", cfg.Addr)

	return server.ListenAndServe()
}

func logUserDataSummary(platformIP, dockerID, publicKeyPEM string, timestamp int64, userData []byte) {
	log.Printf("generated userdata: taa SM2 public key raw X||Y")
	log.Printf("  input: taaPublicKey(%d bytes) + dockerId(%s) + platformIP(%s) + timestamp(%d)",
		len(publicKeyPEM), dockerID, platformIP, timestamp)
	log.Printf("  userdata (64 bytes hex): %x", userData)
}

func prepareAttestationReport(userData []byte) error {
	log.Printf("generating attestation report: helper=%q output=%s", fixedAttestationHelper, fixedAttestationFile)
	if err := attestation.Generate(context.Background(), attestation.Config{
		OutputPath: fixedAttestationFile,
		HelperPath: fixedAttestationHelper,
		Mode:       fixedAttestationMode,
		UserData:   userData,
	}); err != nil {
		log.Printf("WARNING: generating attestation report failed, continuing with empty report: %v", err)
		if writeErr := os.WriteFile(fixedAttestationFile, nil, 0o600); writeErr != nil {
			return fmt.Errorf("write empty attestation report: %w", writeErr)
		}
	} else {
		log.Printf("attestation report ready: %s", fixedAttestationFile)
	}
	return nil
}

func registerPlatform(platformIP, dockerID, publicKeyPEM string, timestamp int64) error {
	log.Printf("notifying platform register: platform=%s dockerId=%s attestation=%s timestamp=%d", platformIP, dockerID, fixedAttestationFile, timestamp)
	return controller.NoticeRegister(context.Background(), platformIP, dockerID, fixedAttestationFile, publicKeyPEM, timestamp)
}

func buildSecurityConfig(cfg config.StartupConfig) controller.SecurityConfig {
	return controller.SecurityConfig{
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
}

func ensureSecurityDirectories(sec controller.SecurityConfig) error {
	for _, dir := range []string{sec.ModelDir, sec.DataDir, sec.ResultDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}

func logSecurityConfig(sec controller.SecurityConfig) {
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
}

func newTAAServer(addr string, state *controller.TAAState) *http.Server {
	mux := http.NewServeMux()
	controller.RegisterRoutes(mux, state)

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// ensureQwenAvailable 检查 qwen (ollama) 服务是否可用，不可用时尝试启动。
// 启动失败仅打印警告，不阻塞 TAA 启动。
func ensureQwenAvailable(endpoint, model, ollamaDir string) {
	log.Printf("checking qwen service: endpoint=%s model=%s", endpoint, model)

	// 1. 检查是否已经可用
	if isOllamaReady(endpoint, model) {
		log.Printf("qwen service already available")
		return
	}

	// 2. 尝试启动 ollama
	log.Printf("qwen service not available, attempting to start...")

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
		log.Printf("WARNING: qwen 启动失败: 未找到 ollama 包目录 (在 %s 的 llm.dir 指定路径)", config.DefaultFileName)
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
