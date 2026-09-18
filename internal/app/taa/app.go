// Package taa 抽象了 TAA 守护进程的运行生命周期与服务编排：
// 加载启动配置、拉起辅助 LLM 审计服务、生成密钥对与远程证明报告、
// 向管控平台注册、构建安全策略配置，并最终启动 HTTP 服务对外提供接口。
package taa

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"taa/internal/attestation"
	"taa/internal/codeaudit"
	"taa/internal/config"
	"taa/internal/controller"
	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
	"taa/teellm"
	"taa/teetls"
)

// ============================================================================
// 常量与数据结构定义
// ============================================================================

const (
	// fixedAttestationFile 为生成的 TEE 远程证明报告默认落盘路径
	fixedAttestationFile = "attestation.report"

	// defaultSM2PrivateKeyFile 为 TAA 实例 SM2 私钥存储文件名（PKCS#8 PEM 格式，严格权限 0600）
	defaultSM2PrivateKeyFile = "sm2_private_key.pem"

	// defaultSM2PublicKeyFile 为 TAA 实例 SM2 公钥存储文件名（SubjectPublicKeyInfo PEM 格式，权限 0644）
	defaultSM2PublicKeyFile = "sm2_public_key.pem"
)

// taaKeyPair 保存 TAA 启动时生成的国密 SM2 私钥对象与 PEM 格式公钥字符串
type taaKeyPair struct {
	PrivateKey   *teecrypto.SM2PrivateKey
	PublicKeyPEM string
}

// ============================================================================
// 生命周期主入口
// ============================================================================

// Run 加载指定路径的启动配置文件并编排 TAA 服务的完整生命周期。
// configPath 为空时使用 config.DefaultFileName 默认路径；
// addr 非空时覆盖配置文件中的监听地址。
func Run(ctx context.Context, configPath, addr string) error {
	path := config.DefaultFileName
	if configPath != "" {
		path = configPath
	}
	cfg, err := config.LoadStartupConfig(path)
	if err != nil {
		return fmt.Errorf("load startup config: %w", err)
	}
	if addr != "" {
		cfg.Addr = addr
	}
	return RunWithConfig(ctx, cfg)
}

// RunWithConfig orchestrates the complete lifecycle and startup flow of the TAA service:
//  1. If LLM code audit is enabled, probe external inference service readiness
//  2. Load or generate persistent SM2 key pair for this TAA instance
//  3. Derive 64-byte UserData and bind it to the TEE attestation report
//  4. Generate underlying TEE hardware remote attestation report
//  5. Register this TAA instance with the platform
//  6. Build security policy configuration and ensure directories are ready
//  7. Construct global controller state and start HTTP service, supporting graceful shutdown via ctx
func RunWithConfig(ctx context.Context, cfg config.StartupConfig) error {
	// 1. If LLM code audit is enabled, probe inference service readiness.
	if cfg.EnableLLM {
		if err := probeInferenceService(ctx, cfg); err != nil {
			if cfg.LLMFailClosed {
				return fmt.Errorf("probe inference service (fail-closed): %w", err)
			}
			log.Printf("WARNING: inference service probe failed (non-fatal): %v", err)
		}
	}

	// 2. 加载或生成本 TAA 实例专用的国密 SM2 密钥对（优先从持久化目录加载，若不存在则生成并落盘）
	keysDir := cfg.KeysDir
	if keysDir == "" {
		keysDir = "/opt/taa/keys"
	}
	keyPair, loaded, err := loadOrGenerateTAAKeyPair(keysDir)
	if err != nil {
		return fmt.Errorf("initialize TAA SM2 key pair: %w", err)
	}
	if loaded {
		log.Printf("loaded persistent TAA SM2 key pair from %s", keysDir)
	} else {
		log.Printf("generated and saved persistent TAA SM2 key pair to %s", keysDir)
	}

	// 派生 SealingKey 并初始化持久化密封状态存储
	sealingKey := store.DeriveSealingKey(keyPair.PrivateKey)
	statePath := filepath.Join(keysDir, "state.sealed")
	stateStore, err := store.NewStateStore(statePath, sealingKey)
	if err != nil {
		return fmt.Errorf("initialize state store: %w", err)
	}
	if _, err := stateStore.DetectAndHandleKeyDrift(!loaded); err != nil {
		return fmt.Errorf("detect and handle key drift (fail-closed): %w", err)
	}

	platformIP := cfg.PlatformIP
	dockerID := cfg.DockerID
	timestamp := time.Now().Unix()

	// 3. 将 SM2 公钥坐标 (X||Y) 填充为 64 字节 UserData，供 TEE 硬件报告度量签名
	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	logUserDataSummary(platformIP, dockerID, keyPair.PublicKeyPEM, timestamp, userData)

	// 4. Generate attestation report containing UserData and perform certificate self-verification
	verifiedPass, err := prepareAttestationReport(ctx, userData, cfg.AttestationHRKCertPath, cfg.AttestationHSKCekCertPath)
	if err != nil {
		return err
	}

	// 5. 向管控平台注册本 TAA 实例，通知平台就绪并提交度量报告与公钥
	if err := registerPlatform(ctx, platformIP, dockerID, keyPair.PublicKeyPEM, timestamp, verifiedPass); err != nil {
		log.Printf("WARNING: platform register failed, continuing startup: %v", err)
	} else {
		log.Printf("platform register completed")
	}
	logGeneratedTAAKeyPair(keyPair)

	// 6. 构建安全策略配置并确保模型/数据/结果目录已就绪
	sec := buildSecurityConfig(cfg)
	if err := ensureSecurityDirectories(sec); err != nil {
		return err
	}
	logSecurityConfig(sec)

	// 7. 创建全局状态管理器并恢复受保护持久化状态
	state := controller.NewTAAState(
		fixedAttestationFile,
		platformIP,
		dockerID,
		cfg.AttestationHRKCertPath,
		cfg.AttestationHSKCekCertPath,
		keyPair.PrivateKey,
		userData,
		sec,
	)
	state.SetStateStore(stateStore)

	pState := stateStore.GetState()
	if pState != nil {
		state.RestoreFromPersistentState(pState)
		if pState.ActiveTask != nil && pState.ActiveTask.Status == "RUNNING" {
			log.Printf("detected interrupted active task during startup, executing crash recovery: taskId=%s, type=%s",
				pState.ActiveTask.TaskID, pState.ActiveTask.Type)
			if err := reconcileCrashRecovery(ctx, state, stateStore, pState.ActiveTask); err != nil {
				log.Printf("WARNING: reconcile crash recovery failed: %v", err)
			}
		}
	}

	logWatcher := state.StartTaaLogWatcher(ctx)
	defer logWatcher.Stop()

	return startServer(ctx, cfg.Addr, state)
}

// ============================================================================
// External Inference Service Readiness Probe
// ============================================================================

// probeInferenceService checks the availability of the external inference service
// without spawning any subprocess. It utilizes the standardized TEE-LLM client.
func probeInferenceService(ctx context.Context, cfg config.StartupConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	timeout := time.Duration(cfg.LLMTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	var teeTLSConfig *teetls.Config
	if cfg.LLMTransport == "teetls" || cfg.LLMTransport == "https" || cfg.LLMTransport == "" {
		mode := teetls.ModeStrict
		if cfg.LLMAttestationMode == "permissive" {
			mode = teetls.ModePermissive
		}
		teeTLSConfig = &teetls.Config{
			Mode:                          mode,
			InsecureSkipAttestationVerify: cfg.LLMInsecureSkipVerify,
			ExpectedMeasurements:          cfg.LLMExpectedMeasurements,
			VerifyMutualAttestation:       cfg.LLMRequireMutualAttest,
		}
		if cfg.LLMHRKCertPath != "" || cfg.LLMHSKCekCertPath != "" {
			teeTLSConfig.EvidenceProvider = teetls.NewHygonHardwareProvider("", cfg.LLMHRKCertPath, cfg.LLMHSKCekCertPath)
		}
	}

	client, err := teellm.NewClient(teellm.Config{
		Endpoint:                       cfg.LLMEndpoint,
		Timeout:                        timeout,
		AllowedHosts:                   cfg.LLMAllowedHosts,
		TEETLS:                         teeTLSConfig,
		CircuitBreakerFailureThreshold: cfg.LLMCircuitBreakerThreshold,
		CircuitBreakerCooldown:         time.Duration(cfg.LLMCooldownSec) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("create inference client: %w", err)
	}
	defer client.Close()

	probeTimeout := 5 * time.Second
	if cfg.LLMTimeoutMs > 0 {
		probeTimeout = timeout
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	log.Printf("probing inference service readiness (transport=%s, endpoint=%s, attestMode=%s)",
		cfg.LLMTransport, cfg.LLMEndpoint, cfg.LLMAttestationMode)
	if err := client.HealthCheck(probeCtx); err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	log.Printf("inference service probe succeeded")
	return nil
}

// ============================================================================
// 密码学密钥对与 TEE 度量 UserData 生成
// ============================================================================

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for sync: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}

// checkKeyFileExists 检查指定路径的密钥文件是否存在。若发生权限错误、I/O 错误或目标为目录，
// 严格返回错误（Fail-Closed），避免将异常状态误判为文件不存在而触发非预期的重新生成覆盖。
func checkKeyFileExists(path string) (bool, error) {
	st, err := os.Stat(path)
	if err == nil {
		if st.IsDir() {
			return false, fmt.Errorf("expected key file but found directory: %s", path)
		}
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("stat key file %s: %w", path, err)
}

// writeKeyFileAtomic 使用临时文件+fsync+原子重命名的方式安全写入密钥文件，并严格设置指定权限
func writeKeyFileAtomic(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("ensure key dir %s: %w", dir, err)
	}
	if fi, err := os.Stat(dir); err == nil && fi.Mode().Perm() != 0o700 {
		_ = os.Chmod(dir, 0o700)
	}

	tmpFile, err := os.CreateTemp(dir, ".tmp-key-*")
	if err != nil {
		return fmt.Errorf("create temp key file in %s: %w", dir, err)
	}
	tmpPath := tmpFile.Name()

	cleanupNeeded := true
	defer func() {
		if cleanupNeeded {
			if rmErr := os.Remove(tmpPath); rmErr != nil && !os.IsNotExist(rmErr) {
				log.Printf("ERROR: failed to clean up temporary key file %s: %v", tmpPath, rmErr)
			}
		}
	}()

	isClosed := false
	defer func() {
		if !isClosed {
			_ = tmpFile.Close()
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("write key data to %s: %w", tmpPath, err)
	}

	if err := tmpFile.Chmod(perm); err != nil {
		return fmt.Errorf("set permissions on %s: %w", tmpPath, err)
	}

	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("fsync key file %s: %w", tmpPath, err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close key file %s: %w", tmpPath, err)
	}
	isClosed = true

	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("atomic rename %s to %s: %w", tmpPath, targetPath, err)
	}

	if err := syncDir(dir); err != nil {
		log.Printf("WARNING: fsync parent dir %s: %v", dir, err)
	}

	cleanupNeeded = false
	return nil
}

// loadOrGenerateTAAKeyPair 优先从 keysDir 目录检查并加载已有的国密 SM2 公私钥对；
// 若密钥不存在，则生成新的 SM2 密钥对并以安全权限持久化落盘（私钥 0600，公钥 0644）；
// 若检测到公私钥不匹配或非预期的单边损坏，采用 Fail-Closed 严格报错以避免覆盖损坏历史解密凭证；
// 若仅公钥缺失而私钥完整，则通过私钥自愈派生公钥并补齐落盘。
// 返回的 loaded 表示是否从现有文件中成功加载。
func loadOrGenerateTAAKeyPair(keysDir string) (*taaKeyPair, bool, error) {
	cleanDir := strings.TrimSpace(keysDir)
	if cleanDir == "" {
		cleanDir = "/opt/taa/keys"
	}
	cleanDir = filepath.Clean(cleanDir)

	privPath := filepath.Join(cleanDir, defaultSM2PrivateKeyFile)
	pubPath := filepath.Join(cleanDir, defaultSM2PublicKeyFile)

	privExists, err := checkKeyFileExists(privPath)
	if err != nil {
		return nil, false, err
	}
	pubExists, err := checkKeyFileExists(pubPath)
	if err != nil {
		return nil, false, err
	}

	// 防御性安全加固：若私钥存在但权限被外部篡改，在加载或自愈前主动收紧权限；若属于组或其他用户可读且收紧失败则 Fail-Closed
	if privExists {
		if privStat, err := os.Stat(privPath); err == nil && privStat.Mode().Perm() != 0o600 {
			if err := os.Chmod(privPath, 0o600); err != nil {
				if privStat.Mode().Perm()&0o077 != 0 {
					return nil, false, fmt.Errorf("insecure private key permissions (%o) on %s and failed to tighten: %w", privStat.Mode().Perm(), privPath, err)
				}
				log.Printf("WARNING: failed to tighten private key permissions on %s from %o to 0600: %v", privPath, privStat.Mode().Perm(), err)
			}
		}
		if dirStat, err := os.Stat(cleanDir); err == nil && dirStat.Mode().Perm() != 0o700 {
			if err := os.Chmod(cleanDir, 0o700); err != nil {
				if dirStat.Mode().Perm()&0o077 != 0 {
					log.Printf("WARNING: insecure keys directory permissions (%o) on %s and failed to tighten: %v", dirStat.Mode().Perm(), cleanDir, err)
				}
			}
		}
	}

	// 1. 两个文件均存在：加载并校验一致性
	if privExists && pubExists {
		privData, err := os.ReadFile(privPath)
		if err != nil {
			return nil, false, fmt.Errorf("read private key file %s: %w", privPath, err)
		}
		pubData, err := os.ReadFile(pubPath)
		if err != nil {
			return nil, false, fmt.Errorf("read public key file %s: %w", pubPath, err)
		}

		privKey, err := teecrypto.ParseSM2PrivateKeyPEM(privData)
		if err != nil {
			return nil, false, fmt.Errorf("parse private key from %s: %w", privPath, err)
		}
		pubKey, err := teecrypto.ParseSM2PublicKeyPEM(pubData)
		if err != nil {
			return nil, false, fmt.Errorf("parse public key from %s: %w", pubPath, err)
		}

		// 严格校验公私钥点坐标一致性
		if privKey.PublicKey.X == nil || privKey.PublicKey.Y == nil ||
			pubKey.X == nil || pubKey.Y == nil ||
			privKey.PublicKey.X.Cmp(pubKey.X) != 0 || privKey.PublicKey.Y.Cmp(pubKey.Y) != 0 {
			return nil, false, fmt.Errorf("key mismatch in %s: public key does not correspond to private key", cleanDir)
		}

		log.Printf("successfully loaded persistent TAA SM2 key pair from %s", cleanDir)
		return &taaKeyPair{PrivateKey: privKey, PublicKeyPEM: string(pubData)}, true, nil
	}

	// 2. 异常状态检测：公钥存在但私钥缺失 -> Fail-Closed 严禁重新生成
	if !privExists && pubExists {
		return nil, false, fmt.Errorf("inconsistent key state in %s: public key exists (%s) but private key (%s) is missing; refusing to overwrite to prevent data loss", cleanDir, pubPath, privPath)
	}

	// 3. 自愈状态检测：私钥存在但公钥缺失 -> 从私钥派生并自动补充公钥
	if privExists && !pubExists {
		privData, err := os.ReadFile(privPath)
		if err != nil {
			return nil, false, fmt.Errorf("read private key file %s: %w", privPath, err)
		}
		privKey, err := teecrypto.ParseSM2PrivateKeyPEM(privData)
		if err != nil {
			return nil, false, fmt.Errorf("parse private key from %s: %w", privPath, err)
		}
		pubPEM, err := teecrypto.MarshalSM2PublicKeyPEM(&privKey.PublicKey)
		if err != nil {
			return nil, false, fmt.Errorf("marshal derived public key: %w", err)
		}
		if err := writeKeyFileAtomic(pubPath, pubPEM, 0o644); err != nil {
			return nil, false, fmt.Errorf("self-heal and write public key to %s: %w", pubPath, err)
		}
		log.Printf("self-healed missing public key from private key in %s", cleanDir)
		return &taaKeyPair{PrivateKey: privKey, PublicKeyPEM: string(pubPEM)}, true, nil
	}

	// 4. 双文件均不存在：首次启动生成新密钥并持久化落盘
	if err := os.MkdirAll(cleanDir, 0o700); err != nil {
		return nil, false, fmt.Errorf("create keys dir %s: %w", cleanDir, err)
	}

	keyPair, err := generateTAAKeyPair()
	if err != nil {
		return nil, false, err
	}

	privPEM, err := teecrypto.MarshalSM2PrivateKeyPEM(keyPair.PrivateKey)
	if err != nil {
		return nil, false, fmt.Errorf("marshal private key: %w", err)
	}

	if err := writeKeyFileAtomic(privPath, privPEM, 0o600); err != nil {
		return nil, false, fmt.Errorf("persist private key to %s: %w", privPath, err)
	}

	if err := writeKeyFileAtomic(pubPath, []byte(keyPair.PublicKeyPEM), 0o644); err != nil {
		return nil, false, fmt.Errorf("persist public key to %s: %w", pubPath, err)
	}

	log.Printf("generated and persisted new TAA SM2 key pair to %s", cleanDir)
	return keyPair, false, nil
}

// generateTAAKeyPair 生成本 TAA 实例专用的国密 SM2 密钥对，并编码导出 PEM 格式公钥
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

// deriveUserData 将 TAA 的 SM2 公钥未压缩坐标 (X||Y) 打包成 64 字节数组（前 32 字节 X，后 32 字节 Y），
// 填入 TEE 报告的 USERDATA 字段中，实现硬件度量报告与应用公钥身份的密码学强绑定。
func deriveUserData(pub *teecrypto.SM2PublicKey) ([]byte, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, fmt.Errorf("TAA SM2 public key is required")
	}
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	if len(xBytes) > 32 || len(yBytes) > 32 {
		return nil, fmt.Errorf("SM2 coordinate size exceeds 32 bytes: x=%d y=%d", len(xBytes), len(yBytes))
	}
	userData := make([]byte, 64)
	copy(userData[32-len(xBytes):32], xBytes)
	copy(userData[64-len(yBytes):], yBytes)
	return userData, nil
}

// logGeneratedTAAKeyPair 打印生成的 TAA SM2 公钥 PEM 文本
func logGeneratedTAAKeyPair(keyPair *taaKeyPair) {
	if keyPair == nil {
		return
	}
	log.Printf("generated TAA SM2 public key:\n%s", keyPair.PublicKeyPEM)
}

// logUserDataSummary 打印 UserData 与关联元数据摘要日志
func logUserDataSummary(platformIP, dockerID, publicKeyPEM string, timestamp int64, userData []byte) {
	log.Printf("generated userdata: taa SM2 public key raw X||Y")
	log.Printf("  input: taaPublicKey(%d bytes) + dockerId(%s) + platformIP(%s) + timestamp(%d)",
		len(publicKeyPEM), dockerID, platformIP, timestamp)
	log.Printf("  userdata (64 bytes hex): %x", userData)
}

// ============================================================================
// TEE 远程证明报告与管控平台注册
// ============================================================================

// prepareAttestationReport invokes underlying TEE tools to generate attestation report and performs certificate self-verification.
// In non-TEE environments or upon generation failure, writes an empty report and logs a warning, allowing service to start in degraded mode (verifiedPass=false).
func prepareAttestationReport(ctx context.Context, userData []byte, hrkCertPath, hskCekCertPath string) (bool, error) {
	log.Printf("generating attestation report: output=%s", fixedAttestationFile)
	if err := attestation.Generate(ctx, attestation.Config{
		OutputPath: fixedAttestationFile,
		UserData:   userData,
	}); err != nil {
		log.Printf("WARNING: generating attestation report failed, continuing with empty report: %v", err)
		if writeErr := os.WriteFile(fixedAttestationFile, nil, 0o600); writeErr != nil {
			return false, fmt.Errorf("write empty attestation report: %w", writeErr)
		}
		return false, nil
	}

	reportBytes, err := os.ReadFile(fixedAttestationFile)
	if err != nil {
		log.Printf("WARNING: failed to read attestation report %s: %v", fixedAttestationFile, err)
		return false, nil
	}
	if len(reportBytes) == 0 {
		return false, nil
	}

	if _, verifyErr := attestation.VerifyReport(reportBytes, hrkCertPath, hskCekCertPath); verifyErr != nil {
		log.Printf("WARNING: attestation self-verification failed: %v", verifyErr)
		return false, nil
	}

	log.Printf("attestation report verified successfully: %s", fixedAttestationFile)
	return true, nil
}

// registerPlatform sends a registration request to the platform, reporting DockerID, attestation report, TAA public key, timestamp, and self-verification status.
func registerPlatform(ctx context.Context, platformIP, dockerID, publicKeyPEM string, timestamp int64, verifiedPass bool) error {
	log.Printf("notifying platform register: platform=%s dockerId=%s attestation=%s timestamp=%d verifiedPass=%v",
		platformIP, dockerID, fixedAttestationFile, timestamp, verifiedPass)
	return controller.NoticeRegister(ctx, platformIP, dockerID, fixedAttestationFile, publicKeyPEM, timestamp, verifiedPass)
}

// ============================================================================
// 安全扫描与代码审计环境初始化
// ============================================================================

// buildSecurityConfig converts the startup configuration into the controller SecurityConfig.
func buildSecurityConfig(cfg config.StartupConfig) controller.SecurityConfig {
	timeout := time.Duration(cfg.LLMTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return controller.SecurityConfig{
		ScanEnabled:      cfg.EnableSecurityScan,
		ModelDir:         cfg.ModelDir,
		ResultCheck:      cfg.EnableResultCheck,
		DataDir:          cfg.DataDir,
		ResultDir:        cfg.ResultDir,
		MaxResultBytes:   cfg.MaxResultBytes,
		ModelInputDir:    cfg.ModelInputDir,
		ModelOutputDir:   cfg.ModelOutputDir,
		ModelLogDir:      cfg.ModelLogDir,
		ModelProgressDir: cfg.ModelProgressDir,
		LLM: codeaudit.LLMConfig{
			Enabled:                 cfg.EnableLLM,
			Transport:               cfg.LLMTransport,
			Endpoint:                cfg.LLMEndpoint,
			AttestationMode:         cfg.LLMAttestationMode,
			HRKCertPath:             cfg.LLMHRKCertPath,
			HSKCekCertPath:          cfg.LLMHSKCekCertPath,
			ExpectedMeasurements:    cfg.LLMExpectedMeasurements,
			RequireMutualAttest:     cfg.LLMRequireMutualAttest,
			InsecureSkipVerify:      cfg.LLMInsecureSkipVerify,
			AuthToken:               cfg.LLMAuthToken,
			Model:                   cfg.LLMModel,
			Timeout:                 timeout,
			MaxFindings:             20,
			Policy:                  cfg.LLMPolicy,
			FailClosed:              cfg.LLMFailClosed,
			AllowedHosts:            cfg.LLMAllowedHosts,
			CircuitBreakerThreshold: cfg.LLMCircuitBreakerThreshold,
			CooldownSec:             cfg.LLMCooldownSec,
		},
	}
}

// ensureSecurityDirectories 确保模型目录、数据目录、结果目录以及模型输入输出目录在本地文件系统中存在
func ensureSecurityDirectories(sec controller.SecurityConfig) error {
	for _, dir := range []string{
		sec.ModelDir,
		sec.DataDir,
		sec.ResultDir,
		sec.GetModelInputDir(),
		sec.GetModelOutputDir(),
		sec.GetModelLogDir(),
		sec.GetModelProgressDir(),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	return nil
}

// logSecurityConfig 打印安全扫描、大模型审计及结果检查策略的配置摘要
func logSecurityConfig(sec controller.SecurityConfig) {
	log.Printf("model staging directories: input=%s output=%s log=%s progress=%s", sec.GetModelInputDir(), sec.GetModelOutputDir(), sec.GetModelLogDir(), sec.GetModelProgressDir())
	if sec.ScanEnabled {
		log.Printf("security scan enabled: model-dir=%s", sec.ModelDir)
		if sec.LLM.Enabled {
			log.Printf("  LLM verifier enabled: model=%s transport=%s endpoint=%s attestMode=%s policy=%s fail-closed=%v",
				sec.LLM.Model, sec.LLM.Transport, sec.LLM.Endpoint, sec.LLM.AttestationMode, sec.LLM.Policy, sec.LLM.FailClosed)
		}
	}
	if sec.ResultCheck {
		log.Printf("result check enabled: data-dir=%s result-dir=%s max-bytes=%d", sec.DataDir, sec.ResultDir, sec.MaxResultBytes)
	}
}
