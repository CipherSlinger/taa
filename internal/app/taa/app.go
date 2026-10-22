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

	"github.com/CipherSlinger/teellm"

	"taa/internal/attestation"
	"taa/internal/codeaudit"
	"taa/internal/config"
	"taa/internal/controller"
	"taa/internal/fhe"
	"taa/internal/store"
	teecrypto "taa/pkg/crypto"
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

	// defaultKeysDir is the keys directory used when the configuration leaves it empty.
	defaultKeysDir = "/root/taa/keys"
)

// normalizeKeysDir applies the default keys directory and cleans the path.
func normalizeKeysDir(keysDir string) string {
	dir := strings.TrimSpace(keysDir)
	if dir == "" {
		dir = defaultKeysDir
	}
	return filepath.Clean(dir)
}

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
//  1. If LLM code audit is enabled, probe the external inference service (advisory)
//  2. Load or generate persistent SM2 key pair for this TAA instance
//  3. Derive 64-byte UserData and bind it to the TEE attestation report
//  4. Generate underlying TEE hardware remote attestation report
//  5. Register this TAA instance with the platform
//  6. Build security policy configuration and ensure directories are ready
//  7. Construct global controller state and start HTTP service, supporting graceful shutdown via ctx
func RunWithConfig(ctx context.Context, cfg config.StartupConfig) error {
	// 1. If LLM code audit is enabled, probe inference service readiness.
	//
	// The probe's verdict is advisory, even with failClosed set. It runs before the HTTP
	// service exists, and in the CSV2 initrd deployment it runs before the guest has a
	// network at all: the guest interface is configured by kata-agent, which the initrd
	// only execs after this process is up. Measured on 2026-10-10 in a booting test VM:
	// "dial tcp 172.16.10.116:8443: connect: network is unreachable". A fatal probe is
	// therefore unsatisfiable there by construction, and it fails in the worst way --
	// taa-init sees TAA die, refuses to hand the VM over to kata-agent (TAA_REQUIRED=1),
	// and the sandbox is never created.
	//
	// failClosed is still honoured where it is load-bearing: the pre-audit probe in the
	// controller runs with the network up and refuses the import when the gateway is
	// unreachable, so nothing is ever scanned without the LLM. The failure is not hidden
	// either -- probeInferenceService logs the endpoint, the elapsed time and a hint
	// about what the error means.
	if cfg.LLM.Enabled {
		if err := probeInferenceService(ctx, cfg); err != nil {
			log.Printf("WARNING: inference service probe failed (non-fatal): %v", err)
		}
	} else {
		// Log the skip explicitly: otherwise a startup log with no connectivity verdict is
		// ambiguous between "the gateway answered" and "no probe was ever attempted".
		log.Printf("LLM code audit disabled; skipping inference service connectivity probe")
	}

	// 2. 加载或恢复本 TAA 实例专用的国密 SM2 密钥对（优先从持久化目录加载，若不存在则生成并落盘）；
	//    CSV 环境下同时导出可经 TAASECRETKEY 带回的私钥密文
	keysDir := normalizeKeysDir(cfg.KeysDir)
	secretEnv := os.Getenv(taaSecretKeyEnv)
	material, err := resolveStartupKeyMaterial(
		keysDir, cfg.StateSealingKeySource, cfg.Contract,
		secretEnv, fetchCSVHardwareSealingKey)
	if err != nil {
		return fmt.Errorf("initialize TAA key material: %w", err)
	}
	defer clear(material.sealingKey)

	keyPair := material.keyPair
	if material.recovered {
		log.Printf("recovered TAA SM2 key pair from %s", taaSecretKeyEnv)
	} else if material.loaded {
		log.Printf("loaded persistent TAA SM2 key pair from %s", keysDir)
	} else {
		log.Printf("generated and saved persistent TAA SM2 key pair to %s", keysDir)
	}
	if material.taaSecretKey != "" {
		log.Printf("derived taaSecretKey for platform registration (%d hex chars)", len(material.taaSecretKey))
	}

	// The sealing key source and the sealed state store
	sealingKey := material.sealingKey
	keySource := material.keySource
	log.Printf("state sealing key source: %s fingerprint: %s", keySource, sealingKeyFingerprint(sealingKey))

	statePath := filepath.Join(keysDir, "state.sealed")
	stateStore, err := store.NewStateStore(statePath, sealingKey, keySource)
	if err != nil {
		return fmt.Errorf("initialize state store: %w", err)
	}
	// isNewKey describes the SM2 key pair only; it has nothing to do with the
	// hardware key, so a csv-hw store must never be told the key is new. A key
	// recovered from TAASECRETKEY is not new either, and recovery requires
	// csv-hw, so the source check already excludes it.
	keyIsNew := !material.loaded && keySource == store.KeySourceSM2
	drifted, err := stateStore.DetectAndHandleKeyDrift(keyIsNew)
	if err != nil {
		return fmt.Errorf("detect and handle key drift (fail-closed): %w", err)
	}
	if drifted {
		log.Printf("WARNING: prior sealed state was archived as %s/.orphaned.<unix> and a clean state was initialized", keysDir)
	}

	platformIP := cfg.PlatformIP
	dockerID := cfg.DockerID
	timestamp := time.Now().Unix()

	// 3. 将 SM2 公钥坐标 (X||Y) 填充为 64 字节 UserData，供 TEE 硬件报告度量签名
	userData, err := deriveUserData(&keyPair.PrivateKey.PublicKey)
	if err != nil {
		return err
	}
	logUserDataSummary(userData)

	// 4. Generate attestation report containing UserData and perform certificate self-verification
	//
	// A server.type=fhe instance is not a TEE: it runs on a plain GPU host with no
	// /dev/csv-guest, so the report can only fail and fill the log with warnings.
	// The skip is explicit rather than inferred from that failure, and
	// verifiedPass stays false - the platform must not read "fhe" as "attested".
	//
	// The empty report file is still written, because registration reads that path
	// (platform.NoticeRegister stats and reads it, and refuses to register when it
	// is absent). Leaving it absent would turn every registration attempt on an fhe
	// instance into "attestation report file is not accessible" instead of the
	// empty-attestation registration the degraded TEE path already produces.
	verifiedPass := false
	if cfg.ServerType == config.ServerTypeFHE {
		log.Printf("[INFO] [attestation] instance type is fhe: remote attestation is not provided by this instance")
		if err := os.WriteFile(fixedAttestationFile, nil, 0o600); err != nil {
			return fmt.Errorf("write empty attestation report: %w", err)
		}
	} else {
		var err error
		verifiedPass, err = prepareAttestationReport(ctx, userData, cfg.AttestationHRKCertPath, cfg.AttestationHSKCekCertPath)
		if err != nil {
			return err
		}
	}

	// 5. 向管控平台注册本 TAA 实例，通知平台就绪并提交度量报告与公钥
	if err := registerPlatform(ctx, platformIP, dockerID, keyPair.PublicKeyPEM, timestamp, verifiedPass, material.taaSecretKey); err != nil {
		log.Printf("[WARN] [register] platform register failed, continuing startup: %v", err)
		// The first attempt is expected to fail in a Kata CSV2 guest: it runs before
		// the sandbox network exists (see register_retry.go). Keep trying in the
		// background so the platform still learns about this instance, and keep using
		// the boot-time timestamp so the payload stays consistent with the report
		// attached to it (the platform's view of a registration is last-write-wins).
		go func() {
			err := retryRegister(ctx, registerRetryInitialDelay, registerRetryMaxDelay, registerRetryWindow,
				func(attemptCtx context.Context) error {
					return registerPlatform(attemptCtx, platformIP, dockerID, keyPair.PublicKeyPEM, timestamp, verifiedPass, material.taaSecretKey)
				})
			if err != nil {
				log.Printf("[WARN] [register] platform register retries gave up: %v", err)
			}
		}()
	} else {
		log.Printf("[INFO] [register] platform register completed")
	}
	logGeneratedTAAKeyPair(keyPair)

	// 6. 构建安全策略配置并确保模型/数据/结果目录已就绪
	sec, err := buildSecurityConfig(cfg)
	if err != nil {
		return err
	}
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

	fheRunner, err := buildFHERunner(cfg)
	if err != nil {
		return fmt.Errorf("build the FHE runner: %w", err)
	}
	if fheRunner != nil {
		state.SetFHERunner(fheRunner)
		// The runner needs a logger, and TAAState owns the log store, so the
		// adapter is installed after the state exists.
		fheRunner.SetLogger(func(level fhe.Level, scope, format string, args ...any) {
			switch level {
			case fhe.LevelWarn:
				state.Logs.Add(controller.LogWarn, scope, format, args...)
			case fhe.LevelError:
				state.Logs.Add(controller.LogError, scope, format, args...)
			default:
				state.Logs.Add(controller.LogInfo, scope, format, args...)
			}
		})
		log.Printf("instance type: fhe (endpoint=%s, dataDir=%s)", cfg.FHE.Endpoint, cfg.FHE.DataDir)
	} else {
		log.Printf("instance type: tee")
	}

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
		// An audit outlives the import task that started it, so its crash leaves no
		// activeTask behind for the block above to find. The pending value comes from
		// the restored state rather than from pState, so a model_import crash that
		// reconcileCrashRecovery just rolled back is not reconciled twice.
		if err := reconcileAbandonedAudit(ctx, state, state.PendingAudit()); err != nil {
			log.Printf("WARNING: reconcile abandoned audit failed: %v", err)
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

	// A zero request timeout means "no deadline", not "give up quickly": the
	// probe must then wait out the health check's own budget, which is what a
	// cold, model-loading gateway needs.
	timeout := time.Duration(cfg.LLM.TimeoutMs) * time.Millisecond
	probeTimeout := teellm.DefaultHealthCheckTimeout
	if cfg.LLM.TimeoutMs > 0 {
		probeTimeout = timeout
	}

	// Announce the probe before building the client, so that even a configuration failure
	// (bad endpoint, host outside AllowedHosts) is preceded by the endpoint it was aimed at.
	log.Printf("inference service connectivity probe: endpoint=%s attestationEnabled=%v measurement=%s mutualAttest=%v timeout=%s",
		cfg.LLM.Endpoint, cfg.LLM.AttestationEnabled, cfg.LLM.AttestationMeasurement, cfg.LLM.RequireMutualAttest, probeTimeout)

	// Reuse the audit's client construction so the probe cannot diverge from the
	// transport the audit actually uses.
	client, err := codeaudit.NewInferenceClient(codeaudit.LLMConfig{
		Endpoint:                cfg.LLM.Endpoint,
		Timeout:                 timeout,
		AttestationEnabled:      cfg.LLM.AttestationEnabled,
		AttestationMeasurement:  cfg.LLM.AttestationMeasurement,
		InsecureSkipVerify:      cfg.LLM.InsecureSkipVerify,
		RequireMutualAttest:     cfg.LLM.RequireMutualAttest,
		HRKCertPath:             cfg.LLM.HRKCertPath,
		HSKCekCertPath:          cfg.LLM.HSKCekCertPath,
		AllowedHosts:            cfg.LLM.AllowedHosts,
		CircuitBreakerThreshold: cfg.LLM.CircuitBreakerThreshold,
		CooldownSec:             cfg.LLM.CooldownSec,
	})
	if err != nil {
		return fmt.Errorf("create inference client: %w", err)
	}
	defer client.Close()

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	// The verdict carries its wall-clock cost: the probe is a full TEE-TLS handshake plus
	// /healthz, and /healthz answers only once the backend model has loaded, so a slow gateway
	// is expected on a cold start. Without the timing, "gateway is cold" and "gateway is
	// unreachable" produce lookalike failures.
	started := time.Now()
	if err := client.HealthCheck(probeCtx); err != nil {
		elapsed := time.Since(started).Round(time.Millisecond)
		// Stated here as well as at the call site because with fail-closed this is the last
		// line this process logs before exiting, and the caller's line does not carry the hint.
		log.Printf("ERROR: inference service connectivity probe failed after %s: %v", elapsed, err)
		log.Printf("hint: check the tee-llm gateway at %s -- \"transient status 503\" means it is "+
			"running but its model is not loaded yet, a dial/connect error means nothing is listening there",
			cfg.LLM.Endpoint)
		return fmt.Errorf("health check failed: %w", err)
	}
	log.Printf("inference service connectivity probe succeeded (took %s)", time.Since(started).Round(time.Millisecond))
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

// ensureKeyPermissions tightens an existing private key file and its directory
// before the key is loaded. A key readable by the group or others that cannot
// be closed down aborts startup; a directory that cannot be tightened only warns.
func ensureKeyPermissions(privPath, dir string) error {
	privStat, err := os.Stat(privPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat private key file %s: %w", privPath, err)
	}
	if privStat.Mode().Perm() != 0o600 {
		if err := os.Chmod(privPath, 0o600); err != nil {
			if privStat.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("insecure private key permissions (%o) on %s and failed to tighten: %w", privStat.Mode().Perm(), privPath, err)
			}
			log.Printf("WARNING: failed to tighten private key permissions on %s from %o to 0600: %v", privPath, privStat.Mode().Perm(), err)
		}
	}

	dirStat, err := os.Stat(dir)
	if err == nil && dirStat.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			if dirStat.Mode().Perm()&0o077 != 0 {
				log.Printf("WARNING: insecure keys directory permissions (%o) on %s and failed to tighten: %v", dirStat.Mode().Perm(), dir, err)
			}
		}
	}
	return nil
}

// loadOrGenerateTAAKeyPair 优先从 keysDir 目录检查并加载已有的国密 SM2 公私钥对；
// 若密钥不存在，则生成新的 SM2 密钥对并以安全权限持久化落盘（私钥 0600，公钥 0644）；
// 若检测到公私钥不匹配或非预期的单边损坏，采用 Fail-Closed 严格报错以避免覆盖损坏历史解密凭证；
// 若仅公钥缺失而私钥完整，则通过私钥自愈派生公钥并补齐落盘。
// 返回的 loaded 表示是否从现有文件中成功加载。
func loadOrGenerateTAAKeyPair(keysDir string) (*taaKeyPair, bool, error) {
	cleanDir := normalizeKeysDir(keysDir)

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
		if err := ensureKeyPermissions(privPath, cleanDir); err != nil {
			return nil, false, err
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

// logUserDataSummary 打印 UserData 摘要日志
func logUserDataSummary(userData []byte) {
	log.Printf("generated userdata: taa SM2 public key raw X||Y")
	log.Printf("  userdata (64 bytes hex): %x", userData)
}

// ============================================================================
// TEE 远程证明报告与管控平台注册
// ============================================================================

// prepareAttestationReport invokes underlying TEE tools to generate attestation report and performs certificate self-verification.
// In non-TEE environments or upon generation failure, writes an empty report and logs a warning, allowing service to start in degraded mode (verifiedPass=false).
func prepareAttestationReport(ctx context.Context, userData []byte, hrkCertPath, hskCekCertPath string) (bool, error) {
	log.Printf("[INFO] [attestation] generating attestation report: output=%s", fixedAttestationFile)
	if err := attestation.Generate(ctx, attestation.Config{
		OutputPath: fixedAttestationFile,
		UserData:   userData,
	}); err != nil {
		log.Printf("[WARN] [attestation] generating attestation report failed, continuing with empty report: %v", err)
		if writeErr := os.WriteFile(fixedAttestationFile, nil, 0o600); writeErr != nil {
			return false, fmt.Errorf("write empty attestation report: %w", writeErr)
		}
		return false, nil
	}

	reportBytes, err := os.ReadFile(fixedAttestationFile)
	if err != nil {
		log.Printf("[WARN] [attestation] failed to read attestation report %s: %v", fixedAttestationFile, err)
		return false, nil
	}
	if len(reportBytes) == 0 {
		return false, nil
	}

	if _, verifyErr := attestation.VerifyReport(reportBytes, hrkCertPath, hskCekCertPath); verifyErr != nil {
		log.Printf("[WARN] [attestation] attestation self-verification failed: %v", verifyErr)
		return false, nil
	}

	log.Printf("[INFO] [attestation] attestation report verified successfully: %s", fixedAttestationFile)
	return true, nil
}

// registerPlatform sends a registration request to the platform, reporting DockerID, attestation report, TAA public key, timestamp, self-verification status and, when available, the wrapped TAA private key.
func registerPlatform(ctx context.Context, platformIP, dockerID, publicKeyPEM string, timestamp int64, verifiedPass bool, taaSecretKey string) error {
	log.Printf("[INFO] [register] notifying platform register: platform=%s dockerId=%s attestation=%s timestamp=%d verifiedPass=%v",
		platformIP, dockerID, fixedAttestationFile, timestamp, verifiedPass)
	return controller.NoticeRegister(ctx, platformIP, dockerID, fixedAttestationFile, publicKeyPEM, timestamp, verifiedPass, taaSecretKey)
}

// ============================================================================
// 安全扫描与代码审计环境初始化
// ============================================================================

// buildSecurityConfig converts the startup configuration into the controller SecurityConfig.
//
// It returns an error because the Tier 1 engine is resolved here, at startup,
// rather than on the import path. The configuration layer has already rejected
// an unknown engine name; this resolves the name into the engine itself, so a
// selection that cannot be honoured (a name the selector does not know, or a
// Semgrep rules file that is not there) stops the process instead of silently
// scanning with the wrong engine or blocking every import with a scan failure.
func buildSecurityConfig(cfg config.StartupConfig) (controller.SecurityConfig, error) {
	engine, err := codeaudit.NewEngine(codeaudit.EngineConfig{
		Name:             cfg.CodeScan.Engine,
		SemgrepRulesPath: cfg.CodeScan.RulesPath,
		SemgrepTimeout:   cfg.CodeScan.Timeout,
	})
	if err != nil {
		return controller.SecurityConfig{}, fmt.Errorf("resolve code scan engine: %w", err)
	}

	timeout := time.Duration(cfg.LLM.TimeoutMs) * time.Millisecond
	// The audit is reproducible only while the inference service decodes
	// deterministically, which it does unless a temperature is sent. Warn rather
	// than reject: a non-zero temperature is a deliberate choice, but its symptom
	// - a benign import blocked by one unlucky MALICIOUS verdict - appears
	// elsewhere and long afterwards, so the cause belongs in the startup log.
	if cfg.LLM.Temperature != nil && *cfg.LLM.Temperature != 0 {
		log.Printf("WARNING: llm.temperature=%v overrides the inference service's deterministic decoding; "+
			"identical findings may now yield different verdicts, which fail-closed can turn into a blocked import",
			*cfg.LLM.Temperature)
	}
	return controller.SecurityConfig{
		ScanEnabled: cfg.EnableCodeAudit,
		Engine:      engine,
		Binary: codeaudit.BinaryConfig{
			Enabled:              cfg.BinaryAuditEnabled,
			MaxArchiveMembers:    cfg.BinaryAuditMaxArchiveMembers,
			MaxFindings:          cfg.BinaryAuditMaxFindings,
			MaxFullScanBytes:     int64(cfg.BinaryAuditMaxFullScanBytes),
			MaxStreamBytes:       int64(cfg.BinaryAuditMaxStreamBytes),
			HighEntropyThreshold: cfg.BinaryAuditHighEntropyThreshold,
		},
		ModelDir:         cfg.ModelDir,
		ResultCheck:      cfg.EnableResultCheck,
		DataDir:          cfg.DataDir,
		ResultDir:        cfg.ResultDir,
		ModelInputDir:    cfg.ModelInputDir,
		ModelOutputDir:   cfg.ModelOutputDir,
		ModelLogDir:      cfg.ModelLogDir,
		ModelProgressDir: cfg.ModelProgressDir,
		ServerType:       cfg.ServerType,
		LLM: codeaudit.LLMConfig{
			Enabled:                cfg.LLM.Enabled,
			AttestationEnabled:     cfg.LLM.AttestationEnabled,
			Endpoint:               cfg.LLM.Endpoint,
			AttestationMeasurement: cfg.LLM.AttestationMeasurement,
			HRKCertPath:            cfg.LLM.HRKCertPath,
			HSKCekCertPath:         cfg.LLM.HSKCekCertPath,
			RequireMutualAttest:    cfg.LLM.RequireMutualAttest,
			InsecureSkipVerify:     cfg.LLM.InsecureSkipVerify,
			AuthToken:              cfg.LLM.AuthToken,
			Model:                  cfg.LLM.Model,
			Timeout:                timeout,
			// 0 means no cap: every finding the static scanner reports gets a verdict.
			// The old value of 20 left the tail of a large scan reported but never
			// adjudicated. The scanner's own cap (ScannerConfig.MaxFindings, 200) is
			// the real ceiling on how many calls this can produce.
			MaxFindings:             0,
			Temperature:             cfg.LLM.Temperature,
			FailClosed:              cfg.LLM.FailClosed,
			AllowedHosts:            cfg.LLM.AllowedHosts,
			CircuitBreakerThreshold: cfg.LLM.CircuitBreakerThreshold,
			CooldownSec:             cfg.LLM.CooldownSec,
		},
	}, nil
}

// buildFHERunner returns the FHE runner for this instance, or nil when the
// instance is a tee. The runner is the only thing that talks to the FHE service,
// so nil here means every FHE code path stays unreachable.
func buildFHERunner(cfg config.StartupConfig) (*fhe.Runner, error) {
	if cfg.ServerType != config.ServerTypeFHE {
		return nil, nil
	}
	if cfg.FHE == nil {
		return nil, fmt.Errorf("server.type is %q but the startup config has no fhe section", config.ServerTypeFHE)
	}
	f := *cfg.FHE
	activate := true
	if f.ActivateModelOnImport != nil {
		activate = *f.ActivateModelOnImport
	}
	// The callback address is always loopback: TAA and the FHE service share the
	// host's network namespace, and the port is the socket this instance listens
	// on.
	callbackBaseURL, err := config.DeriveFHECallbackBaseURL(cfg.Addr)
	if err != nil {
		return nil, err
	}
	return fhe.New(fhe.Config{
		Endpoint:              f.Endpoint,
		DataDir:               f.DataDir,
		KeyCacheDir:           f.KeyCacheDir,
		CallbackBaseURL:       callbackBaseURL,
		PollInterval:          time.Duration(f.PollIntervalMs) * time.Millisecond,
		RequestTimeout:        time.Duration(f.RequestTimeoutMs) * time.Millisecond,
		ActivateModelOnImport: activate,
	}, nil)
}

// ensureSecurityDirectories 确保模型目录、数据目录、结果目录以及模型输入输出目录在本地文件系统中存在
func ensureSecurityDirectories(sec controller.SecurityConfig) error {
	dirs := []string{
		sec.ModelDir,
		sec.DataDir,
		sec.ResultDir,
		sec.GetModelInputDir(),
		sec.GetModelOutputDir(),
	}
	for _, p := range []string{sec.GetModelLogDir(), sec.GetModelProgressDir()} {
		dir := p
		if filepath.Ext(p) != "" {
			dir = filepath.Dir(p)
		}
		dirs = append(dirs, dir)
	}
	for _, dir := range dirs {
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
			log.Printf("  LLM verifier enabled: model=%s attestation-enabled=%v endpoint=%s measurement=%s fail-closed=%v",
				sec.LLM.Model, sec.LLM.AttestationEnabled, sec.LLM.Endpoint, sec.LLM.AttestationMeasurement, sec.LLM.FailClosed)
		}
	}
	if sec.ResultCheck {
		log.Printf("result check enabled: data-dir=%s result-dir=%s", sec.DataDir, sec.ResultDir)
	}
}
