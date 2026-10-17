package config

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	DefaultFileName       = "taa-config.json"
	DefaultMaxFileBytes   = 3 * 1024 * 1024 * 1024 // 3 GB
	DefaultMaxResultBytes = DefaultMaxFileBytes
)

type StartupConfig struct {
	Addr       string
	PlatformIP string
	DockerID   string
	Contract   string
	// ServerType is "tee" (the default) or "fhe", from server.type.
	ServerType string
	// FHE is non-nil only on a server.type=fhe instance.
	FHE *FHEConfig
	// EnableCodeAudit gates the whole code audit: the static scan and, with it,
	// the LLM arbitration that only ever runs on what the scan raised. Turning it
	// off is the audit's kill switch, not a per-channel toggle; the channels
	// themselves are switched by CodeScan and BinaryAuditEnabled.
	EnableCodeAudit bool
	// CodeScan is the Tier 1 static scan: which engine runs, where its rules come
	// from, and how long one scan may take.
	CodeScan CodeScanConfig
	// BinaryAuditEnabled turns the binary channel on for model import audits. It
	// defaults to true; turning it off is the rollback of this feature and leaves
	// an audit byte-identical to the one produced before the channel existed.
	BinaryAuditEnabled bool
	// BinaryAuditMaxArchiveMembers bounds how many members of a container are
	// examined. Zero means the codeaudit default.
	BinaryAuditMaxArchiveMembers int
	// BinaryAuditHighEntropyThreshold is the bits-per-byte above which an
	// executable section is called packed. Zero means the codeaudit default
	// (7.5).
	//
	// The whole of [0,8] is accepted, and neither end is neutral. At 8.0 nothing
	// is ever called packed, because Shannon entropy cannot exceed 8, so the
	// family goes quiet on this deployment. Lower down, a threshold that lands
	// inside the band compiled code already occupies (roughly 6.0-6.5) starts
	// calling ordinary shared objects packed - and BIN_001 is HIGH, so those
	// imports are refused under both policies. The default is 7.5, clear of the
	// band.
	BinaryAuditHighEntropyThreshold float64
	// BinaryAuditMaxFindings is the listing budget for the binary pass, not a
	// completeness bound: reaching it drops LOW findings (and only LOW - HIGH and
	// MEDIUM can block the import and are always kept) and is recorded as
	// findings_capped, and it never withholds a pass. Zero means the codeaudit
	// default.
	BinaryAuditMaxFindings int
	// BinaryAuditMaxFullScanBytes is the size above which a file is read at its
	// two ends instead of end to end. Zero means the codeaudit default. It is
	// exposed rather than fixed because it is the one limit whose right value
	// depends on the deployment's package sizes: raising it buys a complete pass
	// over a large pickle at a cost of about 3 microseconds per kibibyte.
	//
	// Lowering it costs completeness only for a file longer than the two windows
	// together (2 MiB): a file at or below that is covered end to end by the
	// windows, so no bound is recorded and nothing is refused, while a longer one
	// still has its middle unread - still recorded, and still a refusal on an
	// executable kind. On the windowed route the pickle interpreter, which is
	// gated to the head window, stops seeing the middle.
	BinaryAuditMaxFullScanBytes int
	// BinaryAuditMaxStreamBytes bounds how much of one file the end-to-end
	// streaming pass reads. Zero means the codeaudit default (3 GiB).
	//
	// It is exposed because it is the twin of MaxFullScanBytes: the stream budget
	// is only reachable by a file that MaxFullScanBytes let through, so an
	// operator who raises MaxFullScanBytes past the stream ceiling makes the
	// stream ceiling bind - and its breach records a structural bound, which on
	// an executable kind blocks the import. Leaving it fixed while its twin is
	// exposed would turn that into an unactionable block.
	//
	// The pairing is a constraint on the operator, not on the loader: nothing
	// checks the two against each other, and a value below MaxFullScanBytes is
	// accepted without complaint. Keep it at or above MaxFullScanBytes, and above
	// anything the deployment imports, or every file in the gap between the two
	// records a bound and an executable one refuses the import.
	BinaryAuditMaxStreamBytes int
	ModelDir                  string
	EnableResultCheck         bool
	MaxFileBytes              int64
	MaxResultBytes            int64
	DataDir                   string
	ResultDir                 string
	ModelInputDir             string
	ModelOutputDir            string
	ModelLogDir               string
	ModelProgressDir          string
	KeysDir                   string
	// StateSealingKeySource selects where the persistent state sealing key
	// comes from: "sm2" (derived from the SM2 private scalar) or "csv-hw"
	// (Hygon CSV hardware key via /dev/csv-guest). See
	// storage.stateSealingKeySource.
	StateSealingKeySource     string
	AttestationHRKCertPath    string
	AttestationHSKCekCertPath string
	// LLM bundles the inference service the audit arbitrates findings with. It is
	// nested because every one of these settings exists for the code audit and
	// nothing else: TAA has no other use for a model.
	LLM LLMConfig
}

// LLMConfig is the inference service the code audit calls to adjudicate the
// findings its static scan raised. Field names carry no "LLM" prefix - the type
// already says it.
type LLMConfig struct {
	Enabled                 bool
	Transport               string
	Endpoint                string
	AttestationMode         string
	HRKCertPath             string
	HSKCekCertPath          string
	ExpectedMeasurements    []string
	RequireMutualAttest     bool
	InsecureSkipVerify      bool
	AuthToken               string
	TimeoutMs               int64
	AllowedHosts            []string
	CircuitBreakerThreshold int
	CooldownSec             int
	Model                   string
	Policy                  string
	FailClosed              bool
	Dir                     string

	// Temperature overrides the sampling temperature the audit requests
	// from the inference service. nil means "not configured": the service
	// applies its own default, which is 0 (deterministic decoding). A non-nil
	// value is sent as-is and re-enables sampling, so identical findings may
	// then yield different verdicts.
	Temperature *float32
}

// CodeScanConfig is the Tier 1 static scan. Field names carry no "codeScan"
// prefix - the type already says it.
type CodeScanConfig struct {
	// Engine selects the Tier 1 static engine ("regex" or "semgrep"). The
	// default is "semgrep" (see defaultStartupConfig); "regex" is the baseline
	// an operator falls back to deliberately.
	Engine string
	// RulesPath is the rules file or directory for the semgrep engine, passed
	// through as --config. Empty means the engine's own default, which is
	// relative to the repository root and therefore useless in a container: a
	// deployment that selects semgrep is expected to set this.
	RulesPath string
	// Timeout bounds one semgrep scan. It is not a scan budget but a safety net:
	// an import waits on this scan, and the adapter turns an expired deadline
	// into a failed scan, which the audit fails closed on. Zero means the
	// adapter's own default (codeaudit.DefaultSemgrepTimeout), which is where the
	// enforced number lives; a negative value is rejected at load time.
	Timeout time.Duration
}

// Server instance roles, selected by the server.type config key.
const (
	// ServerTypeTEE is the CSV guest that audits models and attests to the
	// platform. It is the default, so every existing config keeps its behaviour.
	ServerTypeTEE = "tee"
	// ServerTypeFHE orchestrates the FHE service on a GPU host. Such an instance
	// is not a TEE, does not attest, and runs no training pipeline.
	ServerTypeFHE = "fhe"
)

// State sealing key sources, selected by storage.stateSealingKeySource.
const (
	// StateSealingKeySourceSM2 derives the key from the SM2 private scalar.
	StateSealingKeySourceSM2 = "sm2"
	// StateSealingKeySourceCSVHW reads the key from the Hygon CSV hardware
	// through /dev/csv-guest. It is required to be available: there is no
	// fallback to the SM2 derivation.
	StateSealingKeySourceCSVHW = "csv-hw"
)

var stateSealingKeySources = []string{StateSealingKeySourceSM2, StateSealingKeySourceCSVHW}

// FHE section defaults. maxEvalKeyBytes is deliberately independent of
// codeAudit.resultCheck.maxFileBytes: a measured eval_context.bin is
// 3,329,929,205 B and the result-check cap defaults to 3 GiB, which is 103.7 MiB
// too small to download a real key.
const (
	DefaultFHEMaxEvalKeyBytes  = int64(6) << 30 // 6442450944
	DefaultFHEPollIntervalMs   = 5000
	DefaultFHERequestTimeoutMs = 30000
	DefaultFHETaskTimeoutMs    = 1800000
)

// FHEConfig is the parsed fhe section. It is only consulted when
// server.type=fhe.
type FHEConfig struct {
	Endpoint         string `json:"endpoint"`
	DataDir          string `json:"dataDir"`
	KeyCacheDir      string `json:"keyCacheDir"`
	CallbackBaseURL  string `json:"callbackBaseUrl"`
	CallbackToken    string `json:"callbackToken"`
	MaxEvalKeyBytes  int64  `json:"maxEvalKeyBytes"`
	PollIntervalMs   int    `json:"pollIntervalMs"`
	RequestTimeoutMs int    `json:"requestTimeoutMs"`
	TaskTimeoutMs    int    `json:"taskTimeoutMs"`
	// ActivateModelOnImport is a pointer because "absent" and "explicitly false"
	// must not collapse: the field defaults to true, so an absent one read as
	// false would turn a missing setting into a deliberate opt-out.
	ActivateModelOnImport *bool `json:"activateModelOnImport"`
}

type startupConfigFile struct {
	Server      startupServerConfigFile      `json:"server"`
	Platform    startupPlatformConfigFile    `json:"platform"`
	Storage     startupStorageConfigFile     `json:"storage"`
	Model       startupModelConfigFile       `json:"model"`
	CodeAudit   startupCodeAuditConfigFile   `json:"codeAudit"`
	Attestation startupAttestationConfigFile `json:"attestation"`
	// FHE is a pointer because "absent" and "present but empty" must be
	// distinguishable: a type=fhe instance with no section at all is a different
	// mistake from one with an empty callbackToken, and both are startup errors.
	FHE *FHEConfig `json:"fhe"`

	// Removed keys. These are declared for one reason only: to make their
	// presence detectable. encoding/json drops a key it does not recognise
	// without a trace, so a config still written against the old layout would
	// load cleanly with every audit setting at its default - the scan silently
	// back on the regex baseline, the inference service back on 127.0.0.1:8443 -
	// and nothing in the log would say so. See rejectRemovedKeys.
	RemovedSecurity json.RawMessage `json:"security"`
	RemovedLLM      json.RawMessage `json:"llm"`

	// Legacy flat fields for backward compatibility
	Addr               string `json:"addr"`
	PlatformIP         string `json:"platformIP"`
	DockerID           string `json:"dockerID"`
	Contract           string `json:"contract"`
	EnableSecurityScan *bool  `json:"securityScan"`
	ModelDir           string `json:"modelDir"`
	EnableResultCheck  *bool  `json:"resultCheck"`
	MaxFileBytes       *int64 `json:"maxFileBytes"`
	MaxResultBytes     *int64 `json:"maxResultBytes"`
	DataDir            string `json:"dataDir"`
	ResultDir          string `json:"resultDir"`
	ModelInputDir      string `json:"modelInputDir"`
	ModelOutputDir     string `json:"modelOutputDir"`
	ModelLogDir        string `json:"modelLogDir"`
	ModelProgressDir   string `json:"modelProgressDir"`
	KeysDir            string `json:"keysDir"`
}

type startupServerConfigFile struct {
	Addr string `json:"addr"`
	Type string `json:"type"`
}

type startupPlatformConfigFile struct {
	IP       string `json:"ip"`
	Endpoint string `json:"endpoint"`
	DockerID string `json:"dockerID"`
	Contract string `json:"contract"`
}

type startupStorageConfigFile struct {
	Model                 string `json:"model"`
	Data                  string `json:"data"`
	Result                string `json:"result"`
	Keys                  string `json:"keys"`
	StateSealingKeySource string `json:"stateSealingKeySource"`
	ModelDir              string `json:"modelDir"`
	DataDir               string `json:"dataDir"`
	ResultDir             string `json:"resultDir"`
	KeysDir               string `json:"keysDir"`
}

// startupCodeAuditConfigFile is the codeAudit block: everything the audit needs,
// including the limits of the result-leakage check and the inference service it
// arbitrates with.
type startupCodeAuditConfigFile struct {
	Enabled *bool `json:"enabled"`
	// Scan is the second accepted spelling of the same switch; when a config
	// writes both, this one is applied first and Enabled wins.
	Scan         *bool                        `json:"scan"`
	CodeScan     startupCodeScanConfigFile    `json:"codeScan"`
	BinaryAudit  startupBinaryAuditConfigFile `json:"binaryAudit"`
	ResultCheck  startupResultCheckConfigFile `json:"resultCheck"`
	MaxFileBytes *int64                       `json:"maxFileBytes"`
	LLM          startupLLMConfigFile         `json:"llm"`

	// Removed keys, declared only so their presence is detectable. See
	// rejectRemovedKeys.
	RemovedCodeScanEngine   json.RawMessage `json:"codeScanEngine"`
	RemovedSemgrepRulesPath json.RawMessage `json:"semgrepRulesPath"`
	RemovedSemgrepTimeout   json.RawMessage `json:"semgrepTimeoutSeconds"`
}

// startupCodeScanConfigFile is the codeAudit.codeScan block.
type startupCodeScanConfigFile struct {
	Engine    string `json:"engine"`
	RulesPath string `json:"rulesPath"`
	// TimeoutSeconds is a whole-scan deadline in seconds. Absent or zero means
	// the adapter's default; zero is not read as "no deadline", because an
	// unbounded scan is a hung import rather than a faster one.
	TimeoutSeconds int `json:"timeoutSeconds"`
}

// UnmarshalJSON turns the one shape this key used to have into a message naming
// the fix. Before the split codeScan was the on/off switch itself, so a config
// written against that layout says "codeScan": true - which would otherwise
// surface as "cannot unmarshal bool into Go struct field", a type error whose
// cause is not visible in the message.
func (s *startupCodeScanConfigFile) UnmarshalJSON(data []byte) error {
	if trimmed := strings.TrimSpace(string(data)); trimmed == "null" {
		return nil
	}
	var asBool bool
	if err := json.Unmarshal(data, &asBool); err == nil {
		return fmt.Errorf("codeAudit.codeScan is now a block: the on/off switch moved to " +
			"codeAudit.enabled, and this key holds codeAudit.codeScan.engine, " +
			"codeAudit.codeScan.rulesPath and codeAudit.codeScan.timeoutSeconds")
	}
	type rawCodeScan startupCodeScanConfigFile
	var raw rawCodeScan
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = startupCodeScanConfigFile(raw)
	return nil
}

// startupBinaryAuditConfigFile is the codeAudit.binaryAudit block.
//
// Enabled is a pointer because "absent" and "false" must not collapse: the
// channel defaults on, so an absent field read as false would turn silence into
// a rollback. The limits are pointers for symmetry with it, and the symmetry
// buys nothing on purpose - no layer reads the pointer, so an absent limit and
// an explicit zero are identical by design: validateBinaryAudit rejects only a
// negative, and a zero then resolves to the codeaudit default through
// normalizeBinaryConfig exactly as an absent field does.
type startupBinaryAuditConfigFile struct {
	Enabled              *bool    `json:"enabled"`
	MaxArchiveMembers    *int     `json:"maxArchiveMembers"`
	HighEntropyThreshold *float64 `json:"highEntropyThreshold"`
	MaxFindings          *int     `json:"maxFindings"`
	MaxFullScanBytes     *int64   `json:"maxFullScanBytes"`
	MaxStreamBytes       *int64   `json:"maxStreamBytes"`
}

type startupResultCheckConfigFile struct {
	Enabled      *bool  `json:"enabled"`
	MaxFileBytes *int64 `json:"maxFileBytes"`
}

func (r *startupResultCheckConfigFile) UnmarshalJSON(data []byte) error {
	var asBool bool
	if err := json.Unmarshal(data, &asBool); err == nil {
		r.Enabled = &asBool
		return nil
	}
	type rawResultCheck startupResultCheckConfigFile
	var raw rawResultCheck
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = startupResultCheckConfigFile(raw)
	return nil
}

type startupModelConfigFile struct {
	Dir    string                       `json:"dir"`
	Input  string                       `json:"input"`
	Output startupModelOutputConfigFile `json:"output"`
}

type startupModelOutputConfigFile struct {
	Result   string `json:"result"`
	Log      string `json:"log"`
	Progress string `json:"progress"`
}

type startupAttestationConfigFile struct {
	HRKCertPath    string `json:"hrkCertPath"`
	HSKCekCertPath string `json:"hskCekCertPath"`
}

type startupLLMConfigFile struct {
	Enabled                 *bool    `json:"enabled"`
	Transport               string   `json:"transport"`
	Endpoint                string   `json:"endpoint"`
	AttestationMode         string   `json:"attestationMode"`
	HRKCertPath             string   `json:"hrkCertPath"`
	HSKCekCertPath          string   `json:"hskCekCertPath"`
	ExpectedMeasurements    []string `json:"expectedMeasurements"`
	RequireMutualAttest     *bool    `json:"requireMutualAttest"`
	InsecureSkipVerify      *bool    `json:"insecureSkipVerify"`
	AuthToken               string   `json:"authToken"`
	RequestTimeoutMs        int64    `json:"requestTimeoutMs"`
	AllowedHosts            []string `json:"allowedHosts"`
	CircuitBreakerThreshold int      `json:"circuitBreakerThreshold"`
	CooldownSec             int      `json:"cooldownSec"`
	Model                   string   `json:"model"`
	Policy                  string   `json:"policy"`
	Temperature             *float32 `json:"temperature"`
	FailClosed              *bool    `json:"failClosed"`
	Dir                     string   `json:"dir"`
}

func LoadStartupConfig(path string) (StartupConfig, error) {
	cfg := defaultStartupConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		return StartupConfig{}, fmt.Errorf("read startup config %s: %w", path, err)
	}

	var fileCfg startupConfigFile
	if err := json.Unmarshal(data, &fileCfg); err != nil {
		return StartupConfig{}, fmt.Errorf("parse startup config %s: %w", path, err)
	}
	if err := rejectRemovedKeys(path, fileCfg); err != nil {
		return StartupConfig{}, err
	}

	applyStartupConfigFile(&cfg, fileCfg)
	applyLLMEndpointOverride(&cfg)
	applyFHEIdentityOverride(&cfg)
	if err := validateStartupConfig(cfg); err != nil {
		return StartupConfig{}, err
	}
	return cfg, nil
}

// applyLLMEndpointOverride lets the deployment environment point TAA at a
// TEE-LLM instance that does not live at the address baked into the image,
// without rebuilding the image.
//
// This is deliberately the opposite precedence from PlatformIP, DockerID and
// Contract: those are seeded in defaultStartupConfig and the config file wins
// over them, because the packaged config simply omits the platform block and
// the environment value is what is left. The LLM endpoint is written into
// every shipped template, so an environment value that could not override it
// would never take effect.
//
// applyFHEIdentityOverride is the one exception to that rule, and only for
// server.type=fhe.
func applyLLMEndpointOverride(cfg *StartupConfig) {
	endpoint := strings.TrimSpace(os.Getenv("TAA_LLM_ENDPOINT"))
	if endpoint == "" {
		return
	}
	cfg.LLM.Endpoint = endpoint
}

// applyFHEIdentityOverride lets the deployment environment point a type=fhe
// instance at the platform it registers with, and give it an identity there,
// without editing the config the image ships with.
//
// The fhe template does carry a platform block, so this is not the "file omits
// it and the environment is what is left" situation the other identity fields
// are in: it is an override, and the environment wins. The reason is that where
// a fhe instance registers is a property of where it was deployed, not of the
// build -- the same image goes to whichever GPU host is free, and the platform
// address on that host is not knowable when the template is written. A tee
// instance keeps the file-wins rule, because its platform address is part of
// the deployment it was packaged for.
//
// An unset or empty variable leaves the file's value in place, so the template
// stays a working default rather than a value the environment must always
// restate.
func applyFHEIdentityOverride(cfg *StartupConfig) {
	if cfg.ServerType != ServerTypeFHE {
		return
	}
	if ip := strings.TrimSpace(os.Getenv("PLATFORM_IP")); ip != "" {
		cfg.PlatformIP = ip
	}
	if dockerID := strings.TrimSpace(os.Getenv("DOCKER_ID")); dockerID != "" {
		cfg.DockerID = dockerID
	}
}

// rejectRemovedKeys fails the load when the config still uses a key that was
// renamed or moved.
//
// It fails rather than warns because the alternative is not "carry on as
// before": the old keys are no longer read, so the settings under them would be
// discarded and the audit would run on defaults. On the initrd path TAA is a
// boot gate, so a hard failure is also the honest signal - the operator sees a
// message naming the fix instead of a VM that boots with a changed audit.
//
// Every key is reported in one error when several are present, so a config that
// was written against an old layout is fixed in a single pass.
func rejectRemovedKeys(path string, fileCfg startupConfigFile) error {
	var found []string
	if hasJSONValue(fileCfg.RemovedSecurity) {
		found = append(found, `"security" (rename to "codeAudit")`)
	}
	if hasJSONValue(fileCfg.RemovedLLM) {
		found = append(found, `"llm" (move under "codeAudit.llm")`)
	}
	if hasJSONValue(fileCfg.CodeAudit.RemovedCodeScanEngine) {
		found = append(found, `"codeAudit.codeScanEngine" (move to "codeAudit.codeScan.engine")`)
	}
	if hasJSONValue(fileCfg.CodeAudit.RemovedSemgrepRulesPath) {
		found = append(found, `"codeAudit.semgrepRulesPath" (move to "codeAudit.codeScan.rulesPath")`)
	}
	if hasJSONValue(fileCfg.CodeAudit.RemovedSemgrepTimeout) {
		found = append(found, `"codeAudit.semgrepTimeoutSeconds" (move to "codeAudit.codeScan.timeoutSeconds")`)
	}
	if len(found) == 0 {
		return nil
	}
	return fmt.Errorf("startup config %s uses removed keys: %s", path, strings.Join(found, ", "))
}

// hasJSONValue reports whether a declared-but-unread key was actually present.
// An explicit null is treated as absent: it carries no settings, so rejecting it
// would fail a config that loses nothing by loading.
func hasJSONValue(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}

// llmPolicies lists the arbitration modes understood by the audit code
// (see codeaudit.LLMConfig.Policy). Any other value matches neither the gate
// nor the assist branch, silently degrading a blocking gate to assist
// behaviour, so it is rejected at load time instead.
var llmPolicies = []string{"assist", "gate"}

// staticEngines lists the Tier 1 engines understood by the audit code (see
// codeaudit.NewEngine). The list is repeated here rather than imported, because
// the config package deliberately does not depend on the audit package. An
// unrecognized name matches no branch in the engine selector, so it is rejected
// at load time instead of silently scanning with the regex baseline while the
// deployment believes otherwise.
var staticEngines = []string{"regex", "semgrep"}

func validateStartupConfig(cfg StartupConfig) error {
	if err := validateServerType(cfg); err != nil {
		return err
	}
	if err := validateStateSealingKeySource(cfg); err != nil {
		return err
	}
	if err := validateFHEConfig(cfg); err != nil {
		return err
	}
	if err := validateCodeScanEngine(cfg); err != nil {
		return err
	}
	if err := validateSemgrepTimeout(cfg); err != nil {
		return err
	}
	if err := validateLLMTemperature(cfg); err != nil {
		return err
	}
	if err := validateBinaryAudit(cfg); err != nil {
		return err
	}
	return validateLLMPolicy(cfg)
}

// serverTypes lists the instance roles understood by the startup config (see
// StartupConfig.ServerType). It is declared once so the membership test and the
// accepted-values message cannot drift apart when a role is added.
var serverTypes = []string{ServerTypeTEE, ServerTypeFHE}

// validateServerType rejects an unrecognised server.type rather than falling back
// to tee. A silent fallback would leave a deployment believing it runs one kind
// of instance while it runs the other.
func validateServerType(cfg StartupConfig) error {
	for _, t := range serverTypes {
		if cfg.ServerType == t {
			return nil
		}
	}
	return fmt.Errorf("unsupported server.type %q in startup config: must be one of %s",
		cfg.ServerType, strings.Join(serverTypes, ", "))
}

// validateStateSealingKeySource rejects an unrecognised key source rather than
// falling back to sm2, and refuses csv-hw on an fhe instance: fhe runs outside
// the CSV guest and has no /dev/csv-guest.
func validateStateSealingKeySource(cfg StartupConfig) error {
	for _, source := range stateSealingKeySources {
		if cfg.StateSealingKeySource != source {
			continue
		}
		if source == StateSealingKeySourceCSVHW && cfg.ServerType == ServerTypeFHE {
			return fmt.Errorf("storage.stateSealingKeySource is %q but server.type is %q: an fhe instance is not a CSV guest and has no /dev/csv-guest; use %q",
				source, ServerTypeFHE, StateSealingKeySourceSM2)
		}
		return nil
	}
	return fmt.Errorf("unsupported storage.stateSealingKeySource %q: must be one of %s",
		cfg.StateSealingKeySource, strings.Join(stateSealingKeySources, ", "))
}

// validateFHEConfig enforces the fhe section on an fhe instance. All five
// connection fields are required: a half-configured instance would fail at task
// time, after the platform was already told the import succeeded. callbackToken
// especially - an unauthenticated callback endpoint is open to every process on
// the host.
func validateFHEConfig(cfg StartupConfig) error {
	if cfg.ServerType != ServerTypeFHE {
		return nil
	}
	if cfg.FHE == nil {
		return fmt.Errorf("server.type is %q but the startup config has no fhe section", ServerTypeFHE)
	}
	required := []struct {
		name  string
		value string
	}{
		{"endpoint", cfg.FHE.Endpoint},
		{"dataDir", cfg.FHE.DataDir},
		{"keyCacheDir", cfg.FHE.KeyCacheDir},
		{"callbackBaseUrl", cfg.FHE.CallbackBaseURL},
		{"callbackToken", cfg.FHE.CallbackToken},
	}
	for _, r := range required {
		if strings.TrimSpace(r.value) == "" {
			return fmt.Errorf("fhe.%s is required when server.type is %q", r.name, ServerTypeFHE)
		}
	}
	if err := validateFHEURL("endpoint", cfg.FHE.Endpoint); err != nil {
		return err
	}
	if err := validateFHEURL("callbackBaseUrl", cfg.FHE.CallbackBaseURL); err != nil {
		return err
	}
	if cfg.FHE.MaxEvalKeyBytes <= 0 {
		return fmt.Errorf("unsupported fhe.maxEvalKeyBytes %d in startup config: must be positive", cfg.FHE.MaxEvalKeyBytes)
	}
	for _, b := range []struct {
		name  string
		value int
	}{
		{"pollIntervalMs", cfg.FHE.PollIntervalMs},
		{"requestTimeoutMs", cfg.FHE.RequestTimeoutMs},
		{"taskTimeoutMs", cfg.FHE.TaskTimeoutMs},
	} {
		if b.value <= 0 {
			return fmt.Errorf("unsupported fhe.%s %d in startup config: must be positive", b.name, b.value)
		}
	}
	return nil
}

// validateFHEURL rejects a value that is not an absolute http or https URL with
// a non-empty host. A bare "host:port" has no scheme, so it fails; and a URL
// like "http://:1" has an empty host even though Host is non-empty, which is why
// the check reads Hostname rather than Host. Both mistakes otherwise survive
// until the instance tries to reach the service, long after startup.
func validateFHEURL(name, value string) error {
	u, err := url.Parse(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("unsupported fhe.%s %q in startup config: %v", name, value, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("unsupported fhe.%s %q in startup config: must be an absolute http or https URL with a host", name, value)
	}
	return nil
}

// validateBinaryAudit rejects limits that cannot mean what they say.
//
// A negative count is rejected rather than normalised: the normalisation path
// exists for "unset", and a deployment that wrote -1 has a different problem
// from one that wrote nothing. Rejecting turns it into a startup error instead
// of an audit that quietly ran with a different budget.
//
// The guarantee is path-specific, and worth stating precisely: it holds on the
// file-load path, because validateStartupConfig runs before the values are used.
// It does not hold globally. normalizeBinaryConfig tests "<= 0", so a negative
// that reaches codeaudit by another route - a hand-built StartupConfig, which is
// exactly how buildSecurityConfig is called from the app tests - is silently
// replaced by the default rather than rejected. Nothing reaches that route in
// production: the only production construction of StartupConfig goes through
// LoadStartupConfig.
func validateBinaryAudit(cfg StartupConfig) error {
	if cfg.BinaryAuditMaxArchiveMembers < 0 {
		return fmt.Errorf("codeAudit.binaryAudit.maxArchiveMembers must not be negative, got %d", cfg.BinaryAuditMaxArchiveMembers)
	}
	if cfg.BinaryAuditMaxFindings < 0 {
		return fmt.Errorf("codeAudit.binaryAudit.maxFindings must not be negative, got %d", cfg.BinaryAuditMaxFindings)
	}
	if cfg.BinaryAuditMaxFullScanBytes < 0 {
		return fmt.Errorf("codeAudit.binaryAudit.maxFullScanBytes must not be negative, got %d", cfg.BinaryAuditMaxFullScanBytes)
	}
	if cfg.BinaryAuditMaxStreamBytes < 0 {
		return fmt.Errorf("codeAudit.binaryAudit.maxStreamBytes must not be negative, got %d", cfg.BinaryAuditMaxStreamBytes)
	}
	if cfg.BinaryAuditHighEntropyThreshold < 0 || cfg.BinaryAuditHighEntropyThreshold > 8 {
		return fmt.Errorf("codeAudit.binaryAudit.highEntropyThreshold must be within [0,8] bits per byte, got %v",
			cfg.BinaryAuditHighEntropyThreshold)
	}
	return nil
}

// validateLLMTemperature rejects a sampling temperature outside [0, 2].
//
// Sampling and audit integrity pull against each other: the audit needs the same
// finding to yield the same verdict, because under assist + failClosed a single
// MALICIOUS verdict blocks the import of code that never changed. Any temperature
// above zero re-enables sampling, and the higher it goes the more the verdict is
// a draw rather than a reading - at 2 the distribution is already nearly flat, so
// the model is close to picking a verdict at random. That is never what an audit
// deployment means to ask for, so it is rejected at startup, where an operator
// sees it, rather than surfacing later as an import blocked for no visible reason.
//
// A negative temperature is rejected for the same class of reason: it is not a
// sharper setting, it is not something the inference service can honour.
func validateLLMTemperature(cfg StartupConfig) error {
	if cfg.LLM.Temperature == nil {
		return nil
	}
	if t := *cfg.LLM.Temperature; t < 0 || t > 2 {
		return fmt.Errorf("codeAudit.llm.temperature in startup config must be within [0, 2]: got %v", t)
	}
	return nil
}

// validateSemgrepTimeout rejects a deadline the adapter cannot honour. A
// negative duration is not a shorter scan: the deadline is already expired when
// the scan starts, so every import fails closed, and the cause is a line of
// configuration nothing re-reads. The failure belongs
// on the configuration, where an operator sees it at startup.
func validateSemgrepTimeout(cfg StartupConfig) error {
	if cfg.CodeScan.Timeout < 0 {
		return fmt.Errorf("codeAudit.codeScan.timeoutSeconds in startup config must not be negative: got %d",
			int64(cfg.CodeScan.Timeout/time.Second))
	}
	return nil
}

func validateCodeScanEngine(cfg StartupConfig) error {
	for _, engine := range staticEngines {
		if cfg.CodeScan.Engine == engine {
			return nil
		}
	}
	return fmt.Errorf("unsupported codeAudit.codeScan.engine %q in startup config: must be one of %s",
		cfg.CodeScan.Engine, strings.Join(staticEngines, ", "))
}

func validateLLMPolicy(cfg StartupConfig) error {
	for _, policy := range llmPolicies {
		if cfg.LLM.Policy == policy {
			return nil
		}
	}
	return fmt.Errorf("unsupported codeAudit.llm.policy %q in startup config: must be one of %s",
		cfg.LLM.Policy, strings.Join(llmPolicies, ", "))
}

func defaultStartupConfig() StartupConfig {
	hrkDefault := "/root/taa/certs/hrk.cert"
	hskDefault := "/root/taa/certs/hsk_cek.cert"
	if _, err := os.Stat(hrkDefault); err != nil {
		if _, localErr := os.Stat("deploy/certs/hrk.cert"); localErr == nil {
			hrkDefault = "deploy/certs/hrk.cert"
			hskDefault = "deploy/certs/hsk_cek.cert"
		}
	}

	return StartupConfig{
		Addr:                      ":6001",
		ServerType:                ServerTypeTEE,
		PlatformIP:                os.Getenv("PLATFORM_IP"),
		DockerID:                  os.Getenv("DOCKER_ID"),
		Contract:                  os.Getenv("CONTRACT_ID"),
		EnableCodeAudit:           true,
		CodeScan:                  CodeScanConfig{Engine: "semgrep"},
		BinaryAuditEnabled:        true,
		ModelDir:                  "/opt/taa/models",
		EnableResultCheck:         true,
		MaxFileBytes:              DefaultMaxFileBytes,
		MaxResultBytes:            DefaultMaxResultBytes,
		DataDir:                   "/opt/taa/data",
		ResultDir:                 "/opt/taa/results",
		ModelInputDir:             "/opt/taa/input",
		ModelOutputDir:            "/opt/taa/output/result",
		ModelLogDir:               "/opt/taa/output/log",
		ModelProgressDir:          "/opt/taa/output/progress/progress.json",
		KeysDir:                   "/root/taa/keys",
		StateSealingKeySource:     StateSealingKeySourceSM2,
		AttestationHRKCertPath:    hrkDefault,
		AttestationHSKCekCertPath: hskDefault,
		LLM: LLMConfig{
			Enabled:                 true,
			Transport:               "teetls",
			Endpoint:                "https://127.0.0.1:8443",
			AttestationMode:         "strict",
			HRKCertPath:             hrkDefault,
			HSKCekCertPath:          hskDefault,
			RequireMutualAttest:     false,
			InsecureSkipVerify:      false,
			TimeoutMs:               30000,
			CircuitBreakerThreshold: 3,
			CooldownSec:             30,
			Model:                   "qwen2.5-coder:0.5b",
			Policy:                  "assist",
			FailClosed:              true,
		},
	}
}

func applyStartupConfigFile(cfg *StartupConfig, fileCfg startupConfigFile) {
	if trimmed := strings.TrimSpace(fileCfg.Addr); trimmed != "" {
		cfg.Addr = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Server.Addr); trimmed != "" {
		cfg.Addr = trimmed
	}
	if trimmed := strings.ToLower(strings.TrimSpace(fileCfg.Server.Type)); trimmed != "" {
		cfg.ServerType = trimmed
	}

	// An fhe instance runs no code audit and produces no attestation report: its
	// model packages are FHE layers rather than executable code, its results are
	// ciphertext, and its trust rests on the encrypted computation rather than on
	// a local quote. Both blocks therefore mean nothing here, and are ignored
	// instead of applied and left unused. Their absence is the normal shape of an
	// fhe config, not an error - which is also why the values that do matter to
	// an fhe instance (maxFileBytes and the legacy top-level switches) are read
	// outside the guarded regions below.
	readsAuditAndAttestation := cfg.ServerType != ServerTypeFHE

	// The startup path builds the security configuration even on an fhe instance,
	// and that resolves the code scan engine against the disk. The generic default
	// (semgrep) refuses to construct without a rules file, and the fhe image
	// carries none, so leaving it in place would turn "this instance never scans"
	// into a restart loop. The rule-carrying engine is the one that needs nothing
	// on disk; that no scan ever runs here is the point, not a side effect.
	if !readsAuditAndAttestation {
		cfg.CodeScan.Engine = "regex"
	}

	if trimmed := strings.TrimSpace(fileCfg.PlatformIP); trimmed != "" {
		cfg.PlatformIP = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Platform.IP); trimmed != "" {
		cfg.PlatformIP = trimmed
	} else if trimmed := strings.TrimSpace(fileCfg.Platform.Endpoint); trimmed != "" {
		cfg.PlatformIP = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.DockerID); trimmed != "" {
		cfg.DockerID = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Platform.DockerID); trimmed != "" {
		cfg.DockerID = trimmed
	}

	if fileCfg.Contract != "" {
		cfg.Contract = fileCfg.Contract
	}
	if fileCfg.Platform.Contract != "" {
		cfg.Contract = fileCfg.Platform.Contract
	}

	if readsAuditAndAttestation {
		if fileCfg.EnableSecurityScan != nil {
			cfg.EnableCodeAudit = *fileCfg.EnableSecurityScan
		}
		if fileCfg.CodeAudit.Scan != nil {
			cfg.EnableCodeAudit = *fileCfg.CodeAudit.Scan
		}
		if fileCfg.CodeAudit.Enabled != nil {
			cfg.EnableCodeAudit = *fileCfg.CodeAudit.Enabled
		}

		if trimmed := strings.ToLower(strings.TrimSpace(fileCfg.CodeAudit.CodeScan.Engine)); trimmed != "" {
			cfg.CodeScan.Engine = trimmed
		}
		if trimmed := strings.TrimSpace(fileCfg.CodeAudit.CodeScan.RulesPath); trimmed != "" {
			cfg.CodeScan.RulesPath = trimmed
		}
		if seconds := fileCfg.CodeAudit.CodeScan.TimeoutSeconds; seconds != 0 {
			cfg.CodeScan.Timeout = time.Duration(seconds) * time.Second
		}

		ba := fileCfg.CodeAudit.BinaryAudit
		if ba.Enabled != nil {
			cfg.BinaryAuditEnabled = *ba.Enabled
		}
		if ba.MaxArchiveMembers != nil {
			cfg.BinaryAuditMaxArchiveMembers = *ba.MaxArchiveMembers
		}
		if ba.HighEntropyThreshold != nil {
			cfg.BinaryAuditHighEntropyThreshold = *ba.HighEntropyThreshold
		}
		if ba.MaxFindings != nil {
			cfg.BinaryAuditMaxFindings = *ba.MaxFindings
		}
		if ba.MaxFullScanBytes != nil {
			cfg.BinaryAuditMaxFullScanBytes = int(*ba.MaxFullScanBytes)
		}
		if ba.MaxStreamBytes != nil {
			cfg.BinaryAuditMaxStreamBytes = int(*ba.MaxStreamBytes)
		}
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelDir); trimmed != "" {
		cfg.ModelDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Dir); trimmed != "" {
		cfg.ModelDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.ModelDir); trimmed != "" {
		cfg.ModelDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.Model); trimmed != "" {
		cfg.ModelDir = trimmed
	}

	if fileCfg.EnableResultCheck != nil {
		cfg.EnableResultCheck = *fileCfg.EnableResultCheck
	}
	if readsAuditAndAttestation && fileCfg.CodeAudit.ResultCheck.Enabled != nil {
		cfg.EnableResultCheck = *fileCfg.CodeAudit.ResultCheck.Enabled
	}

	if fileCfg.MaxResultBytes != nil {
		cfg.MaxFileBytes = *fileCfg.MaxResultBytes
	}
	if fileCfg.MaxFileBytes != nil {
		cfg.MaxFileBytes = *fileCfg.MaxFileBytes
	}
	if readsAuditAndAttestation {
		if fileCfg.CodeAudit.MaxFileBytes != nil {
			cfg.MaxFileBytes = *fileCfg.CodeAudit.MaxFileBytes
		}
		if fileCfg.CodeAudit.ResultCheck.MaxFileBytes != nil {
			cfg.MaxFileBytes = *fileCfg.CodeAudit.ResultCheck.MaxFileBytes
		}
	}
	cfg.MaxResultBytes = cfg.MaxFileBytes

	if trimmed := strings.TrimSpace(fileCfg.DataDir); trimmed != "" {
		cfg.DataDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.DataDir); trimmed != "" {
		cfg.DataDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.Data); trimmed != "" {
		cfg.DataDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ResultDir); trimmed != "" {
		cfg.ResultDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.ResultDir); trimmed != "" {
		cfg.ResultDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.Result); trimmed != "" {
		cfg.ResultDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.KeysDir); trimmed != "" {
		cfg.KeysDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.KeysDir); trimmed != "" {
		cfg.KeysDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Storage.Keys); trimmed != "" {
		cfg.KeysDir = trimmed
	}
	if trimmed := strings.ToLower(strings.TrimSpace(fileCfg.Storage.StateSealingKeySource)); trimmed != "" {
		cfg.StateSealingKeySource = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelInputDir); trimmed != "" {
		cfg.ModelInputDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Input); trimmed != "" {
		cfg.ModelInputDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelOutputDir); trimmed != "" {
		cfg.ModelOutputDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Output.Result); trimmed != "" {
		cfg.ModelOutputDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelLogDir); trimmed != "" {
		cfg.ModelLogDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Output.Log); trimmed != "" {
		cfg.ModelLogDir = trimmed
	}

	if trimmed := strings.TrimSpace(fileCfg.ModelProgressDir); trimmed != "" {
		cfg.ModelProgressDir = trimmed
	}
	if trimmed := strings.TrimSpace(fileCfg.Model.Output.Progress); trimmed != "" {
		cfg.ModelProgressDir = trimmed
	}
	if readsAuditAndAttestation {
		if trimmed := strings.TrimSpace(fileCfg.Attestation.HRKCertPath); trimmed != "" {
			cfg.AttestationHRKCertPath = trimmed
		}
		if trimmed := strings.TrimSpace(fileCfg.Attestation.HSKCekCertPath); trimmed != "" {
			cfg.AttestationHSKCekCertPath = trimmed
		}
		if fileCfg.CodeAudit.LLM.Enabled != nil {
			cfg.LLM.Enabled = *fileCfg.CodeAudit.LLM.Enabled
		}
		if fileCfg.CodeAudit.LLM.Transport != "" {
			cfg.LLM.Transport = strings.TrimSpace(fileCfg.CodeAudit.LLM.Transport)
		}
		if fileCfg.CodeAudit.LLM.Endpoint != "" {
			cfg.LLM.Endpoint = fileCfg.CodeAudit.LLM.Endpoint
		}
		if trimmed := strings.TrimSpace(fileCfg.CodeAudit.LLM.AttestationMode); trimmed != "" {
			cfg.LLM.AttestationMode = trimmed
		}
		if trimmed := strings.TrimSpace(fileCfg.CodeAudit.LLM.HRKCertPath); trimmed != "" {
			cfg.LLM.HRKCertPath = trimmed
		}
		if trimmed := strings.TrimSpace(fileCfg.CodeAudit.LLM.HSKCekCertPath); trimmed != "" {
			cfg.LLM.HSKCekCertPath = trimmed
		}
		if len(fileCfg.CodeAudit.LLM.ExpectedMeasurements) > 0 {
			cfg.LLM.ExpectedMeasurements = fileCfg.CodeAudit.LLM.ExpectedMeasurements
		}
		if fileCfg.CodeAudit.LLM.RequireMutualAttest != nil {
			cfg.LLM.RequireMutualAttest = *fileCfg.CodeAudit.LLM.RequireMutualAttest
		}
		if fileCfg.CodeAudit.LLM.InsecureSkipVerify != nil {
			cfg.LLM.InsecureSkipVerify = *fileCfg.CodeAudit.LLM.InsecureSkipVerify
		}
		if fileCfg.CodeAudit.LLM.AuthToken != "" {
			cfg.LLM.AuthToken = fileCfg.CodeAudit.LLM.AuthToken
		}
		if fileCfg.CodeAudit.LLM.RequestTimeoutMs > 0 {
			cfg.LLM.TimeoutMs = fileCfg.CodeAudit.LLM.RequestTimeoutMs
		}
		if len(fileCfg.CodeAudit.LLM.AllowedHosts) > 0 {
			cfg.LLM.AllowedHosts = fileCfg.CodeAudit.LLM.AllowedHosts
		}
		if fileCfg.CodeAudit.LLM.CircuitBreakerThreshold > 0 {
			cfg.LLM.CircuitBreakerThreshold = fileCfg.CodeAudit.LLM.CircuitBreakerThreshold
		}
		if fileCfg.CodeAudit.LLM.CooldownSec > 0 {
			cfg.LLM.CooldownSec = fileCfg.CodeAudit.LLM.CooldownSec
		}
		if fileCfg.CodeAudit.LLM.Model != "" {
			cfg.LLM.Model = fileCfg.CodeAudit.LLM.Model
		}
		if fileCfg.CodeAudit.LLM.Policy != "" {
			cfg.LLM.Policy = strings.ToLower(strings.TrimSpace(fileCfg.CodeAudit.LLM.Policy))
		}
		// nil-guard rather than the "> 0" guard the neighbouring LLM numerics use.
		// nil means "not configured"; zero is a real sampling value here (greedy
		// decoding, which is what the audit wants), so a "> 0" guard would make it
		// impossible to state zero explicitly.
		if fileCfg.CodeAudit.LLM.Temperature != nil {
			cfg.LLM.Temperature = fileCfg.CodeAudit.LLM.Temperature
		}
		if fileCfg.CodeAudit.LLM.FailClosed != nil {
			cfg.LLM.FailClosed = *fileCfg.CodeAudit.LLM.FailClosed
		}
		if fileCfg.CodeAudit.LLM.Dir != "" {
			cfg.LLM.Dir = fileCfg.CodeAudit.LLM.Dir
		}
	}

	// The fhe section is only meaningful on an fhe instance. A tee instance that
	// carries one is a deployment mistake, but not a fatal one: warn and drop it
	// so the instance keeps behaving exactly as it did before the section existed.
	if fileCfg.FHE != nil {
		if cfg.ServerType == ServerTypeFHE {
			f := *fileCfg.FHE
			applyFHEDefaults(&f)
			cfg.FHE = &f
		} else {
			log.Printf("WARNING: startup config carries an fhe section but server.type is %q; the section is ignored", cfg.ServerType)
		}
	}
}

// applyFHEDefaults fills the optional fhe fields. Required fields are left as
// they are: an empty required field must be rejected, not silently defaulted.
func applyFHEDefaults(f *FHEConfig) {
	if f.MaxEvalKeyBytes == 0 {
		f.MaxEvalKeyBytes = DefaultFHEMaxEvalKeyBytes
	}
	if f.PollIntervalMs == 0 {
		f.PollIntervalMs = DefaultFHEPollIntervalMs
	}
	if f.RequestTimeoutMs == 0 {
		f.RequestTimeoutMs = DefaultFHERequestTimeoutMs
	}
	if f.TaskTimeoutMs == 0 {
		f.TaskTimeoutMs = DefaultFHETaskTimeoutMs
	}
	if f.ActivateModelOnImport == nil {
		v := true
		f.ActivateModelOnImport = &v
	}
}
