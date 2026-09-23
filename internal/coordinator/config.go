package coordinator

import (
	"path/filepath"
	"strings"

	"taa/internal/codeaudit"
)

const (
	DefaultModelInputDir      = "/opt/taa/input"
	DefaultModelOutputDir     = "/opt/taa/output/result"
	DefaultModelLogDir        = "/opt/taa/output/log/train.jsonl"
	DefaultModelProgressDir   = "/opt/taa/output/progress/progress.json"
	DefaultModelCheckpointDir = "/opt/taa/checkpoint"
	DefaultMaxFileBytes       = 3 * 1024 * 1024 * 1024 // 3 GB
	DefaultMaxResultBytes     = DefaultMaxFileBytes
)

// SecurityConfig 保存启动时固化的安全配置与运行目录
type SecurityConfig struct {
	ScanEnabled        bool                   // 是否在模型导入时执行源码安全扫描
	Engine             codeaudit.StaticEngine // Tier 1 静态扫描引擎；未配置时（nil）审计按失败处理
	ModelDir           string                 // 模型代码目录（扫描目标）
	DataDir            string                 // 数据目录
	ResultCheck        bool                   // 是否在导出时检查明文数据泄露
	ResultDir          string                 // 训练结果目录（导出前检查）
	MaxFileBytes       int64                  // Maximum file size limit in bytes (downloads and exports, default 3GB)
	MaxResultBytes     int64                  // Backward-compatible alias for MaxFileBytes
	ModelInputDir      string                 // 模型数据输入目录（缺省 /opt/taa/input）
	ModelOutputDir     string                 // 模型结果输出目录（缺省 /opt/taa/output/result）
	ModelLogDir        string                 // Model log file or directory path (default /opt/taa/output/log/train.jsonl)
	ModelProgressDir   string                 // Model progress file or directory path (default /opt/taa/output/progress/progress.json)
	ModelCheckpointDir string                 // Model checkpoint directory (default /opt/taa/checkpoint)
	LLM                codeaudit.LLMConfig    // 本地 LLM 语义验证配置
}

func (sec SecurityConfig) GetMaxFileBytes() int64 {
	if sec.MaxFileBytes > 0 {
		return sec.MaxFileBytes
	}
	if sec.MaxResultBytes > 0 {
		return sec.MaxResultBytes
	}
	return DefaultMaxFileBytes
}

func (sec SecurityConfig) GetModelInputDir() string {
	dir := DefaultModelInputDir
	if strings.TrimSpace(sec.ModelInputDir) != "" {
		dir = sec.ModelInputDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

func (sec SecurityConfig) GetModelOutputDir() string {
	dir := DefaultModelOutputDir
	if strings.TrimSpace(sec.ModelOutputDir) != "" {
		dir = sec.ModelOutputDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

func (sec SecurityConfig) GetModelLogDir() string {
	dir := DefaultModelLogDir
	if strings.TrimSpace(sec.ModelLogDir) != "" {
		dir = sec.ModelLogDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

func (sec SecurityConfig) GetModelProgressDir() string {
	dir := DefaultModelProgressDir
	if strings.TrimSpace(sec.ModelProgressDir) != "" {
		dir = sec.ModelProgressDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}

func (sec SecurityConfig) GetModelCheckpointDir() string {
	dir := DefaultModelCheckpointDir
	if strings.TrimSpace(sec.ModelCheckpointDir) != "" {
		dir = sec.ModelCheckpointDir
	}
	if abs, err := filepath.Abs(dir); err == nil {
		return filepath.Clean(abs)
	}
	return filepath.Clean(dir)
}
