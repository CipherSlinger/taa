package coordinator

import (
	"path/filepath"
	"strings"

	"taa/internal/codeaudit"
)

const (
	DefaultModelInputDir    = "/opt/taa/input"
	DefaultModelOutputDir   = "/opt/taa/output/result"
	DefaultModelLogDir      = "/opt/taa/output/log"
	DefaultModelProgressDir = "/opt/taa/output/progress"
)

// SecurityConfig 保存启动时固化的安全配置与运行目录
type SecurityConfig struct {
	ScanEnabled      bool                // 是否在模型导入时执行源码安全扫描
	ModelDir         string              // 模型代码目录（扫描目标）
	DataDir          string              // 数据目录
	ResultCheck      bool                // 是否在导出时检查明文数据泄露
	ResultDir        string              // 训练结果目录（导出前检查）
	MaxResultBytes   int64               // 导出产物单文件最大限制字节数（默认 3GB）
	ModelInputDir    string              // 模型数据输入目录（缺省 /opt/taa/input）
	ModelOutputDir   string              // 模型结果输出目录（缺省 /opt/taa/output/result）
	ModelLogDir      string              // 模型日志目录（缺省 /opt/taa/output/log）
	ModelProgressDir string              // 模型进度目录（缺省 /opt/taa/output/progress）
	LLM              codeaudit.LLMConfig // 本地 LLM 语义验证配置
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
