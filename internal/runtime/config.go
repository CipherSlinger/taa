package runtime

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// RuntimeConfig 定义模型训练运行配置
type RuntimeConfig struct {
	Commands []string `json:"commands"`
	Env      string   `json:"env"`
}

// ParseRuntimeConfig 解析 JSON 格式的运行配置，兼容 env 为对象或字符串的混合形态
func ParseRuntimeConfig(raw string) (RuntimeConfig, map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return RuntimeConfig{}, nil, fmt.Errorf("runtimeConfig 不能为空")
	}

	var cfg RuntimeConfig
	var env map[string]string
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		if strings.Contains(err.Error(), "cannot unmarshal object into Go struct field") && strings.Contains(err.Error(), ".env of type string") {
			var objCfg struct {
				Commands []string       `json:"commands"`
				Env      map[string]any `json:"env"`
			}
			if errObj := json.Unmarshal([]byte(raw), &objCfg); errObj != nil {
				return RuntimeConfig{}, nil, fmt.Errorf("解析 runtimeConfig 失败: %w", errObj)
			}
			cfg.Commands = objCfg.Commands
			if objCfg.Env != nil {
				env = make(map[string]string, len(objCfg.Env))
				for k, v := range objCfg.Env {
					switch val := v.(type) {
					case string:
						env[k] = val
					default:
						b, err := json.Marshal(val)
						if err == nil && !bytes.Equal(b, []byte("null")) {
							env[k] = string(b)
						} else {
							env[k] = fmt.Sprintf("%v", val)
						}
					}
				}
				if envBytes, err := json.Marshal(env); err == nil {
					cfg.Env = string(envBytes)
				}
			}
		} else {
			return RuntimeConfig{}, nil, fmt.Errorf("解析 runtimeConfig 失败: %w", err)
		}
	}
	if len(cfg.Commands) == 0 {
		return RuntimeConfig{}, nil, fmt.Errorf("runtimeConfig.commands 不能为空")
	}
	for i, command := range cfg.Commands {
		if strings.TrimSpace(command) == "" {
			return RuntimeConfig{}, nil, fmt.Errorf("runtimeConfig.commands[%d] 不能为空", i)
		}
	}

	if env == nil {
		env = map[string]string{}
		if strings.TrimSpace(cfg.Env) != "" {
			if err := json.Unmarshal([]byte(cfg.Env), &env); err != nil {
				return RuntimeConfig{}, nil, fmt.Errorf("解析 runtimeConfig.env 失败: %w", err)
			}
		}
	}
	return cfg, env, nil
}

func isPathContinuationByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-' || b == '.'
}

// ResolveRuntimeString 解析并替换字符串中的路径宏和规范化路径前缀
func ResolveRuntimeString(s string, dataDir, outputDir string) string {
	if s == "" {
		return ""
	}
	outputRoot := filepath.Dir(filepath.Clean(outputDir))
	logDir := filepath.Join(outputRoot, "log")
	progressDir := filepath.Join(outputRoot, "progress")

	macroReplacer := strings.NewReplacer(
		"<input>", dataDir,
		"<output>", outputDir,
		"<INPUT>", dataDir,
		"<OUTPUT>", outputDir,
		"<in>", dataDir,
		"<out>", outputDir,
		"<IN>", dataDir,
		"<OUT>", outputDir,
	)
	s = macroReplacer.Replace(s)

	type prefixTarget struct {
		prefix string
		target string
	}
	targets := []prefixTarget{
		{prefix: "/opt/taa/output/log", target: logDir},
		{prefix: "/opt/taa/output/progress", target: progressDir},
		{prefix: "/opt/taa/output/result", target: outputDir},
		{prefix: "/opt/taa/output", target: outputDir},
		{prefix: "/opt/taa/input", target: dataDir},
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		matched := false
		for _, item := range targets {
			if strings.HasPrefix(s[i:], item.prefix) {
				nextIdx := i + len(item.prefix)
				if nextIdx == len(s) {
					b.WriteString(item.target)
					i = nextIdx
					matched = true
					break
				}
				nextByte := s[nextIdx]
				if nextByte == '/' {
					b.WriteString(item.target)
					b.WriteByte('/')
					i = nextIdx + 1
					matched = true
					break
				}
				if !isPathContinuationByte(nextByte) {
					b.WriteString(item.target)
					i = nextIdx
					matched = true
					break
				}
			}
		}
		if !matched {
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

// ResolveRuntimeCommands 对命令行切片逐项做路径宏替换
func ResolveRuntimeCommands(commands []string, dataDir, outputDir string) []string {
	resolved := make([]string, len(commands))
	for i, cmd := range commands {
		resolved[i] = ResolveRuntimeString(cmd, dataDir, outputDir)
	}
	return resolved
}

// ResolveRuntimeEnv 对环境变量集合逐项做路径宏替换
func ResolveRuntimeEnv(env map[string]string, dataDir, outputDir string) map[string]string {
	if len(env) == 0 {
		return env
	}
	resolved := make(map[string]string, len(env))
	for k, v := range env {
		resolved[k] = ResolveRuntimeString(v, dataDir, outputDir)
	}
	return resolved
}
