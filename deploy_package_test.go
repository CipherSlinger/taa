package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOllamaPackageAtNewPathIsComplete(t *testing.T) {
	pkgDir := filepath.Join("models", "audit", "ollama-qwen2.5-coder-0.5b")
	requiredPaths := []string{
		filepath.Join(pkgDir, "ollama"),
		filepath.Join(pkgDir, "start-ollama.sh"),
		filepath.Join(pkgDir, "models", "models"),
		filepath.Join(pkgDir, "lib", "ollama"),
		filepath.Join(pkgDir, "lib", "ollama", "llama-server"),
		filepath.Join(pkgDir, "lib", "ollama", "libllama-server-impl.so"),
	}

	for _, rel := range requiredPaths {
		if _, err := os.Stat(rel); err != nil {
			t.Fatalf("missing required deployment asset %s: %v", rel, err)
		}
	}
}

func TestDeployShLocalStartsOllamaViaStartScript(t *testing.T) {
	data, err := os.ReadFile("deploy.sh")
	if err != nil {
		t.Fatalf("read deploy.sh: %v", err)
	}
	text := string(data)
	start := strings.Index(text, "step \"starting local ollama\"")
	end := strings.Index(text, "step \"starting local taa\"")
	if start < 0 || end < 0 || end <= start {
		t.Fatal("deploy.sh local ollama block not found")
	}
	block := text[start:end]
	if !strings.Contains(block, "./start-ollama.sh") || !strings.Contains(block, "OLLAMA_LOCAL_DIR") {
		t.Fatal("deploy.sh local ollama block should use the package start script")
	}
	if strings.Contains(block, "LOCAL_OLLAMA_LOADER") || strings.Contains(block, "custom dynamic linker") {
		t.Fatal("deploy.sh local ollama block should not depend on the custom loader")
	}
}

func TestStartOllamaScriptLaunchesLocalBinary(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("models", "audit", "ollama-qwen2.5-coder-0.5b", "start-ollama.sh"))
	if err != nil {
		t.Fatalf("read start-ollama.sh: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `exec "$DIR/ollama" serve`) {
		t.Fatal("start-ollama.sh should exec the local ollama binary")
	}
	if strings.Contains(text, "ld-linux-x86-64.so.2") {
		t.Fatal("start-ollama.sh should not depend on a custom loader")
	}
}
