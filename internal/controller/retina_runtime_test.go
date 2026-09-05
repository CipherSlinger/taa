package controller

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRetinaDKDScriptsPreferBundledPython(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell scripts are not supported on windows")
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	srcScriptDir := filepath.Join(repoRoot, "models", "examples", "Retina-DKD")
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "Retina-DKD")
	codeDir := filepath.Join(scriptDir, "Retina-DKD")
	dataDir := filepath.Join(scriptDir, "data")
	outputDir := filepath.Join(tmpDir, "output")
	logFile := filepath.Join(tmpDir, "python.log")
	pathDir := filepath.Join(tmpDir, "bin")

	for _, dir := range []string{scriptDir, codeDir, dataDir, outputDir, filepath.Join(scriptDir, "python", "bin"), pathDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	for _, name := range []string{"debug.py", "train.py"} {
		data, err := os.ReadFile(filepath.Join(srcScriptDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(scriptDir, name), data, 0o755); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	pythonStub := "#!/bin/sh\n" +
		"printf '%s %s\\n' \"$0\" \"$*\" >> \"$PYTHON_LOG_FILE\"\n" +
		"case \"$1\" in\n" +
		"  --version)\n" +
		"    printf 'Python 3.11.16\\n'\n" +
		"    ;;\n" +
		"  -c)\n" +
		"    ;;\n" +
		"esac\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "python", "bin", "python3"), []byte(pythonStub), 0o755); err != nil {
		t.Fatalf("write python stub: %v", err)
	}

	systemPythonStub := "#!/bin/sh\n" +
		"printf '%s %s\\n' \"$0\" \"$*\" >> \"$PYTHON_LOG_FILE\"\n" +
		"exit 99\n"
	if err := os.WriteFile(filepath.Join(pathDir, "python3"), []byte(systemPythonStub), 0o755); err != nil {
		t.Fatalf("write system python stub: %v", err)
	}

	basePath := os.Getenv("PATH")
	baseEnv := make([]string, 0, len(os.Environ())+2)
	baseEnv = append(baseEnv,
		"PYTHON_LOG_FILE="+logFile,
		"PATH="+pathDir+":"+basePath,
	)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "PYTHON_BIN=") {
			continue
		}
		baseEnv = append(baseEnv, kv)
	}

	run := func(script string, args ...string) string {
		t.Helper()
		path := script
		if !filepath.IsAbs(path) {
			path = filepath.Join(scriptDir, path)
		}
		cmd := exec.Command(path, args...)
		cmd.Dir = scriptDir
		cmd.Env = baseEnv
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v\noutput:\n%s", script, err, out)
		}
		return string(out)
	}

	bundledPython := filepath.Join(scriptDir, "python", "bin", "python3")
	run(bundledPython, filepath.Join(scriptDir, "debug.py"), "--output", outputDir)
	run(bundledPython, filepath.Join(scriptDir, "train.py"), "--input", dataDir, "--output", outputDir)

	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read python log: %v", err)
	}
	log := string(logData)
	want := filepath.Join(scriptDir, "python", "bin", "python3")
	if !strings.Contains(log, want) {
		t.Fatalf("expected bundled python path %q in log, got:\n%s", want, log)
	}
}

func TestRetinaDKDTrainScriptRunsUnderPython3(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("python3 scripts are not supported on windows")
	}

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}

	srcScriptDir := filepath.Join(repoRoot, "models", "examples", "Retina-DKD")
	tmpDir := t.TempDir()
	scriptDir := filepath.Join(tmpDir, "Retina-DKD")
	codeDir := filepath.Join(scriptDir, "Retina-DKD")
	dataDir := filepath.Join(scriptDir, "data")
	outputDir := filepath.Join(tmpDir, "output")
	logFile := filepath.Join(tmpDir, "python.log")
	pathDir := filepath.Join(tmpDir, "bin")

	for _, dir := range []string{scriptDir, codeDir, dataDir, outputDir, filepath.Join(scriptDir, "python", "bin"), pathDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(srcScriptDir, "train.py"))
	if err != nil {
		t.Fatalf("read train.py: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scriptDir, "train.py"), data, 0o755); err != nil {
		t.Fatalf("write train.py: %v", err)
	}

	pythonStub := "#!/bin/sh\n" +
		"printf '%s %s\\n' \"$0\" \"$*\" >> \"$PYTHON_LOG_FILE\"\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(scriptDir, "python", "bin", "python3"), []byte(pythonStub), 0o755); err != nil {
		t.Fatalf("write python stub: %v", err)
	}

	systemPythonStub := "#!/bin/sh\n" +
		"printf '%s %s\\n' \"$0\" \"$*\" >> \"$PYTHON_LOG_FILE\"\n" +
		"exit 99\n"
	if err := os.WriteFile(filepath.Join(pathDir, "python3"), []byte(systemPythonStub), 0o755); err != nil {
		t.Fatalf("write system python stub: %v", err)
	}

	basePath := os.Getenv("PATH")
	baseEnv := make([]string, 0, len(os.Environ())+2)
	baseEnv = append(baseEnv,
		"PYTHON_LOG_FILE="+logFile,
		"PATH="+pathDir+":"+basePath,
	)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "PYTHON_BIN=") {
			continue
		}
		baseEnv = append(baseEnv, kv)
	}

	cmd := exec.Command(filepath.Join(scriptDir, "python", "bin", "python3"), filepath.Join(scriptDir, "train.py"), "--input", dataDir, "--output", outputDir)
	cmd.Dir = scriptDir
	cmd.Env = baseEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("train.py failed under python3: %v\noutput:\n%s", err, out)
	}

	logData, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("read python log: %v", err)
	}
	log := string(logData)
	want := filepath.Join(scriptDir, "python", "bin", "python3")
	if !strings.Contains(log, want) {
		t.Fatalf("expected bundled python path %q in log, got:\n%s", want, log)
	}
}
