package codeaudit

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSemgrepEngine_MultiLanguageRules verifies that Semgrep engine can load
// a rules directory and scan multiple languages: Go, C/C++, Java, and Shell.
func TestSemgrepEngine_MultiLanguageRules(t *testing.T) {
	if _, err := exec.LookPath("semgrep"); err != nil {
		t.Skip("semgrep binary not installed on host, skipping CLI test")
	}

	rulesDir, err := filepath.Abs("../../models/audit/semgrep/rules")
	if err != nil {
		t.Fatalf("failed to resolve rules directory: %v", err)
	}
	if _, err := os.Stat(rulesDir); err != nil {
		t.Fatalf("rules directory %s does not exist: %v", rulesDir, err)
	}

	engine := NewSemgrepEngine(DefaultScanner(), rulesDir, SemgrepLimits{})

	tmpDir := t.TempDir()

	// 1. Go sample (CMD_001 and NET_001)
	goCode := `package main

import (
	"context"
	"net/http"
	"os/exec"
)

func run(c string) {
	exec.Command("sh", "-c", c).Run()
	exec.CommandContext(context.Background(), "bash", "-c", c).Run()
}

func fetch(url string) {
	http.Get(url)
	http.Post(url, "text/plain", nil)
	client := &http.Client{}
	client.Do(nil)
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.go"), []byte(goCode), 0644); err != nil {
		t.Fatal(err)
	}

	// 2. C/C++ sample (CMD_001)
	cCode := `#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

void execute_cmd(const char *cmd) {
	system(cmd);
	popen(cmd, "r");
	char *args[] = {"/bin/sh", NULL};
	execve("/bin/sh", args, NULL);
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.c"), []byte(cCode), 0644); err != nil {
		t.Fatal(err)
	}

	// 3. Java sample (CMD_001)
	javaCode := `public class Runner {
	public static void main(String[] args) throws Exception {
		Runtime.getRuntime().exec(args[0]);
		new ProcessBuilder("sh", "-c", args[0]).start();
	}
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.java"), []byte(javaCode), 0644); err != nil {
		t.Fatal(err)
	}

	// 4. Shell sample (CMD_001)
	shCode := `#!/bin/bash
eval "$1"
bash -c "$2"
sh -c "$3"
`
	if err := os.WriteFile(filepath.Join(tmpDir, "test.sh"), []byte(shCode), 0644); err != nil {
		t.Fatal(err)
	}

	report, err := engine.ScanDirectory(tmpDir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if report.FilesCount != 4 {
		t.Fatalf("expected 4 files scanned, got %d", report.FilesCount)
	}

	// Verify we got findings for each language
	foundLangs := make(map[string]bool)
	ruleFamilies := make(map[string]bool)
	for _, f := range report.Findings {
		ext := filepath.Ext(f.File)
		foundLangs[ext] = true
		ruleFamilies[f.RuleID] = true
	}

	for _, ext := range []string{".go", ".c", ".java", ".sh"} {
		if !foundLangs[ext] {
			t.Errorf("expected security finding in %s file, but found none", ext)
		}
	}

	if !ruleFamilies["CMD_001"] {
		t.Errorf("expected CMD_001 findings, got %v", ruleFamilies)
	}
	if !ruleFamilies["NET_001"] {
		t.Errorf("expected NET_001 findings, got %v", ruleFamilies)
	}

	if len(report.Findings) < 10 {
		t.Fatalf("expected at least 10 multi-language findings across patterns, got %d", len(report.Findings))
	}
}
