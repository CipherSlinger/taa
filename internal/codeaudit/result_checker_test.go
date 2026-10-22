package codeaudit

import (
	"os"
	"path/filepath"
	"testing"
)

func writeResultTestFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResultCheckerFailsOnCopiedInputFile(t *testing.T) {
	inputDir := t.TempDir()
	resultDir := t.TempDir()
	data := []byte("id,label,image\n001,DN,img_001.jpg\n002,NDRD,img_002.jpg\n")
	writeResultTestFile(t, inputDir, "train.csv", data)
	// A different name must not matter: the digest is what is compared.
	writeResultTestFile(t, resultDir, "copied_but_renamed.csv", data)

	report, err := NewResultChecker(inputDir).CheckDirectory(resultDir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("expected the check to fail when a result file is a copy of an input file")
	}
	assertResultHasCheck(t, report, "file_hash_match")
}

func TestResultCheckerPassesWhenNoHashMatches(t *testing.T) {
	inputDir := t.TempDir()
	resultDir := t.TempDir()
	data := []byte("id,label,image\n001,DN,img_001.jpg\n")
	writeResultTestFile(t, inputDir, "train.csv", data)
	// The result embeds the training rows, but is not a byte-for-byte copy. The
	// hash comparison is whole-file only and deliberately lets this through.
	writeResultTestFile(t, resultDir, "model_result.bin",
		append([]byte("model header..."), append(data, []byte("...footer")...)...))

	report, err := NewResultChecker(inputDir).CheckDirectory(resultDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("expected a pass without a hash intersection, got warnings: %+v", report.Warnings)
	}
}

func TestResultCheckerCleanDirectoryPasses(t *testing.T) {
	inputDir := t.TempDir()
	resultDir := t.TempDir()
	writeResultTestFile(t, inputDir, "train.csv", []byte("id,label\n1,cat\n"))
	writeResultTestFile(t, resultDir, "model.pth", []byte{0x80, 0x02, 0x00, 0x00, 0xFF, 0xFE})
	writeResultTestFile(t, resultDir, "metrics.json", []byte(`{"accuracy":0.99}`))

	report, err := NewResultChecker(inputDir).CheckDirectory(resultDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("clean result should pass, got warnings: %+v", report.Warnings)
	}
	if len(report.Warnings) != 0 {
		t.Fatalf("expected 0 warnings, got %d", len(report.Warnings))
	}
}

func TestResultCheckerFailsOnOneCopiedFileAmongCleanOnes(t *testing.T) {
	inputDir := t.TempDir()
	resultDir := t.TempDir()
	leaked := []byte("patient_id,image\n7,img_007.jpg\n")
	writeResultTestFile(t, inputDir, "nested/train.csv", leaked)
	writeResultTestFile(t, resultDir, "model.pth", []byte{1, 2, 3})
	writeResultTestFile(t, resultDir, "assets/leaked.csv", leaked)

	report, err := NewResultChecker(inputDir).CheckDirectory(resultDir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("one copied file must fail the directory")
	}
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %+v, want exactly one match", report.Warnings)
	}
	assertResultHasCheck(t, report, "file_hash_match")
}

// 根目录下被点名的文件是调用方自己的元数据（训练报告），它按设计带样本行预览，
// 比它等于把检查自己的产物报成泄露。
func TestResultCheckerSkipsNamedRootFiles(t *testing.T) {
	reported := "training_report.json"
	leaked := []byte(`{"preview":[["1","cat","img1.jpg"]]}`)

	t.Run("skipped at the root", func(t *testing.T) {
		inputDir := t.TempDir()
		resultDir := t.TempDir()
		writeResultTestFile(t, inputDir, "train.csv", leaked)
		writeResultTestFile(t, resultDir, reported, leaked)

		report, err := NewResultChecker(inputDir).CheckDirectory(resultDir, reported)
		if err != nil {
			t.Fatal(err)
		}
		if !report.Passed {
			t.Fatalf("named root file should be skipped, got warnings: %+v", report.Warnings)
		}
	})

	// 跳过规则只认根目录：同名文件出现在深处就是训练脚本自己的产物，必须照查，
	// 否则"没被检查过的文件照样进导出包"。
	t.Run("still checked deeper in the tree", func(t *testing.T) {
		inputDir := t.TempDir()
		resultDir := t.TempDir()
		writeResultTestFile(t, inputDir, "train.csv", leaked)
		writeResultTestFile(t, resultDir, "sub/"+reported, leaked)

		report, err := NewResultChecker(inputDir).CheckDirectory(resultDir, reported)
		if err != nil {
			t.Fatal(err)
		}
		if report.Passed {
			t.Fatal("a same-named file below the root must still be checked")
		}
	})
}

// Empty and hidden files carry no training data, and two unrelated empty files
// share a digest; skipping them keeps a clean run from failing on bookkeeping.
func TestResultCheckerSkipsEmptyAndHiddenFiles(t *testing.T) {
	inputDir := t.TempDir()
	resultDir := t.TempDir()
	for _, dir := range []string{inputDir, resultDir} {
		writeResultTestFile(t, dir, "placeholder", []byte{})
		writeResultTestFile(t, dir, ".DS_Store", []byte{0x00, 0x01, 0x02})
	}
	writeResultTestFile(t, inputDir, "train.csv", []byte("id,label\n1,cat\n"))

	report, err := NewResultChecker(inputDir).CheckDirectory(resultDir)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("empty and hidden files must not fail the check, got warnings: %+v", report.Warnings)
	}
}

func TestResultCheckerCheckFile(t *testing.T) {
	inputDir := t.TempDir()
	data := []byte("training data\n")
	writeResultTestFile(t, inputDir, "data/sample.txt", data)
	checker := NewResultChecker(inputDir)

	t.Run("copied file fails", func(t *testing.T) {
		path := writeResultTestFile(t, t.TempDir(), "copy.txt", data)
		report, err := checker.CheckFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if report.Passed {
			t.Fatal("expected a copied input file to fail")
		}
		assertResultHasCheck(t, report, "file_hash_match")
	})

	t.Run("different content passes", func(t *testing.T) {
		path := writeResultTestFile(t, t.TempDir(), "result.bin", []byte("other bytes\n"))
		report, err := checker.CheckFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !report.Passed {
			t.Fatalf("expected a pass, got warnings: %+v", report.Warnings)
		}
	})

	t.Run("empty file passes", func(t *testing.T) {
		path := writeResultTestFile(t, t.TempDir(), "empty.bin", []byte{})
		report, err := checker.CheckFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !report.Passed {
			t.Fatalf("empty file should pass, got warnings: %+v", report.Warnings)
		}
	})

	t.Run("missing file errors", func(t *testing.T) {
		if _, err := checker.CheckFile(filepath.Join(t.TempDir(), "missing.bin")); err == nil {
			t.Fatal("expected an error for a non-existent result file")
		}
	})
}

func TestResultCheckerRequiresInputDirectory(t *testing.T) {
	resultDir := t.TempDir()
	writeResultTestFile(t, resultDir, "model.pth", []byte{1, 2, 3})

	for _, inputDir := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		if _, err := NewResultChecker(inputDir).CheckDirectory(resultDir); err == nil {
			t.Fatalf("inputDir %q: expected an error, the check cannot run without inputs", inputDir)
		}
	}

	if _, err := NewResultChecker(t.TempDir()).CheckDirectory(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected an error for a non-existent result directory")
	}
}

// ── helpers ──────────────────────────────────────────────

func assertResultHasCheck(t *testing.T, report *ResultCheckReport, check string) {
	t.Helper()
	for _, w := range report.Warnings {
		if w.Check == check {
			return
		}
	}
	var checks []string
	for _, w := range report.Warnings {
		checks = append(checks, w.Check)
	}
	t.Fatalf("expected warning with check %q, got: %v", check, checks)
}
