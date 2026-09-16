package coordinator

import (
	"os"
	"path/filepath"
	"testing"

	"taa/internal/resource"
	"taa/internal/runtime"
	teecrypto "taa/pkg/crypto"
)

func TestFlowExportDirectoryEnvelope(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "result")
	if err := os.MkdirAll(sourceDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sourceDir, "model.bin"), []byte("sample model weights data"), 0o644); err != nil {
		t.Fatal(err)
	}

	privKey, err := teecrypto.GenerateSM2KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEMBytes, err := teecrypto.MarshalSM2PublicKeyPEM(&privKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	pubKeyPEM := string(pubKeyPEMBytes)

	envelopeData, err := ExportResultToEnvelope(sourceDir, pubKeyPEM)
	if err != nil {
		t.Fatalf("ExportResultToEnvelope failed: %v", err)
	}
	if len(envelopeData) == 0 {
		t.Fatal("expected non-empty envelope data")
	}

	// Decrypt envelope using private key to verify envelope validity
	plainZipData, err := teecrypto.OpenSM2SM4GCM(privKey, envelopeData)
	if err != nil {
		t.Fatalf("OpenSM2SM4GCM failed: %v", err)
	}
	if len(plainZipData) == 0 {
		t.Fatal("decrypted zip is empty")
	}

	extractDst := filepath.Join(tmpDir, "extracted")
	if err := resource.ExtractZipArchive(extractDst, plainZipData); err != nil {
		t.Fatalf("ExtractZipArchive failed: %v", err)
	}

	recovered, err := os.ReadFile(filepath.Join(extractDst, "result", "model.bin"))
	if err != nil {
		t.Fatalf("failed to read recovered model.bin: %v", err)
	}
	if string(recovered) != "sample model weights data" {
		t.Fatalf("recovered content = %q, want %q", string(recovered), "sample model weights data")
	}
}

func TestFlowTrainingExecution(t *testing.T) {
	tmpDir := t.TempDir()
	modelDir := filepath.Join(tmpDir, "model")
	inputDir := filepath.Join(tmpDir, "input")
	outputDir := filepath.Join(tmpDir, "output")
	resultDir := filepath.Join(tmpDir, "result")
	_ = os.MkdirAll(modelDir, 0o755)
	_ = os.MkdirAll(inputDir, 0o755)

	// Sample input file
	_ = os.WriteFile(filepath.Join(inputDir, "data.txt"), []byte("data content"), 0o644)

	cfg := runtime.RuntimeConfig{
		Commands: []string{
			"cat <input>/data.txt > <output>/out.txt",
			"echo '{\"accuracy\": 0.99}' > <output>/training_result.json",
		},
	}

	out, err := ExecuteTrainingRun(nil, cfg, nil, modelDir, inputDir, outputDir, resultDir, "task-train-1")
	if err != nil {
		t.Fatalf("ExecuteTrainingRun failed: %v, output=%s", err, out)
	}

	// Verify out.txt was copied to resultDir
	resFile := filepath.Join(resultDir, "out.txt")
	content, err := os.ReadFile(resFile)
	if err != nil {
		t.Fatalf("result file not found in %s: %v", resultDir, err)
	}
	if string(content) != "data content" {
		t.Fatalf("result content = %q, want 'data content'", string(content))
	}
}
