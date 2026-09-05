package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPostRegisterIncludesNewFields(t *testing.T) {
	tmpDir := t.TempDir()
	attestationPath := filepath.Join(tmpDir, "attestation.report")
	originalData := []byte("attestation-body")
	if err := os.WriteFile(attestationPath, originalData, 0o600); err != nil {
		t.Fatalf("write attestation file: %v", err)
	}

	var (
		mu                   sync.Mutex
		gotMethod            string
		gotPath              string
		gotContentTyp        string
		gotDockerID          string
		gotAuthInfoIsNull    bool
		gotTaaPubKey         string
		gotAttestationValues string
		gotTimestamp         string
		gotVerifiedPass      bool
		gotAttBase64         string
		gotHasTeeKey         bool
		gotErr               error
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentTyp = r.Header.Get("Content-Type")
		var payload struct {
			DockerID          string          `json:"dockerId"`
			AuthInfo          json.RawMessage `json:"authInfo"`
			TaaPublicKey      string          `json:"taaPublicKey"`
			AttestationValues string          `json:"attestationValues"`
			Timestamp         string          `json:"timestamp"`
			VerifiedPass      bool            `json:"verifiedPass"`
			Attestation       string          `json:"attestation"`
			TeePublicKey      string          `json:"teePublicKey,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			gotErr = err
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		gotDockerID = payload.DockerID
		gotAuthInfoIsNull = string(payload.AuthInfo) == "null"
		gotTaaPubKey = payload.TaaPublicKey
		gotAttestationValues = payload.AttestationValues
		gotTimestamp = payload.Timestamp
		gotVerifiedPass = payload.VerifiedPass
		gotAttBase64 = payload.Attestation
		gotHasTeeKey = payload.TeePublicKey != ""

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := postRegister(context.Background(), server.Client(), server.URL+registerEndpoint, "docker-1", attestationPath, "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----", "{}", true, 1234567890); err != nil {
		t.Fatalf("postRegister() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if gotErr != nil {
		t.Fatalf("handler error = %v", gotErr)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %s, want %s", gotMethod, http.MethodPost)
	}
	if gotPath != registerEndpoint {
		t.Fatalf("path = %s, want %s", gotPath, registerEndpoint)
	}
	if gotContentTyp != "application/json" {
		t.Fatalf("content-type = %s, want application/json", gotContentTyp)
	}
	if gotDockerID != "docker-1" {
		t.Fatalf("dockerId = %q, want %q", gotDockerID, "docker-1")
	}
	if !gotAuthInfoIsNull {
		t.Fatalf("authInfo is null = %v, want true", gotAuthInfoIsNull)
	}
	if gotTaaPubKey != "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----" {
		t.Fatalf("taaPublicKey = %q", gotTaaPubKey)
	}
	if gotAttestationValues != "{}" {
		t.Fatalf("attestationValues = %s, want {}", gotAttestationValues)
	}
	if gotTimestamp != "1234567890" {
		t.Fatalf("timestamp = %q, want 1234567890", gotTimestamp)
	}
	if !gotVerifiedPass {
		t.Fatal("verifiedPass = false, want true")
	}
	if gotHasTeeKey {
		t.Fatal("teePublicKey should be absent")
	}
	// Verify attestation is Base64 encoded
	decoded, err := base64.StdEncoding.DecodeString(gotAttBase64)
	if err != nil {
		t.Fatalf("decode attestation base64: %v", err)
	}
	if string(decoded) != string(originalData) {
		t.Fatalf("attestation body = %q, want %q", string(decoded), string(originalData))
	}
}

func TestPostRegisterLogsFullRequestOnPlatformError(t *testing.T) {
	tmpDir := t.TempDir()
	attestationPath := filepath.Join(tmpDir, "attestation.report")
	if err := os.WriteFile(attestationPath, []byte("attestation-body"), 0o600); err != nil {
		t.Fatalf("write attestation file: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":1,"msg":"JSON 不合法: invalid character"}`, http.StatusBadRequest)
	}))
	defer server.Close()

	var logs bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldOutput)

	err := postRegister(context.Background(), server.Client(), server.URL+registerEndpoint, "docker-1", attestationPath, "-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----", "{}", true, 1234567890)
	if err == nil {
		t.Fatal("expected platform error")
	}

	logText := logs.String()
	for _, want := range []string{
		"platform register request rejected: status=400",
		"platform register request dump:",
		"POST " + server.URL + registerEndpoint,
		"Content-Type: application/json",
		`"dockerId":"docker-1"`,
		`"authInfo":null`,
		`"taaPublicKey":"-----BEGIN PUBLIC KEY-----\nFAKE\n-----END PUBLIC KEY-----"`,
		`"attestationValues":"{}"`,
		`"timestamp":"1234567890"`,
		`"verifiedPass":true`,
		`"attestation":"` + base64.StdEncoding.EncodeToString([]byte("attestation-body")) + `"`,
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("log does not contain %q:\n%s", want, logText)
		}
	}
}

func TestNoticeRegisterValidation(t *testing.T) {
	tmpDir := t.TempDir()
	attestationPath := filepath.Join(tmpDir, "attestation.report")
	if err := os.WriteFile(attestationPath, []byte("x"), 0o600); err != nil {
		t.Fatalf("write attestation file: %v", err)
	}

	tests := []struct {
		name     string
		platform string
		dockerID string
		file     string
		pubKey   string
		wantErr  string
	}{
		{name: "platform", platform: "", dockerID: "docker-1", file: attestationPath, pubKey: "pub", wantErr: "PLATFORM_IP is required"},
		{name: "docker", platform: "127.0.0.1:65535", dockerID: "", file: attestationPath, pubKey: "pub", wantErr: "DOCKER_ID is required"},
		{name: "attestation", platform: "127.0.0.1:65535", dockerID: "docker-1", file: "", pubKey: "pub", wantErr: "attestation report file is required"},
		{name: "public-key", platform: "127.0.0.1:65535", dockerID: "docker-1", file: attestationPath, pubKey: "", wantErr: "taaPublicKey is required"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := NoticeRegister(context.Background(), tc.platform, tc.dockerID, tc.file, tc.pubKey, 1234567890)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestPostRegisterRejectsMissingFile(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing.report")
	err := postRegister(context.Background(), http.DefaultClient, "http://127.0.0.1:65535", "docker-1", missingPath, "pub", "{}", true, 1234567890)
	if err == nil {
		t.Fatal("expected postRegister to fail for missing attestation file")
	}
	if !strings.Contains(err.Error(), "no such file") && !strings.Contains(err.Error(), "cannot find") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNoticeRegisterFallsBackWhenAttestationValuesExtractionFails(t *testing.T) {
	tmpDir := t.TempDir()
	attestationPath := filepath.Join(tmpDir, "attestation.report")
	if err := os.WriteFile(attestationPath, []byte("short"), 0o600); err != nil {
		t.Fatalf("write attestation file: %v", err)
	}

	var gotPayload struct {
		AttestationValues string `json:"attestationValues"`
		VerifiedPass      bool   `json:"verifiedPass"`
		Attestation       string `json:"attestation"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := NoticeRegister(context.Background(), server.URL, "docker-1", attestationPath, "pub", 1234567890); err != nil {
		t.Fatalf("NoticeRegister() error = %v", err)
	}
	if gotPayload.AttestationValues != "" {
		t.Fatalf("attestationValues = %q, want empty", gotPayload.AttestationValues)
	}
	if gotPayload.VerifiedPass {
		t.Fatal("verifiedPass should be false when report extraction fails")
	}
	if gotPayload.Attestation == "" {
		t.Fatal("attestation should still be sent when the file exists")
	}
}

func TestNoticeRegisterReturnsErrorWhenPlatformUnavailable(t *testing.T) {
	tmpDir := t.TempDir()
	attestationPath := filepath.Join(tmpDir, "attestation.report")
	if err := os.WriteFile(attestationPath, []byte("short"), 0o600); err != nil {
		t.Fatalf("write attestation file: %v", err)
	}

	err := NoticeRegister(context.Background(), "127.0.0.1:65535", "docker-1", attestationPath, "pub", 1234567890)
	if err == nil {
		t.Fatal("expected NoticeRegister to return an error when platform is unavailable")
	}
}
