package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	csvgo "taa/attestation/csv_go"
)

type csvInterfaces interface {
	GetAttestationReportIOCTL(reportBuf, nonce []byte) error
	VerifyAttestationReport(reportBuf []byte, verifyChain bool) error
	GetSealingKeyIOCTL(keyBuf []byte) error
}

type csvClient struct {
	client *csvgo.Client
}

func (c csvClient) GetAttestationReportIOCTL(reportBuf, nonce []byte) error {
	return c.client.GetAttestationReportIOCTL(reportBuf, nonce)
}

func (c csvClient) VerifyAttestationReport(reportBuf []byte, verifyChain bool) error {
	return c.client.VerifyAttestationReport(reportBuf, verifyChain)
}

func (c csvClient) GetSealingKeyIOCTL(keyBuf []byte) error {
	return c.client.GetSealingKeyIOCTL(keyBuf)
}

type smokeConfig struct {
	OutputPath  string
	DevicePath  string
	VerifyChain bool
	Rand        io.Reader
	CSV         csvInterfaces
	Now         func() time.Time
}

type smokeResult struct {
	Status         string       `json:"status"`
	StartedAt      string       `json:"startedAt"`
	FinishedAt     string       `json:"finishedAt"`
	Hostname       string       `json:"hostname"`
	GOOS           string       `json:"goos"`
	GOARCH         string       `json:"goarch"`
	DevicePath     string       `json:"devicePath"`
	VerifyChain    bool         `json:"verifyChain"`
	ReportSize     int          `json:"reportSize"`
	SealingKeySize int          `json:"sealingKeySize"`
	NonceHex       string       `json:"nonceHex"`
	Steps          []stepResult `json:"steps"`
}

type stepResult struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Error    string `json:"error,omitempty"`
	Duration string `json:"duration"`
}

func main() {
	var cfg smokeConfig
	flag.StringVar(&cfg.OutputPath, "out", "csv-go-smoke-result.json", "path to write JSON smoke-test results")
	flag.StringVar(&cfg.DevicePath, "device", "/dev/csv-guest", "CSV guest ioctl device path")
	flag.BoolVar(&cfg.VerifyChain, "verify-chain", false, "verify certificate chain in addition to report signature")
	flag.Parse()

	result, err := runSmoke(context.Background(), cfg)
	if result != nil {
		fmt.Printf("csv_go smoke status: %s\n", result.Status)
		fmt.Printf("result file: %s\n", cfg.OutputPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "csv_go smoke failed: %v\n", err)
		os.Exit(1)
	}
}

func runSmoke(ctx context.Context, cfg smokeConfig) (*smokeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg.OutputPath == "" {
		cfg.OutputPath = "csv-go-smoke-result.json"
	}
	if cfg.DevicePath == "" {
		cfg.DevicePath = "/dev/csv-guest"
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.CSV == nil {
		client := csvgo.NewClient(csvgo.WithDevicePath(cfg.DevicePath), csvgo.WithRand(cfg.Rand))
		cfg.CSV = csvClient{client: client}
	}

	started := cfg.Now()
	hostname, _ := os.Hostname()
	result := &smokeResult{
		Status:         "pass",
		StartedAt:      started.Format(time.RFC3339Nano),
		Hostname:       hostname,
		GOOS:           runtime.GOOS,
		GOARCH:         runtime.GOARCH,
		DevicePath:     cfg.DevicePath,
		VerifyChain:    cfg.VerifyChain,
		ReportSize:     csvgo.ReportSize,
		SealingKeySize: csvgo.SealingKeySize,
	}

	nonce := make([]byte, csvgo.NonceSize)
	if _, err := io.ReadFull(cfg.Rand, nonce); err != nil {
		recordStep(result, "generate_nonce", started, err)
		return finishSmoke(cfg, result, err)
	}
	result.NonceHex = hex.EncodeToString(nonce)

	report := make([]byte, csvgo.ReportSize)
	if err := ctx.Err(); err != nil {
		recordStep(result, "context", started, err)
		return finishSmoke(cfg, result, err)
	}
	if err := timedStep(result, "get_attestation_report_ioctl", cfg.Now, func() error {
		return cfg.CSV.GetAttestationReportIOCTL(report, nonce)
	}); err != nil {
		return finishSmoke(cfg, result, err)
	}

	if !allZero(report[csvgo.OffsetReserved2 : csvgo.OffsetReserved2+csvgo.SealingKeySize]) {
		err := errors.New("reserved2 is not zeroed in returned attestation report")
		recordStep(result, "check_reserved2_zeroed", cfg.Now(), err)
		return finishSmoke(cfg, result, err)
	}
	recordStep(result, "check_reserved2_zeroed", cfg.Now(), nil)

	if err := timedStep(result, "verify_attestation_report", cfg.Now, func() error {
		return cfg.CSV.VerifyAttestationReport(report, cfg.VerifyChain)
	}); err != nil {
		return finishSmoke(cfg, result, err)
	}

	key := make([]byte, csvgo.SealingKeySize)
	if err := timedStep(result, "get_sealing_key_ioctl", cfg.Now, func() error {
		return cfg.CSV.GetSealingKeyIOCTL(key)
	}); err != nil {
		return finishSmoke(cfg, result, err)
	}

	return finishSmoke(cfg, result, nil)
}

func timedStep(result *smokeResult, name string, now func() time.Time, fn func() error) error {
	started := now()
	err := fn()
	recordStep(result, name, started, err)
	return err
}

func recordStep(result *smokeResult, name string, started time.Time, err error) {
	step := stepResult{Name: name, Status: "pass", Duration: time.Since(started).String()}
	if err != nil {
		step.Status = "fail"
		step.Error = err.Error()
		result.Status = "fail"
	}
	result.Steps = append(result.Steps, step)
}

func finishSmoke(cfg smokeConfig, result *smokeResult, runErr error) (*smokeResult, error) {
	result.FinishedAt = cfg.Now().Format(time.RFC3339Nano)
	if runErr != nil {
		result.Status = "fail"
	}
	if err := writeResult(cfg.OutputPath, result); err != nil {
		if runErr != nil {
			return result, fmt.Errorf("%w; write result: %v", runErr, err)
		}
		return result, err
	}
	return result, runErr
}

func writeResult(path string, result *smokeResult) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create result file %q: %w", path, err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("write result file %q: %w", path, err)
	}
	return nil
}

func allZero(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
