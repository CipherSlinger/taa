package attestation

import (
	"fmt"
	"strings"

	"taa/pkg/csvattest"
)

// VerifyReport verifies an attestation report and its certificate chain using configured certificate paths.
func VerifyReport(reportData []byte, hrkCertPath, hskCekCertPath string) (*csvattest.VerificationResult, error) {
	if len(reportData) < csvattest.ReportSize {
		return nil, csvattest.ErrShortBuffer
	}

	hrk := strings.TrimSpace(hrkCertPath)
	hskCek := strings.TrimSpace(hskCekCertPath)
	if hrk == "" || hskCek == "" {
		return nil, fmt.Errorf("both HRK and HSK/CEK certificate paths must be specified (got hrk=%q, hsk_cek=%q)", hrk, hskCek)
	}

	opts := csvattest.VerifyOptions{
		VerifyChain:    true,
		HRKCertPath:    hrk,
		HSKCekCertPath: hskCek,
	}
	return csvattest.VerifyReportWithOptions(reportData, opts)
}
