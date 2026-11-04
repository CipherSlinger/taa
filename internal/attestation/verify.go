package attestation

import (
	"taa/pkg/csvattest"
)

// VerifyReport checks that the report body was signed by the PEK certificate
// carried inside the report itself.
//
// The HRK/HSK/CEK certificate chain is deliberately not walked. Those
// certificates are issued per machine, so requiring them would bind this binary,
// and the initrd image that carries it, to one device; a report produced on any
// other machine would fail. Without the chain check the verification proves the
// report is self-consistent (the embedded PEK signed it) but not that the PEK
// belongs to a genuine Hygon platform - callers that need that property must
// vouch for the report by other means.
func VerifyReport(reportData []byte) (*csvattest.VerificationResult, error) {
	if len(reportData) < csvattest.ReportSize {
		return nil, csvattest.ErrShortBuffer
	}

	return csvattest.VerifyReportWithOptions(reportData, csvattest.VerifyOptions{VerifyChain: false})
}
