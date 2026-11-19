package attestation

import (
	"fmt"
	"strings"

	"taa/pkg/csvattest"
)

// certificateChainDirs lists, in order, where VerifyReport looks for the
// vendor chain. The packaging paths install it under /root/taa/certs; the
// other entries cover a mounted deployment and a source checkout. It is a
// variable so tests can point it at a fixture directory.
var certificateChainDirs = csvattest.DefaultCertDirs

// VerifyReport checks that the report was signed by its embedded PEK and that
// the PEK is anchored in the vendor chain found by certificateChainPaths.
//
// A report that verifies without the chain proves only that its own PEK signed
// the following bytes; anchoring is what ties it to a genuine platform. The
// certificates are per machine, so a deployment must install its own pair;
// when none is found the signature check still runs and the missing chain is
// returned as the error, which callers report as verifiedPass=false.
func VerifyReport(reportData []byte) (*csvattest.VerificationResult, error) {
	if len(reportData) < csvattest.ReportSize {
		return nil, csvattest.ErrShortBuffer
	}

	hrkPath, hskCekPath, chainErr := certificateChainPaths()
	// csvattest verifies the PEK signature before the chain, so a forged report
	// is still reported as forged when the chain is missing. VerifyChain is
	// false only in that case, which keeps the whole check to one pass.
	res, err := csvattest.VerifyReportWithOptions(reportData, csvattest.VerifyOptions{
		VerifyChain:    chainErr == nil,
		HRKCertPath:    hrkPath,
		HSKCekCertPath: hskCekPath,
	})
	if err != nil {
		return res, err
	}
	if chainErr != nil {
		return res, chainErr
	}
	return res, nil
}

// certificateChainPaths returns the first complete pair in certificateChainDirs.
//
// The paths are explicit rather than a CertDir so csvattest reads exactly
// these files instead of falling back to a vendor KDS download on the boot path.
func certificateChainPaths() (string, string, error) {
	hrkPath, hskCekPath, ok := csvattest.ResolveLocalCertChain(certificateChainDirs)
	if !ok {
		return "", "", fmt.Errorf(
			"attestation certificate chain not found: expected hrk.cert and hsk_cek.cert in one of %s",
			strings.Join(certificateChainDirs, ", "))
	}
	return hrkPath, hskCekPath, nil
}
