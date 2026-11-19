package attestation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"taa/pkg/csvattest"
)

// CertificateChainDirs lists, in order, the directories searched for the
// Hygon vendor certificate chain (hrk.cert and hsk_cek.cert) that anchors the
// attestation report passed to VerifyReport.
//
// The first entry is where every packaging path installs the files: deploy.sh
// copies them into the TAA image and the remote container, build-initrd.sh
// into the guest rootfs, and deploy-llm.sh into the TEE-LLM Pod. The remaining
// entries cover a process started from a checkout (the repository's
// deploy/certs fixtures) and a deployment that mounts the chain under /etc.
//
// It is a variable so tests can point it at a fixture directory.
var CertificateChainDirs = []string{
	"/root/taa/certs",
	"/etc/taa/certs",
	"deploy/certs",
}

// VerifyReport checks that the report body was signed by the PEK certificate it
// carries, and that the certificate chain HRK -> HSK/CEK -> PEK anchors that
// PEK to the vendor root in CertificateChainDirs.
//
// The chain is required. A report that verifies without it proves only that the
// embedded PEK signed the immediately following bytes, which anyone who can
// write the report can produce; anchoring it is what makes the verdict say the
// report came from a genuine Hygon platform. The certificates are per machine,
// so a deployment on another machine must carry its own pair in one of the
// searched directories; when none is found VerifyReport fails rather than
// falling back to the weaker signature-only check, and the caller reports
// verifiedPass=false.
func VerifyReport(reportData []byte) (*csvattest.VerificationResult, error) {
	if len(reportData) < csvattest.ReportSize {
		return nil, csvattest.ErrShortBuffer
	}

	// Verify the report signature first so a corrupted or tampered report is
	// reported as such even when no certificate chain is installed.
	res, err := csvattest.VerifyReportWithOptions(reportData, csvattest.VerifyOptions{VerifyChain: false})
	if err != nil {
		return res, err
	}

	hrkPath, hskCekPath, err := CertificateChainPaths()
	if err != nil {
		return res, err
	}

	return csvattest.VerifyReportWithOptions(reportData, csvattest.VerifyOptions{
		VerifyChain:    true,
		HRKCertPath:    hrkPath,
		HSKCekCertPath: hskCekPath,
	})
}

// CertificateChainPaths returns the first complete hrk.cert / hsk_cek.cert
// pair found in CertificateChainDirs.
//
// An explicit pair of paths is returned rather than a directory so that
// csvattest reads exactly these files: giving it no paths would make it fall
// back to downloading the chain from the vendor KDS, which the boot path must
// not depend on.
func CertificateChainPaths() (string, string, error) {
	for _, dir := range CertificateChainDirs {
		hrkPath := filepath.Join(dir, "hrk.cert")
		hskCekPath := filepath.Join(dir, "hsk_cek.cert")
		if fileExists(hrkPath) && fileExists(hskCekPath) {
			return hrkPath, hskCekPath, nil
		}
	}
	return "", "", fmt.Errorf(
		"attestation certificate chain not found: expected hrk.cert and hsk_cek.cert in one of %s",
		strings.Join(CertificateChainDirs, ", "))
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
