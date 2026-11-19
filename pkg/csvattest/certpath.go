package csvattest

import (
	"os"
	"path/filepath"
)

// DefaultCertDirs lists, in order, the directories that may hold the local
// vendor certificate chain. The first is where every packaging path installs
// the pair; the others cover a mounted deployment and a source checkout.
var DefaultCertDirs = []string{"/root/taa/certs", "/etc/taa/certs", "deploy/certs"}

// ResolveLocalCertChain returns explicit hrk.cert and hsk_cek.cert paths from
// the first directory in dirs that contains both files, and whether one was
// found. Explicit paths keep callers from choosing a CertDir, which falls back
// to downloading the chain from the vendor KDS.
func ResolveLocalCertChain(dirs []string) (hrkPath, hskCekPath string, ok bool) {
	for _, dir := range dirs {
		hrkPath := filepath.Join(dir, "hrk.cert")
		hskCekPath := filepath.Join(dir, "hsk_cek.cert")
		if fileExists(hrkPath) && fileExists(hskCekPath) {
			return hrkPath, hskCekPath, true
		}
	}
	return "", "", false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
