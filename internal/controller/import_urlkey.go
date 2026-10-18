package controller

import (
	"fmt"
	"regexp"

	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
)

// dataKeyCipherInBody matches a dataKeyCipher query value inside a request body,
// where it travels as part of resourceUrl. The value is the SM2-wrapped data key
// the payload is decrypted with; the delivery contract keeps it out of logs, and
// the request body is logged and reported to the platform.
//
// The value pattern stops at any character that cannot belong to a query
// parameter in a JSON string, so a malformed value is masked too: a value that is
// not hex is not a usable key, but it is still the field the contract says must
// not be logged.
var dataKeyCipherInBody = regexp.MustCompile(`(?i)(dataKeyCipher=)[^&\s"\\]*`)

// redactDataKeyCipher returns a request body safe to log.
func redactDataKeyCipher(body []byte) string {
	return dataKeyCipherInBody.ReplaceAllString(string(body), "${1}<redacted>")
}

// unwrapDataKeyCipherFromURL splits the SM2 data key envelope out of a resource
// delivery URL and unwraps it with TAA's own SM2 private key.
//
// Both resource endpoints (/v1/taa/import and /v1/taa/importModel) accept the same
// delivery shape -- <download link>?dataKeyCipher=<hex C1C3C2> with a
// ciphertext-only body -- so the parse and the unwrap live here instead of being
// repeated per handler.
//
// The returned downloadURL is what must be fetched: the envelope never reaches the
// file server, and every other query parameter is preserved byte-for-byte so a
// signed URL stays valid. dataKey is nil when the URL carries no envelope, which
// leaves the legacy whole-file envelope in charge.
//
// The unwrap happens before the download on purpose: a malformed value or an
// envelope wrapped for another key is answered without pulling the whole payload.
// Every error is a client error (CodeInvalidArgument), and the caller must not
// download when one is returned.
func (s *TAAState) unwrapDataKeyCipherFromURL(rawURL string) (downloadURL string, dataKey []byte, err error) {
	downloadURL, dataKeyCipherHex, hasDataKeyCipher, err := resource.SplitDataKeyCipher(rawURL)
	if err != nil {
		return "", nil, err
	}
	if !hasDataKeyCipher {
		return downloadURL, nil, nil
	}
	wrapped, err := teecrypto.ParseWrappedDataKeyHex(dataKeyCipherHex)
	if err != nil {
		return "", nil, err
	}
	dataKey, err = teecrypto.UnwrapKeySM2(s.SM2PrivateKey, wrapped)
	if err != nil {
		return "", nil, fmt.Errorf("dataKeyCipher 解封失败: %w", err)
	}
	// Neither the envelope nor the unwrapped data key is logged: the delivery
	// contract keeps the dataKeyCipher out of logs, and the key it carries is the
	// one that decrypts the payload.
	return downloadURL, dataKey, nil
}
