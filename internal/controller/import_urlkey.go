package controller

import (
	"encoding/hex"
	"fmt"

	"taa/internal/resource"
	teecrypto "taa/pkg/crypto"
)

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
	// Debugging aid for the delivery protocol: both halves of the envelope are printed
	// so a platform-side wrap can be checked against what TAA actually unwrapped.
	s.Logs.Add(LogInfo, "import", "信封调试: dataKeyCipher=%s -> 数据密钥=%s (%d 字节)",
		dataKeyCipherHex, hex.EncodeToString(dataKey), len(dataKey))
	return downloadURL, dataKey, nil
}
