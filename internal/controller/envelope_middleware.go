package controller

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"taa/internal/platform/envelope"
)

// maxEnvelopeBytes bounds the on-the-wire request body. cipher carries base64
// of the original JSON, so it is about a third larger than the plaintext the
// handler used to read; the bound is set well above any request these routes
// carry so that it only ever stops abuse, never legitimate traffic.
const maxEnvelopeBytes = 8 << 20

// envelopeWriter carries the envelope session to writeJSON. It exists because
// http.ResponseWriter has no Context(): the request side travels in the request
// context, the response side has to travel in the writer.
type envelopeWriter struct {
	http.ResponseWriter
	sess *envelope.Keys
}

// envelopeMiddleware turns the sealed request into the plaintext one the
// handlers already know, and marks the writer so every JSON response on this
// request is sealed on the way out.
//
// The order is the whole point: decrypt, verify the signature over the
// decrypted bytes, and only then let the handler see a body. A request that
// does not open never reaches business logic, so no handler needs to know the
// envelope exists.
func (s *TAAState) envelopeMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		keys := s.envelopeKeys()
		if keys == nil {
			// Only reachable on a hand-built state: startup refuses to run
			// without the platform public key. There is nothing to seal with, so
			// the honest answer is an unsealable 500 rather than a plaintext
			// business response.
			http.Error(w, "envelope key material is not configured", http.StatusInternalServerError)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxEnvelopeBytes+1))
		if err != nil {
			writeSealedError(keys, w, http.StatusBadRequest, "读取请求体失败")
			return
		}
		if len(body) > maxEnvelopeBytes {
			writeSealedError(keys, w, http.StatusRequestEntityTooLarge, "请求体过大")
			return
		}

		env, err := envelope.Parse(body)
		if err != nil {
			// Distinguishing "not an envelope" from "an envelope that failed to
			// open" is useful while the platform is being migrated, but both are
			// rejections: there is no plaintext path in.
			writeSealedError(keys, w, http.StatusBadRequest, "请求缺少 cipher/sign")
			return
		}

		plaintext, err := keys.Open(env)
		if err != nil {
			writeSealedError(keys, w, http.StatusUnauthorized, "请求解密或验签失败")
			return
		}

		r.Body = io.NopCloser(bytes.NewReader(plaintext))
		r.ContentLength = int64(len(plaintext))
		next(&envelopeWriter{ResponseWriter: w, sess: keys}, r)
	}
}

// writeSealedError answers with the same apiResponse shape and, crucially, the
// same sealed format as every other response. It builds a throwaway writer
// because the rejection happens before a session exists; constructing one here
// keeps a single sealing path instead of a second, divergent one.
func writeSealedError(keys *envelope.Keys, w http.ResponseWriter, status int, msg string) {
	ew := &envelopeWriter{ResponseWriter: w, sess: keys}
	writeError(ew, status, msg)
}

// writeSealedJSON is the sealing half of writeJSON. It returns false when the
// writer is not on an envelope path, so writeJSON can fall through to the
// original plaintext behaviour for fheCallback.
//
// Marshalling with json.Marshal instead of json.NewEncoder(w).Encode is
// deliberate: the signed bytes must be exactly the bytes the platform decrypts,
// and Encode appends a newline that would be part of the signed plaintext but
// invisible in any JSON view of it.
func writeSealedJSON(w http.ResponseWriter, status int, resp apiResponse) bool {
	ew, ok := w.(*envelopeWriter)
	if !ok {
		return false
	}

	plain, err := json.Marshal(resp)
	if err == nil {
		var sealed []byte
		sealed, err = ew.sess.Seal(plain, "")
		if err == nil {
			ew.Header().Set("Content-Type", "application/json; charset=utf-8")
			ew.WriteHeader(status)
			_, _ = ew.Write(sealed)
			return true
		}
	}

	// Sealing failed: a TAA-side fault such as an unusable public key. Returning
	// the response in plaintext would leak the business data the envelope exists
	// to protect, so this fails loudly instead.
	http.Error(ew.ResponseWriter, "response envelope failed", http.StatusInternalServerError)
	return true
}
