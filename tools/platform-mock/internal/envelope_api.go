package mock

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"taa/internal/platform/envelope"
	"taa/pkg/crypto"
)

// maxOpenResponseBytes bounds the sealed body the open-response route reads. A
// TAA response envelope carries one business JSON object; the ceiling is generous
// enough for the export index and small enough to refuse a stray file upload.
const maxOpenResponseBytes = 8 << 20

// envelopeRequest is the console's seal request. Either both keys are supplied
// (an operator-built envelope) or neither is (seal with the mock's own key
// material, which is what the console itself sends).
type envelopeRequest struct {
	DockerID           string          `json:"dockerId"`
	Plaintext          json.RawMessage `json:"plaintext"`
	PlatformPrivateKey string          `json:"platformPrivateKey"`
	TAAPublicKeyHex    string          `json:"taaPublicKeyHex"`
	Identity           string          `json:"identity"`
}

// cryptoEnvelopeHandler builds the sealed body TAA actually accepts.
//
// The API tester cannot run SM2 in the browser, and TAA rejects every plaintext
// request, so a hand-written curl that is meant to succeed has to carry the
// {dockerId?, cipher, sign} envelope already built. Doing it here reuses the
// same envelope package the mock's own requests use, so the copied command and
// the console are byte-for-byte consistent.
//
// GET returns the key material currently in effect: the platform private key
// the envelope must be signed with and the TAA public key it must be encrypted
// to. POST seals a body with explicit keys, or with the mock's registered key
// when both key fields are empty.
func cryptoEnvelopeHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 GET 或 POST 方法", nil, http.StatusMethodNotAllowed)
		return
	}

	ks := currentPlatformKeys()
	if ks == nil {
		writeEnvelope(w, http.StatusInternalServerError, "平台密钥对不可用", nil, http.StatusInternalServerError)
		return
	}
	dockerID := requestedDockerID(r)

	if r.Method == http.MethodGet {
		privPEM, _, pubHex, err := ks.keyPEMs()
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "读取平台 SM2 密钥对失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"dockerId":             dockerID,
			"platformPrivateKey":   privPEM,
			"platformPublicKeyHex": pubHex,
			"taaPublicKeyHex":      ks.taaPublicHexFor(dockerID),
			"identity":             ks.identityString(),
		}, 0)
		return
	}

	var req envelopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeEnvelope(w, http.StatusBadRequest, "解析 JSON 请求失败: "+err.Error(), nil, http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.DockerID) != "" {
		dockerID = strings.TrimSpace(req.DockerID)
	}
	plaintext, err := envelopePlaintext(req.Plaintext)
	if err != nil {
		writeEnvelope(w, http.StatusBadRequest, err.Error(), nil, http.StatusBadRequest)
		return
	}

	privPEM := strings.TrimSpace(req.PlatformPrivateKey)
	taaHex := strings.TrimSpace(req.TAAPublicKeyHex)
	identity := req.Identity
	usedKeystore := privPEM == "" && taaHex == ""

	// An empty side is filled from the keystore rather than refused: the console
	// prefills both boxes, but a field it could not prefill (an instance that has
	// not registered its key yet) must produce the keystore's diagnostic, and a
	// hand-edited box is easier to understand when the other side still works.
	priv := ks.platformPrivate()
	if privPEM != "" {
		parsed, perr := crypto.ParseSM2PrivateKeyPEM([]byte(privPEM))
		if perr != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 SM2 私钥失败: "+perr.Error(), nil, http.StatusBadRequest)
			return
		}
		priv = parsed
	}
	if priv == nil {
		writeEnvelope(w, http.StatusInternalServerError, "平台 SM2 私钥不可用", nil, http.StatusInternalServerError)
		return
	}
	taaPub := ks.taaPublicFor(dockerID)
	if taaHex != "" {
		parsed, perr := crypto.ParseSM2PublicKeyHex(taaHex)
		if perr != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 TAA 公钥失败: "+perr.Error(), nil, http.StatusBadRequest)
			return
		}
		taaPub = parsed
	}
	if taaPub == nil {
		writeEnvelope(w, http.StatusBadRequest, "无法封装信封: "+noTAAPublicKeyMessage(dockerID), nil, http.StatusBadRequest)
		return
	}
	if identity == "" {
		identity = ks.identityString()
	}
	sealed, err := envelope.SealForPlatform(priv, taaPub, []byte(identity), plaintext)
	if err != nil {
		writeEnvelope(w, http.StatusBadRequest, "封装信封失败: "+err.Error(), nil, http.StatusBadRequest)
		return
	}

	writeEnvelope(w, http.StatusOK, "success", map[string]any{
		"dockerId":     dockerID,
		"body":         string(sealed),
		"size":         len(sealed),
		"identity":     identity,
		"usedKeystore": usedKeystore,
	}, 0)
}

// noTAAPublicKeyMessage names the missing registration in the same words the
// keystore uses, so the console shows one diagnostic regardless of which side
// produced it.
func noTAAPublicKeyMessage(dockerID string) string {
	if dockerID == "" {
		return "尚未注册 TAA 公钥：等 TAA 完成注册后再试"
	}
	return "实例 " + dockerID + " 尚未注册 TAA 公钥：等该实例完成注册后再试"
}

// envelopePlaintext resolves the request's plaintext field. A JSON string is
// taken as the literal bytes TAA will parse; any other JSON value is used as
// its compact encoding, so an object body and a pre-rendered string both work.
func envelopePlaintext(raw json.RawMessage) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, errors.New("缺少待封装请求体 plaintext")
	}
	if trimmed[0] == '"' {
		var text string
		if err := json.Unmarshal(trimmed, &text); err != nil {
			return nil, errors.New("plaintext 字符串解析失败: " + err.Error())
		}
		if strings.TrimSpace(text) == "" {
			return nil, errors.New("待封装请求体为空")
		}
		return []byte(text), nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, trimmed); err != nil {
		return nil, errors.New("plaintext 不是合法 JSON: " + err.Error())
	}
	if compact.Len() == 0 {
		return nil, errors.New("待封装请求体为空")
	}
	return compact.Bytes(), nil
}

// openResponseRequest is the body of POST /api/taa/open-response: the sealed
// response TAA returned, verbatim.
//
// It takes the envelope as the request body itself rather than as a field, so a
// curl command can forward what it saved with --data-binary @file and no jq step
// in between.
type openResponseRequest struct {
	DockerID string `json:"dockerId"`
}

// taOpenResponseHandler unseals a TAA response for a hand-written curl.
//
// TAA seals every JSON response on these routes, so a direct call returns
// {dockerId?, cipher, sign} and the business answer stays inside cipher. The
// browser never sees that shape because the mock's reverse proxy opens it on the
// way back; a command line has no such proxy, so it has to come here.
//
// Verification is the same as on the proxy path - decrypt with the platform
// private key, then verify the signature with the TAA public key registered for
// the instance - and a body that fails either check is refused rather than
// returned. Nothing is trusted because it "looks like" a response.
func taOpenResponseHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	ks := currentPlatformKeys()
	if ks == nil {
		writeEnvelope(w, http.StatusInternalServerError, "平台密钥对不可用", nil, http.StatusInternalServerError)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxOpenResponseBytes+1))
	if err != nil {
		writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
		return
	}
	if len(raw) > maxOpenResponseBytes {
		writeEnvelope(w, http.StatusRequestEntityTooLarge, "请求体过大：这看起来不是 TAA 的单个响应信封", nil, http.StatusRequestEntityTooLarge)
		return
	}
	env, err := envelope.Parse(bytes.TrimSpace(raw))
	if err != nil {
		// Not an envelope at all is the common case here: a plaintext error page,
		// a 405 from a wrong method, or an empty file from a failed call. Those
		// are printed as they are, because they are the whole answer.
		writeOpenResult(w, r, false, strings.TrimSpace(requestedDockerID(r)), strings.TrimSpace(string(raw)), http.StatusOK)
		return
	}

	dockerID := strings.TrimSpace(requestedDockerID(r))
	if dockerID == "" {
		dockerID = strings.TrimSpace(env.DockerID)
	}
	var plaintext []byte
	var openErr error
	if dockerID == "" {
		// A hand-written curl knows neither the instance nor that the response
		// carries no dockerId, so the key is found by trying the registered ones.
		plaintext, dockerID, openErr = ks.openFromTAAResponseWithoutHint(env)
	} else {
		plaintext, openErr = ks.openFromTAAResponseFor(dockerID, env)
	}
	if openErr != nil {
		// A refusal is the answer the operator needs: it says why the response
		// could not be trusted (wrong instance key, wrong SM2 identity, tampered
		// body), which is not something the sealed bytes can convey.
		if isRawOpenResponse(r) {
			writeRawText(w, http.StatusBadRequest, "解封 TAA 响应失败: "+openErr.Error())
			return
		}
		writeEnvelope(w, http.StatusBadRequest, "解封 TAA 响应失败: "+openErr.Error(), nil, http.StatusBadRequest)
		return
	}
	writeOpenResult(w, r, true, dockerID, string(plaintext), http.StatusOK)
}

// isRawOpenResponse reports whether the caller asked for the plaintext alone.
// A generated curl command uses raw so the terminal shows the business JSON
// instead of an envelope wrapper around it; tooling can leave it off and read
// the structured answer.
func isRawOpenResponse(r *http.Request) bool {
	if r == nil || r.URL == nil {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("raw"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func writeOpenResult(w http.ResponseWriter, r *http.Request, sealed bool, dockerID, plaintext string, status int) {
	if isRawOpenResponse(r) {
		writeRawText(w, status, plaintext)
		return
	}
	writeEnvelope(w, status, "success", map[string]any{
		"sealed":    sealed,
		"dockerId":  dockerID,
		"plaintext": plaintext,
		"size":      len(plaintext),
	}, 0)
}

// writeRawText writes the plaintext bytes with a content type that matches what
// they look like, so a terminal shows JSON as JSON and an error page as text.
func writeRawText(w http.ResponseWriter, status int, body string) {
	contentType := "text/plain; charset=utf-8"
	if trimmed := strings.TrimSpace(body); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		contentType = "application/json; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
	if !strings.HasSuffix(body, "\n") {
		_, _ = io.WriteString(w, "\n")
	}
}
