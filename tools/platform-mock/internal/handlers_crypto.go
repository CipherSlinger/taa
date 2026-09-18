package mock

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"taa/pkg/crypto"
)

func cryptoGenerateKeyHandler(w http.ResponseWriter, r *http.Request) {
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

	priv, err := crypto.GenerateSM2KeyPair()
	if err != nil {
		writeEnvelope(w, http.StatusInternalServerError, "生成 SM2 密钥对失败: "+err.Error(), nil, http.StatusInternalServerError)
		return
	}
	pubPEM, err := crypto.MarshalSM2PublicKeyPEM(&priv.PublicKey)
	if err != nil {
		writeEnvelope(w, http.StatusInternalServerError, "编码 SM2 公钥失败: "+err.Error(), nil, http.StatusInternalServerError)
		return
	}
	privPEM, err := crypto.MarshalSM2PrivateKeyPEM(priv)
	if err != nil {
		writeEnvelope(w, http.StatusInternalServerError, "编码 SM2 私钥失败: "+err.Error(), nil, http.StatusInternalServerError)
		return
	}

	writeEnvelope(w, http.StatusOK, "success", map[string]string{
		"publicKey":  string(pubPEM),
		"privateKey": string(privPEM),
	}, 0)
}

func cryptoDecryptHandler(w http.ResponseWriter, r *http.Request) {
	setCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeEnvelope(w, http.StatusMethodNotAllowed, "仅支持 POST 方法", nil, http.StatusMethodNotAllowed)
		return
	}

	var (
		privKeyPEM string
		cipherData []byte
	)

	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(128 << 20); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 multipart/form-data 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		privKeyPEM = strings.TrimSpace(r.FormValue("privateKey"))
		file, _, err := r.FormFile("file")
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "获取待解密文件失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			writeEnvelope(w, http.StatusInternalServerError, "读取待解密文件失败: "+err.Error(), nil, http.StatusInternalServerError)
			return
		}
		cipherData = data
	} else if strings.Contains(contentType, "application/json") {
		var req struct {
			PrivateKey string `json:"privateKey"`
			Ciphertext string `json:"ciphertext"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeEnvelope(w, http.StatusBadRequest, "解析 JSON 失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		privKeyPEM = strings.TrimSpace(req.PrivateKey)
		data, err := base64.StdEncoding.DecodeString(req.Ciphertext)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "Base64 解码密文失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		cipherData = data
	} else {
		privKeyPEM = strings.TrimSpace(r.Header.Get("X-Private-Key"))
		if privKeyPEM != "" {
			if decoded, err := base64.StdEncoding.DecodeString(privKeyPEM); err == nil && strings.Contains(string(decoded), "PRIVATE KEY") {
				privKeyPEM = string(decoded)
			}
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			writeEnvelope(w, http.StatusBadRequest, "读取请求体失败: "+err.Error(), nil, http.StatusBadRequest)
			return
		}
		cipherData = data
	}

	if privKeyPEM == "" {
		writeEnvelope(w, http.StatusBadRequest, "缺少 privateKey 参数", nil, http.StatusBadRequest)
		return
	}
	if len(cipherData) == 0 {
		writeEnvelope(w, http.StatusBadRequest, "待解密数据为空", nil, http.StatusBadRequest)
		return
	}

	privKey, err := crypto.ParseSM2PrivateKeyPEM([]byte(privKeyPEM))
	if err != nil {
		writeEnvelope(w, http.StatusBadRequest, "解析 SM2 私钥失败: "+err.Error(), nil, http.StatusBadRequest)
		return
	}

	plainData, err := crypto.OpenSM2SM4GCM(privKey, cipherData)
	if err != nil {
		writeEnvelope(w, http.StatusBadRequest, "SM2+SM4-GCM 解密失败: "+err.Error(), nil, http.StatusBadRequest)
		return
	}

	if strings.Contains(contentType, "application/json") {
		writeEnvelope(w, http.StatusOK, "success", map[string]any{
			"plaintext": base64.StdEncoding.EncodeToString(plainData),
			"size":      len(plainData),
		}, 0)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(plainData)))
	w.WriteHeader(http.StatusOK)
	w.Write(plainData)
}
