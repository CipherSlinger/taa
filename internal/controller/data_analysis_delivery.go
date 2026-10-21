package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"taa/internal/resource"
	pkgerrors "taa/pkg/errors"
)

// Delivery query parameters understood by the data-anaylsis import path. The
// legacy tee/fhe path keeps using dataKeyCipher alone through
// resource.SplitDataKeyCipher; these names are only stripped and decoded when
// the instance type is data-anaylsis.
const (
	deliveryParamDataKeyCipher    = "dataKeyCipher"
	deliveryParamFileName         = "fileName"
	deliveryParamDataResourceCode = "dataResourceCode"
)

// dataAnalysisDelivery is one parsed data-anaylsis import URL.
type dataAnalysisDelivery struct {
	// DownloadURL is the resource link with the delivery parameters stripped.
	DownloadURL string
	// DataKey is the unwrapped SM4 key.
	DataKey []byte
	// FileName is the original upload name, URL-decoded.
	FileName string
	// DataResourceCode is the resource id, URL-decoded; it names the landing
	// subdirectory.
	DataResourceCode string
}

// parseDataAnalysisDelivery splits the delivery parameters out of resourceUrl,
// decodes the two path components, and unwraps the SM2 data key envelope.
//
// All three parameters are mandatory: without the envelope there is nothing to
// decrypt, and without the name and code there is nowhere to land the bytes.
// Every error is a client error and is returned before anything is downloaded.
func (s *TAAState) parseDataAnalysisDelivery(rawURL string) (dataAnalysisDelivery, error) {
	cleanURL, values, err := resource.SplitDeliveryParams(rawURL,
		deliveryParamDataKeyCipher, deliveryParamFileName, deliveryParamDataResourceCode)
	if err != nil {
		return dataAnalysisDelivery{}, err
	}
	for _, name := range []string{deliveryParamDataKeyCipher, deliveryParamFileName, deliveryParamDataResourceCode} {
		if _, ok := values[name]; !ok {
			return dataAnalysisDelivery{}, fmt.Errorf("resourceUrl 缺少 %s 参数", name)
		}
	}

	cleanURL = strings.TrimSpace(cleanURL)
	if cleanURL == "" {
		return dataAnalysisDelivery{}, fmt.Errorf("resourceUrl 缺少下载地址: 剥离下发参数后为空")
	}

	fileName, err := url.QueryUnescape(values[deliveryParamFileName])
	if err != nil {
		return dataAnalysisDelivery{}, fmt.Errorf("fileName URL 解码失败: %w", err)
	}
	code, err := url.QueryUnescape(values[deliveryParamDataResourceCode])
	if err != nil {
		return dataAnalysisDelivery{}, fmt.Errorf("dataResourceCode URL 解码失败: %w", err)
	}
	if err := validateDeliveryPathComponent(deliveryParamFileName, fileName); err != nil {
		return dataAnalysisDelivery{}, err
	}
	if err := validateDeliveryPathComponent(deliveryParamDataResourceCode, code); err != nil {
		return dataAnalysisDelivery{}, err
	}

	dataKey, err := s.unwrapDataKeyCipherHex(values[deliveryParamDataKeyCipher])
	if err != nil {
		return dataAnalysisDelivery{}, err
	}
	return dataAnalysisDelivery{
		DownloadURL:      cleanURL,
		DataKey:          dataKey,
		FileName:         fileName,
		DataResourceCode: code,
	}, nil
}

// validateDeliveryPathComponent accepts a decoded value that names exactly one
// path element. Spaces and non-ASCII characters are legitimate parts of an
// uploaded name, so they are kept; separators, traversal and NUL are not.
func validateDeliveryPathComponent(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s 不能为空", field)
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s 不能为空白", field)
	}
	if value == "." || value == ".." {
		return fmt.Errorf("%s 不能是 %q", field, value)
	}
	if strings.ContainsAny(value, "/\\\x00") {
		return fmt.Errorf("%s 不能包含路径分隔符或 NUL", field)
	}
	if filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return fmt.Errorf("%s 不能是绝对路径", field)
	}
	return nil
}

// handleDataAnalysisImport serves /v1/taa/import on a data-anaylsis instance.
// It downloads the ciphertext, answers 200, and lets the async processor decrypt
// and land it. Validation failures are answered before any state is reserved or
// bandwidth is spent, and do not report to the platform; once a download has
// been attempted, failures are reported through reportRes.
func (s *TAAState) handleDataAnalysisImport(w http.ResponseWriter, req *importRequest, phase int) {
	// evalKeyUrl/evalKeyFileHash belong to the fhe contract; this instance runs
	// neither fhe nor training, so they are ignored rather than refused with the
	// tee-specific message validateFHEFields would produce.
	if req.EvalKeyURL != "" || req.EvalKeyFileHash != "" {
		s.Logs.Add(LogWarn, "import", "data-anaylsis 实例不使用 evalKeyUrl/evalKeyFileHash，已忽略")
	}

	delivery, err := s.parseDataAnalysisDelivery(req.ResourceURL)
	if err != nil {
		s.Logs.Add(LogWarn, "import", "拒绝数据 import 请求: %v", err)
		writeErr(w, http.StatusBadRequest, pkgerrors.Wrap(pkgerrors.CodeInvalidArgument, err.Error(), err))
		return
	}
	req.DataAnalysisFileName = delivery.FileName
	req.DataAnalysisResourceCode = delivery.DataResourceCode

	release, err := s.tryAcquireTask(req.TaskID, req.RequestID, "downloading", false)
	if err != nil {
		s.Logs.Add(LogWarn, "import", "拒绝并发任务请求: %v", err)
		writeErr(w, http.StatusConflict, err)
		return
	}

	s.setCurrentOp("downloading")
	// The delivery URL is logged without the envelope and the path parameters.
	s.Logs.Add(LogInfo, "import", "data-anaylsis: 开始下载资源: %s (fileName=%s, dataResourceCode=%s, phase=%d)",
		delivery.DownloadURL, delivery.FileName, delivery.DataResourceCode, phase)
	ciphertextPath, size, err := s.downloadToTempFile(delivery.DownloadURL)
	if err != nil {
		release()
		s.Logs.Add(LogError, "import", "下载资源失败: %v", err)
		s.reportDataAnalysisResult(*req, 1, err.Error())
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	s.Logs.Add(LogInfo, "import", "data-anaylsis: 下载完成 (%d bytes) -> %s", size, ciphertextPath)

	writeEnvelope(w, http.StatusOK, "数据已接收，处理中", nil, 0)

	reqCopy := *req
	s.runAsyncSafe("processImportedResource", release, func() {
		s.processImportedResource(reqCopy, phase, false, ciphertextPath, delivery.DataKey)
	})
}
