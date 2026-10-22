package controller

import (
	"encoding/json"

	"taa/internal/codeaudit"
)

// setLastAudit records the latest audit result. It is generation-gated so a
// superseded audit cannot overwrite the result of the audit that replaced it.
func (s *TAAState) setLastAudit(gen uint64, audit *codeaudit.AuditReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.auditGen != gen {
		return
	}
	s.LastAudit = audit
}

func (s *TAAState) getLastAudit() *codeaudit.AuditReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastAudit
}

func projectCodeAuditSection(audit *codeaudit.AuditReport) map[string]any {
	if audit == nil {
		return nil
	}
	var fileReports any
	if audit.FileReports != nil {
		fileReports = cloneFileReports(audit.FileReports)
	}
	return map[string]any{
		"conclusion":   audit.Conclusion,
		"file_reports": fileReports,
		// The whole audit's wall-clock time, measured by GenerateAuditReport from
		// the start of the static scan through the LLM phases. Lifted out of
		// scan_metadata because that struct does not leave the process; without
		// this the platform has no way to see how long an audit took.
		"duration_ms": audit.ScanMetadata.ScanDurationMs,
	}
}

func cloneFileReports(src []codeaudit.FileReport) []codeaudit.FileReport {
	if src == nil {
		return nil
	}
	out := make([]codeaudit.FileReport, len(src))
	for i := range src {
		out[i] = src[i]
		if src[i].Findings != nil {
			out[i].Findings = append([]codeaudit.Finding{}, src[i].Findings...)
		}
	}
	return out
}

func auditReportJSON(audit *codeaudit.AuditReport) string {
	payload := projectCodeAuditSection(audit)
	if payload == nil {
		return ""
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(data)
}
