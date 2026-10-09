package controller

import (
	"encoding/json"

	"taa/internal/codeaudit"
)

func (s *TAAState) setLastAudit(audit *codeaudit.AuditReport) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastAudit = audit
}

func (s *TAAState) getLastAudit() *codeaudit.AuditReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.LastAudit
}

// projectCodeAuditSection selects the audit fields the platform sees. It is not the
// whole AuditReport and never was: `report` is an opaque string on the reportAudit
// wire and a nested object in the training report (internal/runtime/report.go), and
// this is the one place both are built from, so a field left out of this map reaches
// neither.
//
// That selection is why roots is a key here. A merged audit's code describes the
// whole run, so a code=1 no longer says which side failed, and the per-root verdicts
// are the only thing in the payload that does. A breakdown nested under target would
// be dropped by this projection and the platform would be back to inferring the side
// from the file paths inside file_reports -- the inference that gets a two-root
// report misread, and with __init__.py present in both trees, misread wrongly.
func projectCodeAuditSection(audit *codeaudit.AuditReport) map[string]any {
	if audit == nil {
		return nil
	}
	var fileReports any
	if audit.FileReports != nil {
		fileReports = cloneFileReports(audit.FileReports)
	}
	// Copied rather than shared: the caller marshals this payload while the report
	// itself lives on in state, and RootReport is flat, so the copy is the whole of
	// the isolation.
	var roots any
	if audit.Roots != nil {
		roots = append([]codeaudit.RootReport{}, audit.Roots...)
	}
	return map[string]any{
		"conclusion":   audit.Conclusion,
		"file_reports": fileReports,
		"roots":        roots,
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
