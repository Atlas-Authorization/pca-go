package pca

// Replays the compliance reference corpus: AuditEvent normalisation, the control-mapping table, per-framework compliance reports,
// their JSON and Markdown renderers, and the console-activity framework report. A reference throw requires an error.

import "testing"

func TestComplianceReferenceVectors(t *testing.T) {
	siemReplay(t, "ref-compliance.json.gz", map[string]vecFn{
		"constants": func(args []any) (any, error) {
			fws := make([]any, len(ComplianceFrameworks))
			for i, f := range ComplianceFrameworks {
				fws[i] = f
			}
			return map[string]any{"COMPLIANCE_FRAMEWORKS": fws, "CONTROL_MAPPINGS": complianceControlMappings()}, nil
		},
		"controlMappings": func(args []any) (any, error) { return ComplianceControlMappings(vecArg(args, 0), len(args) > 0) },
		"toAuditEvent":    func(args []any) (any, error) { return ComplianceToAuditEvent(vecArg(args, 0)) },
		"toComplianceReport": func(args []any) (any, error) {
			return ComplianceToReport(vecArg(args, 0), vecArg(args, 1))
		},
		"renderJson":     func(args []any) (any, error) { return ComplianceRenderJSON(vecArg(args, 0)) },
		"renderMarkdown": func(args []any) (any, error) { return ComplianceRenderMarkdown(vecArg(args, 0)) },
		"frameworkReport": func(args []any) (any, error) {
			return ComplianceFrameworkReport(vecArg(args, 0), vecArg(args, 1), vecArg(args, 2), len(args) > 2)
		},
		"frameworkReportToMarkdown": func(args []any) (any, error) { return ComplianceFrameworkReportToMarkdown(vecArg(args, 0)) },
	})
}
