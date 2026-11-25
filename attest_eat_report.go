package pca

import (
	"encoding/json"
	"strconv"
)

// EatEvidenceFromReport projects a parsed SEV-SNP report into the JSON-safe evidence carried in an EAT: version, measurement (hex),
// reported_tcb (a decimal string, so the u64 survives JSON), guest_svn, chip_id (hex) and the debug flag. SEV-SNP has no weights
// field, so no weights evidence is projected.
func EatEvidenceFromReport(report *SevSnpReport) map[string]any {
	return map[string]any{
		"version":      json.Number(strconv.FormatUint(uint64(report.Version), 10)),
		"measurement":  toHexLower(report.Measurement),
		"reported_tcb": strconv.FormatUint(report.ReportedTcb, 10),
		"guest_svn":    json.Number(strconv.FormatUint(uint64(report.GuestSvn), 10)),
		"chip_id":      toHexLower(report.ChipID),
		"debug":        report.Policy&snpPolicyDebugBit != 0,
	}
}

// EatMeasuredFromReport derives the measured identity of a parsed report with the default hardware mapping: runtime_measurement =
// hex(MEASUREMENT), operator = hex(CHIP_ID); SEV-SNP has no model id or weights field, so those are empty and weights_measured is false.
func EatMeasuredFromReport(report *SevSnpReport) MeasuredIdentity {
	return MakeDefaultDeriveIdentity(false)(report)
}
