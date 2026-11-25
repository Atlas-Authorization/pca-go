package pca

// The public forms of the attestation helpers whose signatures use the lane's internal types. The aliases make the types nameable
// and the wrappers forward to the unexported implementation unchanged. Certificates cross the boundary as *NodeCert.

// DcapQuote is a parsed Intel DCAP TD quote.
type DcapQuote = dcapQuote

// PckTcb is the FMSPC and TCB read from a PCK leaf.
type PckTcb = pckTcb

// SpdmReport is a parsed NVIDIA SPDM measurement report.
type SpdmReport = spdmReport

// VerifiedRim is an NVIDIA reference-integrity manifest whose signature and chain verified.
type VerifiedRim = verifiedRim

// NvidiaRimIds names the RIM files that belong to one SPDM report.
type NvidiaRimIds = nvidiaRimIDs

// CertRoleInfo is the basicConstraints / keyUsage view of one certificate.
type CertRoleInfo = certRoleInfo

// CertExtensionTable is the extension list of one certificate in encounter order.
type CertExtensionTable = extTable

// IntelCollateral is the Intel PCS collateral bundle of one TDX quote.
type IntelCollateral = intelCollateral

// CollateralPolicy is the TCB status acceptance policy applied to Intel collateral.
type CollateralPolicy = collateralPolicy

// TdxQuotePolicy is the measurement policy of a genuine TDX quote check.
type TdxQuotePolicy = tdxQuotePolicy

// NvidiaCollateralHook is the post-verification RIM / CRL / OCSP check of the NVIDIA verifier.
type NvidiaCollateralHook = nvidiaHook

// CollateralResult is the outcome of VerifyIntelTdxCollateral.
type CollateralResult struct {
	Ok          bool
	Reason      string
	Status      string
	AdvisoryIDs []string
	// Set whenever the evaluation completed (Status != ""), also when the policy then refuses the status.
	PlatformStatus, TdxModuleStatus, QeStatus string
	TcbEvaluationDataNumber                   float64 // the smaller of the two documents' numbers
	Fmspc                                     string
}

// TdxQuoteResult is the outcome of VerifyGenuineTdxQuote.
type TdxQuoteResult struct {
	Ok         bool
	Reason     string
	ReportData []byte
	Fmspc      string
	Pck        *PckTcb
	MrTd       []byte
	Report     *DcapTdReport // the parsed TD report (Ok only)
	AkPoint    []byte        // the attestation key, uncompressed SEC1 (Ok only)
	ChainDepth int           // the PCK chain length (Ok only)
}

// OcspResult is the outcome of VerifyNvidiaOcspResponse (Status is good, revoked or unknown).
type OcspResult struct {
	Ok     bool
	Reason string
	Status string
}

// ParseNodeCertPEM parses the first certificate of a PEM text.
func ParseNodeCertPEM(text string) (*NodeCert, error) {
	c, err := certFromPEM(text)
	if err != nil {
		return nil, err
	}
	return &NodeCert{c}, nil
}

func attCerts(chain []*NodeCert) []*attCert {
	out := make([]*attCert, len(chain))
	for i, c := range chain {
		out[i] = c.c
	}
	return out
}

func nodeCerts(chain []*attCert) []*NodeCert {
	out := make([]*NodeCert, len(chain))
	for i, c := range chain {
		out[i] = &NodeCert{c}
	}
	return out
}

// VerifyCrl verifies a DER CRL under the issuer certificate's key at nowMs: the revoked serials (lowercase hex, no leading zeros)
// or the failure reason.
func VerifyCrl(der []byte, issuer *NodeCert, nowMs int64) (map[string]bool, string) {
	k, err := keyOfCert(issuer.c)
	if err != nil {
		return nil, "CRL issuer key unreadable: " + errMsg(err)
	}
	return verifyCRL(der, k, nowMs)
}

// SerialIsRevoked reports whether the serial (hex, any case, leading zeros ignored) is in a revoked set from VerifyCrl.
func SerialIsRevoked(revoked map[string]bool, serialHex string) bool {
	return revoked[normSerial(serialHex)]
}

// VerifySignedJson verifies an Intel PCS signed document and returns the body under name, or the failure text.
func VerifySignedJson(text, name string, signer *NodeCert) (map[string]any, string) {
	k, err := keyOfCert(signer.c)
	if err != nil {
		return nil, "signer key unreadable: " + errMsg(err)
	}
	return verifySignedJSON(text, name, k)
}

// VerifyIntelTdxCollateral checks a TDX quote against its Intel collateral (TCB info, QE identity, CRLs) pinned to pin.
func VerifyIntelTdxCollateral(quote []byte, c *IntelCollateral, nowMs int64, pol *CollateralPolicy, pin string, allowDebug bool) CollateralResult {
	r := verifyIntelTdxCollateral(quote, c, nowMs, pol, pin, allowDebug)
	return CollateralResult{Ok: r.ok, Reason: r.reason, Status: r.status, AdvisoryIDs: r.advisoryIDs, PlatformStatus: r.platform, TdxModuleStatus: r.module,
		QeStatus: r.qe, TcbEvaluationDataNumber: r.evalNum, Fmspc: r.fmspc}
}

// IntelCollateralFromWire reads the collateral of an evidence object (tcbInfoJson, pckCrlDer ...).
func IntelCollateralFromWire(m map[string]any) *IntelCollateral { return collateralFromWire(m) }

// NewCollateralPolicy builds the acceptance policy: nil acceptStatuses is the default (UpToDate, SWHardeningNeeded) and nil
// minTcbEvaluationDataNumber means no floor.
func NewCollateralPolicy(acceptStatuses []string, minTcbEvaluationDataNumber *float64) *CollateralPolicy {
	p := &collateralPolicy{acceptStatuses: acceptStatuses, hasAccept: acceptStatuses != nil}
	if minTcbEvaluationDataNumber != nil {
		p.minEval, p.hasMinEval = *minTcbEvaluationDataNumber, true
	}
	return p
}

// ParseDcapQuote parses an Intel DCAP TD quote (v4, ECDSA-P256 signature block).
func ParseDcapQuote(q []byte) (*DcapQuote, error) { return parseDcapQuote(q) }

// ExtractPckFmspcAndTcb reads the FMSPC and the issued TCB from a PCK leaf certificate (DER).
func ExtractPckFmspcAndTcb(leaf []byte) (*PckTcb, error) { return extractPckFmspcAndTcb(leaf) }

// VerifyGenuineTdxQuote verifies a TDX quote's PCK chain, signatures and policy under the pinned Intel root; allowDebugOnly accepts
// debug TDs.
func VerifyGenuineTdxQuote(quote []byte, pin string, nowMs int64, pol *TdxQuotePolicy, allowDebugOnly bool) TdxQuoteResult {
	return VerifyGenuineTdxQuoteBound(quote, pin, nowMs, pol, nil, allowDebugOnly)
}

// VerifyGenuineTdxQuoteBound is VerifyGenuineTdxQuote with the optional PCA binding (holder, grant, epoch, nonce) that the TD
// report_data must carry; a nil expected checks no binding.
func VerifyGenuineTdxQuoteBound(quote []byte, pin string, nowMs int64, pol *TdxQuotePolicy, expected *AttestationBinding, allowDebugOnly bool) TdxQuoteResult {
	r := verifyGenuineTdxQuoteExpected(quote, pin, nowMs, pol, allowDebugOnly, expected)
	out := TdxQuoteResult{Ok: r.ok, Reason: r.reason, ReportData: r.reportData, Fmspc: r.fmspc, Pck: r.pck, MrTd: r.mrTd}
	if r.ok {
		out.Report, _ = ParseDcapTdReport(r.body)
		out.AkPoint, _ = ecPointOfKey(keyInfoOf(r.akPub, nil), "P-256")
		out.ChainDepth = r.depth
	}
	return out
}

// ParseNvidiaSpdmEvidence parses an SPDM GET_MEASUREMENTS response with its signature.
func ParseNvidiaSpdmEvidence(b []byte) (*SpdmReport, error) { return parseNvidiaSpdmEvidence(b) }

// VerifyNvidiaSpdmSignature reports whether the device leaf's ECDSA P-384 key signed the report's transcript.
func VerifyNvidiaSpdmSignature(rep *SpdmReport, leaf *NodeCert) bool {
	return nvidiaReportSigned(leaf.c, rep.signedBytes, rep.signature)
}

// VerifyNvidiaDeviceChain verifies a PEM device chain (leaf first) against the pinned root SPKI SHA-256 values: the chain, or the
// failure reason.
func VerifyNvidiaDeviceChain(pemText string, pins []string, nowMs int64) ([]*NodeCert, string) {
	ch, why := verifyNvidiaDeviceChain(pemText, pins, nowMs)
	if why != "" {
		return nil, why
	}
	return nodeCerts(ch), ""
}

// VerifyNvidiaRim verifies a signed NVIDIA RIM document against the pinned root SPKI SHA-256 values.
func VerifyNvidiaRim(xml string, rimPins []string, nowMs int64) (*VerifiedRim, string) {
	return verifyNvidiaRim(xml, rimPins, nowMs)
}

// NvidiaRimIdsForReport names the driver and VBIOS RIMs of a report (nil when its opaque data does not say).
func NvidiaRimIdsForReport(rep *SpdmReport) *NvidiaRimIds { return nvidiaRimIDsForReport(rep) }

// CompareReportToRims checks the report's runtime measurements against the golden RIM values: "" when they agree.
func CompareReportToRims(rep *SpdmReport, driver, vbios *VerifiedRim) string {
	return compareReportToRims(rep, driver, vbios)
}

// CheckNvidiaChainRevocation checks a device chain against CRLs; requireFor is optional (see the flagship's requireCrlFor).
// "" when it holds.
func CheckNvidiaChainRevocation(chain []*NodeCert, crls [][]byte, nowMs int64, requireIssuers []string, requireFor ...any) string {
	return checkNvidiaChainRevocation(attCerts(chain), crls, nowMs, requireIssuers, requireFor...)
}

// VerifyNvidiaOcspResponse verifies one DER OCSP response for cert (issued by issuer, chain is the device chain).
func VerifyNvidiaOcspResponse(der []byte, cert, issuer *NodeCert, chain []*NodeCert, nowMs int64) OcspResult {
	r := verifyNvidiaOcspResponse(der, cert.c, issuer.c, attCerts(chain), nowMs)
	return OcspResult{Ok: r.ok, Reason: r.reason, Status: r.status}
}

// CheckNvidiaChainOcsp checks one OCSP response per chain certificate; "" when every certificate is good.
func CheckNvidiaChainOcsp(chain []*NodeCert, responses [][]byte, nowMs int64) string {
	return checkNvidiaChainOcsp(attCerts(chain), responses, nowMs)
}

// NewNvidiaCollateralHook builds the collateral hook from its options (rimRootSpkiSha256, firmware, revocation, requireCrls,
// requireCrlIssuers, requireCrlFor).
func NewNvidiaCollateralHook(opts map[string]any) (*NvidiaCollateralHook, error) {
	return newNvidiaHook(opts)
}

// RunNvidiaCollateralHook runs the hook over one report and its verified chain with the evidence's collateral bundle (nil: none
// supplied): the failure reason, or "" when the collateral holds.
func RunNvidiaCollateralHook(h *NvidiaCollateralHook, rep *SpdmReport, chain []*NodeCert, nowMs int64, collateral map[string]any) string {
	return h.withBundle(collateral).run(rep, attCerts(chain), nowMs)
}

// ParseCertExtensions lists the extensions of one certificate (DER) in encounter order.
func ParseCertExtensions(cert []byte) (*CertExtensionTable, error) { return parseCertExtensions(cert) }

// ParseTbsExtensions lists the extensions of one tbsCertificate (DER).
func ParseTbsExtensions(tbsDer []byte) (*CertExtensionTable, error) {
	return parseTbsExtensions(tbsDer)
}

// ReadCertRoleInfo reads basicConstraints and keyUsage from one certificate (DER).
func ReadCertRoleInfo(cert []byte) (CertRoleInfo, error) { return readCertRoleInfo(cert) }

// StrictChainError applies the strict chain checks (roles, path length, critical extensions) to a leaf-first chain: "" when it holds.
func StrictChainError(chain []*NodeCert) string { return strictChainError(attCerts(chain)) }

// CheckVcekReportBinding checks that the VCEK certificate's TBS carries the report's chip id and TCB: "" when it does.
func CheckVcekReportBinding(vcekTbs, report []byte) string {
	r, err := parseSnpReport(report)
	if err != nil {
		return errMsg(err)
	}
	return checkVcekReportBinding(vcekTbs, r)
}
