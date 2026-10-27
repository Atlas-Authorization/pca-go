package pca

// Intel TDX (DCAP v4, ECDSA-P256): the genuine quote end to end (PCK chain to the pinned Intel SGX Root CA, QE report under
// the PCK leaf, attestation key endorsed by the QE, TD quote signature), the PCA binding in its two modes, and the optional
// Intel PCS collateral (attest_intel_collateral.go). Same checks, order and reason text as the reference verifier.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// intelSGXRootCASpkiSHA256 pins Intel's SGX Provisioning Certification Root CA (SPKI SHA-256, lowercase hex).
const intelSGXRootCASpkiSHA256 = "a0af031289f5d5d4132f9186068a7fc13628633ba235777472e29b6b6c67a49e"

const (
	dcapHeaderLen   = 48
	dcapTdReportLen = 584
	dcapSgxReport   = 384
	dcapQeAttrOff   = 48
	dcapQeRdataOff  = 0x140
)

type dcapQuote struct {
	header, tdReportBody, quoteSignature, akPubRaw []byte
	qeReportBody, qeReportSignature, qeAuthData    []byte
	pckChainPem                                    string
}

func parseDcapQuote(q []byte) (*dcapQuote, error) {
	if len(q) < dcapHeaderLen+dcapTdReportLen+4 {
		return nil, errors.New("parseDcapQuote: too short for header + TD report + sig length")
	}
	le := binary.LittleEndian
	version := int(le.Uint16(q[0:]))
	attKeyType := int(le.Uint16(q[2:]))
	teeType := le.Uint32(q[4:])
	if version != 4 {
		return nil, fmt.Errorf("parseDcapQuote: unsupported quote version %d (expected 4)", version)
	}
	if attKeyType != 2 {
		return nil, fmt.Errorf("parseDcapQuote: unsupported attestation key type %d (expected ECDSA-P256 = 2)", attKeyType)
	}
	if teeType != 0x81 {
		return nil, fmt.Errorf("parseDcapQuote: unexpected TEE type 0x%x (expected TDX = 0x81)", teeType)
	}
	out := &dcapQuote{
		header:       append([]byte{}, q[:dcapHeaderLen]...),
		tdReportBody: append([]byte{}, q[dcapHeaderLen:dcapHeaderLen+dcapTdReportLen]...),
	}
	o := dcapHeaderLen + dcapTdReportLen
	sigDataLen := int(le.Uint32(q[o:]))
	o += 4
	sigEnd := o + sigDataLen
	if sigEnd > len(q) {
		return nil, fmt.Errorf("parseDcapQuote: signature data (%d) overruns the quote", sigDataLen)
	}
	need := func(n int, what string) error {
		if o+n > sigEnd {
			return fmt.Errorf("parseDcapQuote: truncated reading %s", what)
		}
		return nil
	}
	if err := need(64, "quote signature"); err != nil {
		return nil, err
	}
	out.quoteSignature = append([]byte{}, q[o:o+64]...)
	o += 64
	if err := need(64, "attestation public key"); err != nil {
		return nil, err
	}
	out.akPubRaw = append([]byte{}, q[o:o+64]...)
	o += 64
	if err := need(6, "outer cert-data header"); err != nil {
		return nil, err
	}
	outerType := int(le.Uint16(q[o:]))
	outerSize := int(le.Uint32(q[o+2:]))
	o += 6
	if outerType != 6 {
		return nil, fmt.Errorf("parseDcapQuote: outer cert-data type %d (expected QE-report-cert-data = 6)", outerType)
	}
	outerEnd := o + outerSize
	if outerEnd > sigEnd {
		return nil, errors.New("parseDcapQuote: outer cert-data overruns signature data")
	}
	if err := need(dcapSgxReport, "QE report"); err != nil {
		return nil, err
	}
	out.qeReportBody = append([]byte{}, q[o:o+dcapSgxReport]...)
	o += dcapSgxReport
	if err := need(64, "QE report signature"); err != nil {
		return nil, err
	}
	out.qeReportSignature = append([]byte{}, q[o:o+64]...)
	o += 64
	if err := need(2, "QE auth-data size"); err != nil {
		return nil, err
	}
	authSize := int(le.Uint16(q[o:]))
	o += 2
	if err := need(authSize, "QE auth-data"); err != nil {
		return nil, err
	}
	out.qeAuthData = append([]byte{}, q[o:o+authSize]...)
	o += authSize
	if err := need(6, "inner cert-data header"); err != nil {
		return nil, err
	}
	innerType := int(le.Uint16(q[o:]))
	innerSize := int(le.Uint32(q[o+2:]))
	o += 6
	if innerType != 5 {
		return nil, fmt.Errorf("parseDcapQuote: inner cert-data type %d (expected PCK-cert-chain = 5)", innerType)
	}
	if o+innerSize > outerEnd {
		return nil, errors.New("parseDcapQuote: inner cert-data overruns outer cert-data")
	}
	out.pckChainPem = string(q[o : o+innerSize])
	for _, x := range q[sigEnd:] {
		if x != 0 {
			return nil, errors.New("parseDcapQuote: non-zero bytes after the signature data")
		}
	}
	return out, nil
}

// ───────────────────────────────────────────────────────────── the Intel SGX extension (byte scan, as the reference does)

var (
	oidSgxFmspc = []byte{0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04}
	oidSgxTcb   = []byte{0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02}
)

// readDerTlvLenient reads one TLV at off; ok is false on any malformed or overrunning length.
func readDerTlvLenient(buf []byte, off int) (derTlv, bool) {
	if off < 0 || off+2 > len(buf) {
		return derTlv{}, false
	}
	tag := buf[off]
	l := int(buf[off+1])
	p := off + 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || p+n > len(buf) {
			return derTlv{}, false
		}
		l = 0
		for i := 0; i < n; i++ {
			l = l*256 + int(buf[p])
			p++
		}
	}
	end := p + l
	if end > len(buf) {
		return derTlv{}, false
	}
	return derTlv{tag: tag, start: p, end: end}, true
}

func indexOfBytes(hay, needle []byte) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		match := true
		for j := range needle {
			if hay[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

type pckTcb struct {
	fmspc  []byte
	sgx    []byte // 16 SGX TCB component SVNs
	pcesvn int
}

// extractPckFmspcAndTcb reads the FMSPC and the issued TCB from the PCK leaf's Intel SGX extension.
func extractPckFmspcAndTcb(leaf []byte) (*pckTcb, error) {
	fi := indexOfBytes(leaf, oidSgxFmspc)
	if fi < 0 {
		return nil, errors.New("extractPckFmspcAndTcb: FMSPC OID not found in certificate")
	}
	fv, ok := readDerTlvLenient(leaf, fi+len(oidSgxFmspc))
	if !ok || fv.tag != 0x04 || fv.end-fv.start != 6 {
		return nil, errors.New("extractPckFmspcAndTcb: malformed FMSPC OCTET STRING")
	}
	fmspc := append([]byte{}, leaf[fv.start:fv.end]...)
	ti := indexOfBytes(leaf, oidSgxTcb)
	if ti < 0 {
		return nil, errors.New("extractPckFmspcAndTcb: TCB OID not found in certificate")
	}
	seq, ok := readDerTlvLenient(leaf, ti+len(oidSgxTcb))
	if !ok || seq.tag != 0x30 {
		return nil, errors.New("extractPckFmspcAndTcb: malformed TCB SEQUENCE")
	}
	sgx := make([]byte, 16)
	pcesvn := -1
	p := seq.start
	idx := 0
	for p < seq.end {
		pair, ok := readDerTlvLenient(leaf, p)
		if !ok || pair.tag != 0x30 {
			return nil, errors.New("extractPckFmspcAndTcb: malformed TCB component")
		}
		oid, ok := readDerTlvLenient(leaf, pair.start)
		if !ok || oid.tag != 0x06 {
			return nil, errors.New("extractPckFmspcAndTcb: TCB component missing OID")
		}
		val, ok := readDerTlvLenient(leaf, oid.end)
		if !ok {
			return nil, errors.New("extractPckFmspcAndTcb: TCB component missing value")
		}
		last := int(leaf[oid.end-1])
		if val.tag == 0x02 {
			var n uint32
			for b := val.start; b < val.end; b++ {
				n = n<<8 | uint32(leaf[b])
			}
			if last >= 1 && last <= 16 {
				sgx[last-1] = byte(n & 0xff)
			} else if last == 17 {
				pcesvn = int(n & 0xffff)
			}
		}
		p = pair.end
		idx++
		if idx > 64 {
			break
		}
	}
	if pcesvn < 0 {
		return nil, errors.New("extractPckFmspcAndTcb: PCESVN not found in TCB extension")
	}
	return &pckTcb{fmspc: fmspc, sgx: sgx, pcesvn: pcesvn}, nil
}

// ───────────────────────────────────────────────────────────── PCK chain

type pckChainResult struct {
	ok       bool
	reason   string
	validity bool // the failure was a validity-window failure
	leaf     *attCert
	leafKey  *ecdsa.PublicKey
	depth    int
}

// verifyIntelPckChain verifies a PEM chain to the pinned Intel SGX Root CA (every certificate valid at nowMs, every link
// signed, the root self-signed and pinned, CA roles, no unrecognised critical extension, an EC P-256 leaf).
func verifyIntelPckChain(pckChainPem string, pin string, nowMs int64) pckChainResult {
	thrown := func(err error) pckChainResult {
		return pckChainResult{reason: "PCK chain X.509 verification error (fail closed): " + errMsg(err)}
	}
	fail := func(r string) pckChainResult { return pckChainResult{reason: r} }
	blocks := pemCertBlocks(pckChainPem)
	if len(blocks) == 0 {
		return fail("no PEM certificates in the PCK chain")
	}
	certs := make([]*attCert, 0, len(blocks))
	for _, b := range blocks {
		c, err := certFromPEM(b)
		if err != nil {
			return thrown(err)
		}
		certs = append(certs, c)
	}
	issuers := map[string]bool{}
	bySubject := map[string]*attCert{}
	for _, c := range certs {
		issuers[string(c.RawIssuer)] = true
		bySubject[string(c.RawSubject)] = c
	}
	leaf := certs[0]
	for _, c := range certs {
		if !issuers[string(c.RawSubject)] {
			leaf = c
			break
		}
	}
	var ordered []*attCert
	seen := map[string]bool{}
	for cur := leaf; cur != nil && !seen[string(cur.RawSubject)]; {
		ordered = append(ordered, cur)
		seen[string(cur.RawSubject)] = true
		if certSelfIssued(cur) {
			break
		}
		cur = bySubject[string(cur.RawIssuer)]
	}
	root := ordered[len(ordered)-1]
	if !certSelfIssued(root) {
		return fail("PCK chain does not terminate in a self-signed root")
	}
	if len(ordered) != len(certs) {
		return fail("PCK chain is not a single connected path (orphan/duplicate certificates)")
	}
	for _, c := range ordered {
		if !derValidAt(c.Raw, nowMs, 0) {
			return pckChainResult{reason: "PCK chain certificate outside its validity period", validity: true}
		}
	}
	for i := 0; i < len(ordered)-1; i++ {
		child, parent := ordered[i], ordered[i+1]
		if string(child.RawIssuer) != string(parent.RawSubject) {
			return fail(fmt.Sprintf("certificate at depth %d issuer does not match its parent subject", i))
		}
		if !certSigOKBy(child, parent) {
			return fail(fmt.Sprintf("certificate at depth %d is not signed by its issuer", i))
		}
	}
	if !certSigOKBy(root, root) {
		return fail("root certificate is not self-signed")
	}
	rootKey, err := keyOfCert(root)
	if err != nil {
		return thrown(err)
	}
	if rootKey.spkiSHA256() != strings.ToLower(pin) {
		return fail("Intel SGX Root CA does not match the pinned trust anchor")
	}
	ders := make([][]byte, len(ordered))
	for i, c := range ordered {
		ders[i] = c.Raw
	}
	if roleFail := checkChainRoles(ders); roleFail != "" {
		return fail(roleFail)
	}
	for i, d := range ders {
		crit, found, err := unrecognisedCriticalExtension(d, nil)
		if err != nil {
			return thrown(err)
		}
		if found {
			return fail(fmt.Sprintf("PCK chain certificate at depth %d has an unrecognised critical extension %s", i, crit))
		}
	}
	lk, err := keyOfCert(leaf)
	if err != nil {
		return thrown(err)
	}
	if lk.typ != "ec" {
		return fail(fmt.Sprintf("PCK leaf key is not EC (got %s)", lk.typ))
	}
	if _, err := ecPointOfKey(lk, "P-256"); err != nil {
		return thrown(err)
	}
	pub, _ := lk.pub.(*ecdsa.PublicKey)
	return pckChainResult{ok: true, leaf: leaf, leafKey: pub, depth: len(ordered)}
}

// ───────────────────────────────────────────────────────────── genuine quote

type tdxQuotePolicy struct {
	mrtds         []string
	fmspcs        []string
	rtmrs         []string
	mrSeams       []string
	mrSignerSeams []string
	hasMrSeams    bool
	hasMrSigner   bool
	allowDebug    bool
}

type tdxResult struct {
	ok         bool
	reason     string
	reportData []byte
	fmspc      string
	pck        *pckTcb
	mrTd       []byte
}

func verifyP256Compact(msg, sig []byte, pub *ecdsa.PublicKey) bool {
	if len(sig) != 64 {
		return false
	}
	return verifyRawECDSA(pub, sha256Sum(msg), sig)
}

func verifyGenuineTdxQuote(quote []byte, pin string, nowMs int64, pol *tdxQuotePolicy, allowDebugOnly bool) tdxResult {
	bad := func(r string) tdxResult { return tdxResult{reason: r} }
	q, err := parseDcapQuote(quote)
	if err != nil {
		return bad("quote parse failed: " + errMsg(err))
	}
	body := q.tdReportBody
	chain := verifyIntelPckChain(q.pckChainPem, pin, nowMs)
	if !chain.ok || chain.leafKey == nil || chain.leaf == nil {
		return bad("PCK chain invalid: " + chain.reason)
	}
	tcb, err := extractPckFmspcAndTcb(chain.leaf.Raw)
	if err != nil {
		return bad("PCK FMSPC/TCB extraction failed: " + errMsg(err))
	}
	if !verifyP256Compact(q.qeReportBody, q.qeReportSignature, chain.leafKey) {
		return bad("QE report signature does not verify under the PCK leaf")
	}
	if q.qeReportBody[dcapQeAttrOff]&0x02 != 0 {
		return bad("QE report ATTRIBUTES.DEBUG is set (debug quoting enclave)")
	}
	qeReportData := q.qeReportBody[dcapQeRdataOff : dcapQeRdataOff+64]
	akBinding := sha256Sum(append(append([]byte{}, q.akPubRaw...), q.qeAuthData...))
	zero := true
	for _, b := range qeReportData[32:64] {
		if b != 0 {
			zero = false
		}
	}
	if !timingSafeEq(qeReportData[:32], akBinding) || !zero {
		return bad("QE report_data does not bind the attestation key (AK not endorsed by this QE)")
	}
	akPub, ok := pointToKey(elliptic.P256(), append([]byte{0x04}, q.akPubRaw...))
	if !ok {
		return bad("attestation public key is not a valid P-256 point")
	}
	if !verifyP256Compact(append(append([]byte{}, q.header...), body...), q.quoteSignature, akPub) {
		return bad("TD quote signature does not verify under the attestation key")
	}
	allowDebug := allowDebugOnly || (pol != nil && pol.allowDebug)
	if !allowDebug && body[120]&1 != 0 {
		return bad("TD_ATTRIBUTES.DEBUG is set (host can inspect the TD)")
	}
	mrTd := body[136:184]
	fmspcHex := toHexLower(tcb.fmspc)
	if pol != nil {
		if len(pol.mrtds) > 0 && !containsStr(pol.mrtds, toHexLower(mrTd)) {
			return bad("MRTD not in policy allowlist")
		}
		if len(pol.fmspcs) > 0 && !containsStr(pol.fmspcs, fmspcHex) {
			return bad("FMSPC not in policy allowlist")
		}
		if pol.hasMrSeams && !containsStr(pol.mrSeams, toHexLower(body[16:64])) {
			return bad("MRSEAM not in policy allowlist")
		}
		if pol.hasMrSigner && !containsStr(pol.mrSignerSeams, toHexLower(body[64:112])) {
			return bad("MRSIGNERSEAM not in policy allowlist")
		}
		if len(pol.rtmrs) > 0 && !containsStr(pol.rtmrs, toHexLower(body[328:376])) {
			return bad("RTMR0 not in policy allowlist")
		}
	}
	return tdxResult{ok: true, reportData: append([]byte{}, body[520:584]...), fmspc: fmspcHex, pck: tcb, mrTd: append([]byte{}, mrTd...)}
}

// ───────────────────────────────────────────────────────────── the verifier

type dcapVerifier struct {
	binding         string
	pol             tdxQuotePolicy
	pin             string
	allowMissing    bool
	collateralPol   collateralPolicy
	hasCollateralPo bool
}

var tdxHexPattern = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func newDcapVerifier(cfg map[string]any) (*dcapVerifier, error) {
	binding, _ := cfg["binding"].(string)
	if binding != "report-data" && binding != "azure-runtime-data" {
		return nil, errors.New("createIntelDcapVerifier: binding must be 'report-data' or 'azure-runtime-data'")
	}
	pol, _ := cfg["policy"].(map[string]any)
	mr, ok := hexListOf(pol["mrtds"])
	if !ok || len(mr) == 0 {
		return nil, errors.New("createIntelDcapVerifier: policy.mrtds must be a NON-EMPTY allowlist (accept-all is not permitted)")
	}
	mrtds := lowerAll(mr)
	for _, m := range mrtds {
		if !tdxHexPattern.MatchString(m) || len(m) != 96 {
			return nil, errors.New("createIntelDcapVerifier: every MRTD must be 96 hex chars (48 bytes)")
		}
	}
	v := &dcapVerifier{binding: binding}
	v.pol.mrtds = mrtds
	for _, name := range []string{"mrSeams", "mrSignerSeams"} {
		raw, present := pol[name]
		if !present {
			continue
		}
		list, ok := hexListOf(raw)
		if !ok || len(list) == 0 {
			return nil, fmt.Errorf("createIntelDcapVerifier: policy.%s, if given, must be a NON-EMPTY list", name)
		}
		for _, m := range list {
			if !tdxHexPattern.MatchString(m) || len(m) != 96 {
				return nil, fmt.Errorf("createIntelDcapVerifier: every %s entry must be 96 hex chars (48 bytes)", name)
			}
		}
		if name == "mrSeams" {
			v.pol.mrSeams, v.pol.hasMrSeams = lowerAll(list), true
		} else {
			v.pol.mrSignerSeams, v.pol.hasMrSigner = lowerAll(list), true
		}
	}
	if l, ok := hexListOf(pol["fmspcs"]); ok {
		v.pol.fmspcs = lowerAll(l)
	}
	if l, ok := hexListOf(pol["rtmrs"]); ok {
		v.pol.rtmrs = lowerAll(l)
	}
	v.pol.allowDebug = pol["allowDebug"] == true
	v.pin = intelSGXRootCASpkiSHA256
	if p, ok := cfg["trustAnchorRootCaSpkiSha256"].(string); ok {
		v.pin = strings.ToLower(p)
	}
	v.allowMissing = cfg["allowMissingCollateral"] == true
	if cp, ok := pol["collateral"].(map[string]any); ok {
		v.hasCollateralPo = true
		if l, ok := hexListOf(cp["acceptStatuses"]); ok {
			v.collateralPol.acceptStatuses, v.collateralPol.hasAccept = l, true
		}
		if f, ok := asFinite(cp["minTcbEvaluationDataNumber"]); ok {
			v.collateralPol.minEval, v.collateralPol.hasMinEval = f, true
		}
	}
	return v, nil
}

func (v *dcapVerifier) verify(ev map[string]any, expected *AttestationBinding, nowMs int64) HardwareResult {
	quote, ok := evBytes(ev, "quote")
	if ev == nil || !ok {
		return hwFail("no Intel DCAP quote for this action")
	}
	if expected == nil {
		return hwFail("no expected attestation binding supplied")
	}
	q := verifyGenuineTdxQuote(quote, v.pin, nowMs, &v.pol, false)
	if !q.ok {
		return hwFail("DCAP quote invalid: " + q.reason)
	}
	if v.binding == "report-data" {
		want, err := attestationBindingBytes(*expected)
		if err != nil {
			return hwFail("binding not constructible: " + err.Error())
		}
		if !timingSafeEq(q.reportData, want) {
			return hwFail("report_data does not bind holder/grant/epoch/nonce")
		}
	} else {
		rd, ok := evBytes(ev, "runtimeData")
		if !ok {
			return hwFail("azure-runtime-data binding needs the runtime-data JSON bytes")
		}
		if why := checkAzureRuntimeDataBinding(q.reportData, rd, expected); why != "" {
			return hwFail(why)
		}
	}
	host := map[string]string{"attestation_type": "tdx-dcap", "fmspc": q.fmspc}
	if col, ok := ev["collateral"].(map[string]any); ok {
		c := collateralFromWire(col)
		var pol *collateralPolicy
		if v.hasCollateralPo {
			pol = &v.collateralPol
		}
		res := verifyIntelTdxCollateral(quote, c, nowMs, pol, v.pin, v.pol.allowDebug)
		if res.status != "" {
			host["tcb_status"] = res.status
		}
		if len(res.advisoryIDs) > 0 {
			host["advisory_ids"] = strings.Join(res.advisoryIDs, ",")
		}
		if !res.ok {
			r := res.reason
			if r == "" {
				r = "rejected"
			}
			return hwFail("Intel collateral: " + r)
		}
	} else if v.allowMissing {
		host["tcb_status"] = "unevaluated"
	} else {
		return hwFail("Intel PCS collateral required but not supplied (set allowMissingCollateral to opt out explicitly)")
	}
	return HardwareResult{OK: true, Bound: true, Measured: newMeasured(toHexLower(q.mrTd), ""), HostAsserted: host}
}
