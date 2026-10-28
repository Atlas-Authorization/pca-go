package pca

// AMD SEV-SNP: genuine ATTESTATION_REPORT verification (ECDSA-P384 report signature under the VCEK, VCEK -> ASK -> ARK chain
// to the pinned ARK of the configured family, VCEK <-> report binding, policy) with the same checks, order and reason text
// as the reference verifier. Classical (ECDSA-P384 / RSA-PSS); no network I/O.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// amdARKSpkiSHA384 holds the SPKI SHA-384 (lowercase hex) of each family's ARK, as published by AMD's key distribution service.
var amdARKSpkiSHA384 = map[string]string{
	"milan": "1249f67f15cf229a4069195e1a9ce537d1765ef706a1f4a123c36be9518786515d25ecc007f366b564d2b3f31c48082e",
	"genoa": "32ab53a6ce5ec14926207396e5c475ae768a6a9831b7e860b5acf2e1c1dff222bc5a8bfc43eb5e06393189c1f246d880",
	"turin": "3475f08a9727f8ac9a1deaea5f2a2097aa59d64d05c2a678c229c873e6359d3a6926287a2a22cd5f88a385e333a2fcc5",
}

// ATTESTATION_REPORT layout (AMD SEV-SNP ABI): offsets, all integers little-endian.
const (
	snpOffVersion       = 0x000
	snpOffGuestSvn      = 0x004
	snpOffPolicy        = 0x008
	snpOffVmpl          = 0x030
	snpOffSigAlgo       = 0x034
	snpOffReportData    = 0x050
	snpOffMeasurement   = 0x090
	snpOffHostData      = 0x0c0
	snpOffReportedTcb   = 0x180
	snpOffChipID        = 0x1a0
	snpOffCommittedTcb  = 0x1e0
	snpOffLaunchTcb     = 0x1f0
	snpOffSignedEnd     = 0x2a0
	snpOffSigR          = 0x2a0
	snpOffSigS          = 0x2e8
	snpReportLen        = 0x4a0
	snpPolicyDebugBit   = uint64(1) << 19
	snpSigAlgoECDSAP384 = 1
)

type snpReport struct {
	guestSvn     uint32
	policy       uint64
	vmpl         uint32
	sigAlgo      uint32
	reportedTcb  uint64
	committedTcb uint64
	launchTcb    uint64
	reportData   []byte
	measurement  []byte
	hostData     []byte
	chipID       []byte
	signed       []byte
	sigR, sigS   []byte
}

func parseSnpReport(b []byte) (*snpReport, error) {
	minLen := snpOffSigS + 72
	if len(b) < minLen {
		return nil, fmt.Errorf("parseSevSnpReport: report too short (%d < %d)", len(b), minLen)
	}
	le := binary.LittleEndian
	return &snpReport{
		guestSvn:     le.Uint32(b[snpOffGuestSvn:]),
		policy:       le.Uint64(b[snpOffPolicy:]),
		vmpl:         le.Uint32(b[snpOffVmpl:]),
		sigAlgo:      le.Uint32(b[snpOffSigAlgo:]),
		reportedTcb:  le.Uint64(b[snpOffReportedTcb:]),
		committedTcb: le.Uint64(b[snpOffCommittedTcb:]),
		launchTcb:    le.Uint64(b[snpOffLaunchTcb:]),
		reportData:   append([]byte{}, b[snpOffReportData:snpOffReportData+64]...),
		measurement:  append([]byte{}, b[snpOffMeasurement:snpOffMeasurement+48]...),
		hostData:     append([]byte{}, b[snpOffHostData:snpOffHostData+32]...),
		chipID:       append([]byte{}, b[snpOffChipID:snpOffChipID+64]...),
		signed:       append([]byte{}, b[:snpOffSignedEnd]...),
		sigR:         append([]byte{}, b[snpOffSigR:snpOffSigR+72]...),
		sigS:         append([]byte{}, b[snpOffSigS:snpOffSigS+72]...),
	}, nil
}

func leToBig(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i := range le {
		be[len(le)-1-i] = le[i]
	}
	return new(big.Int).SetBytes(be)
}

// verifySnpReportSignature: ECDSA-P384 / SHA-384 over the signed region under the VCEK; AMD stores r and s little-endian.
func verifySnpReportSignature(r *snpReport, pub *ecdsa.PublicKey) bool {
	n := elliptic.P384().Params().N
	rr, ss := leToBig(r.sigR), leToBig(r.sigS)
	if rr.Sign() <= 0 || rr.Cmp(n) >= 0 || ss.Sign() <= 0 || ss.Cmp(n) >= 0 {
		return false
	}
	return ecdsa.Verify(pub, sha384Sum(r.signed), rr, ss)
}

const (
	amdOIDHWID    = "1.3.6.1.4.1.3704.1.4"
	amdOIDBlSPL   = "1.3.6.1.4.1.3704.1.3.1"
	amdOIDTeeSPL  = "1.3.6.1.4.1.3704.1.3.2"
	amdOIDSnpSPL  = "1.3.6.1.4.1.3704.1.3.3"
	amdOIDUcodeSP = "1.3.6.1.4.1.3704.1.3.8"
	amdHWIDLen    = 64
)

// decodeSpl decodes an SPL extension value: one minimal DER INTEGER 0..255. The failure text, or "".
func decodeSpl(v []byte) (int, string) {
	if len(v) < 3 || v[0] != 0x02 {
		return 0, "is not a DER INTEGER"
	}
	l := int(v[1])
	if l < 1 || l > 2 || len(v) != 2+l {
		return 0, "has a wrong-length INTEGER"
	}
	c0 := v[2]
	if c0&0x80 != 0 {
		return 0, "is negative"
	}
	if l == 2 {
		if c0 != 0x00 {
			return 0, "is out of range (> 255)"
		}
		if v[3]&0x80 == 0 {
			return 0, "is a non-minimal INTEGER"
		}
		return int(v[3]), ""
	}
	return int(c0), ""
}

// checkVcekReportBinding binds the VCEK body to the report: hwID == chip_id and the four SPLs == the REPORTED_TCB bytes.
func checkVcekReportBinding(vcekTbs []byte, r *snpReport) string {
	exts, err := parseTbsExtensions(vcekTbs)
	if err != nil {
		return "VCEK extensions malformed: " + errMsg(err)
	}
	hw, ok := exts.get(amdOIDHWID)
	if !ok {
		return "VCEK certificate has no CHIP_ID (hwID) extension"
	}
	if hw.critical {
		return "VCEK CHIP_ID (hwID) extension is marked critical (the AMD profile is non-critical)"
	}
	if len(hw.value) != amdHWIDLen {
		return fmt.Sprintf("VCEK CHIP_ID (hwID) extension is %d bytes, expected %d", len(hw.value), amdHWIDLen)
	}
	if !timingSafeEq(hw.value, r.chipID) {
		return "VCEK CHIP_ID does not match report chip_id"
	}
	byteAt := func(i uint) int { return int((r.reportedTcb >> (8 * i)) & 0xff) }
	pairs := []struct {
		oid  string
		name string
		want int
	}{
		{amdOIDBlSPL, "bootloader", byteAt(0)},
		{amdOIDTeeSPL, "tee", byteAt(1)},
		{amdOIDSnpSPL, "snp", byteAt(6)},
		{amdOIDUcodeSP, "microcode", byteAt(7)},
	}
	for _, p := range pairs {
		ext, ok := exts.get(p.oid)
		if !ok {
			return fmt.Sprintf("VCEK certificate has no %s SPL extension", p.name)
		}
		if ext.critical {
			return fmt.Sprintf("VCEK %s SPL extension is marked critical (the AMD profile is non-critical)", p.name)
		}
		got, why := decodeSpl(ext.value)
		if why != "" {
			return fmt.Sprintf("VCEK %s SPL extension %s", p.name, why)
		}
		if got != p.want {
			return fmt.Sprintf("VCEK %s SPL %d does not match report reported_tcb (%d) — TCB downgrade?", p.name, got, p.want)
		}
	}
	return ""
}

// verifyAmdCertChain verifies VCEK -> ASK -> ARK with the ARK pinned. It returns the failure reason, or the VCEK key and tbs.
func verifyAmdCertChain(vcekDer []byte, askArkPem string, pin string, nowMs int64, clockSkew any) (string, *ecdsa.PublicKey, []byte) {
	thrown := func(err error) (string, *ecdsa.PublicKey, []byte) {
		return "AMD chain verification error: " + errMsg(err), nil, nil
	}
	fail := func(r string) (string, *ecdsa.PublicKey, []byte) { return r, nil, nil }
	skew := 0.0
	if !isNil(clockSkew) {
		f, ok := asFinite(clockSkew)
		if !ok || f < 0 {
			return fail("clockSkewMs must be a non-negative number")
		}
		skew = f
	}
	vcek, err := parseCertDER(vcekDer)
	if err != nil {
		return thrown(err)
	}
	pems := pemCertBlocks(askArkPem)
	if len(pems) != 2 {
		return fail("ASK+ARK chain must contain exactly two certificates (ASK then ARK)")
	}
	ask, err := certFromPEM(pems[0])
	if err != nil {
		return thrown(err)
	}
	ark, err := certFromPEM(pems[1])
	if err != nil {
		return thrown(err)
	}
	if !certSelfIssued(ark) || !certSigOKBy(ark, ark) {
		return fail("second certificate of the chain is not a self-signed ARK (chain out of order?)")
	}
	if certSelfIssued(ask) {
		return fail("first certificate of the chain is self-signed, not an ASK (chain out of order?)")
	}
	if string(ask.RawSubject) != string(vcek.RawIssuer) {
		return fail("ASK subject does not match the VCEK issuer")
	}
	arkKey, err := keyOfCert(ark)
	if err != nil {
		return thrown(err)
	}
	if arkKey.spkiSHA384() != strings.ToLower(pin) {
		return fail("ARK does not match the pinned AMD trust anchor")
	}
	if string(ask.RawIssuer) != string(ark.RawSubject) || !certSigOKBy(ask, ark) {
		return fail("ASK is not signed by ARK")
	}
	if !certSigOKBy(vcek, ask) {
		return fail("VCEK is not signed by ASK")
	}

	labels := []string{"VCEK", "ASK", "ARK"}
	ders := [][]byte{vcekDer, ask.Raw, ark.Raw}
	if roleErr := checkChainRoles(ders); roleErr != "" {
		return fail("AMD chain role check failed: " + roleErr)
	}
	for i, der := range ders {
		label := labels[i]
		exts, err := parseCertExtensions(der)
		if err != nil {
			return thrown(err)
		}
		for _, oid := range exts.oids {
			if exts.m[oid].critical && !recognisedCriticalExtensions[oid] {
				return fail(fmt.Sprintf("%s certificate has an unrecognised critical extension %s", label, oid))
			}
		}
		if label != "VCEK" {
			if bc, ok := exts.get("2.5.29.19"); !ok || !bc.critical {
				return fail(fmt.Sprintf("%s certificate BasicConstraints is not marked critical", label))
			}
		}
		from, to := derValidity(der)
		if !from.ok || !to.ok {
			return fail(fmt.Sprintf("%s certificate validity is unparseable", label))
		}
		if float64(nowMs)+skew < float64(from.ms) {
			return fail(fmt.Sprintf("%s certificate is not yet valid", label))
		}
		if float64(nowMs)-skew > float64(to.ms) {
			return fail(fmt.Sprintf("%s certificate has expired", label))
		}
	}

	vk, err := keyOfCert(vcek)
	if err != nil {
		return thrown(err)
	}
	if vk.typ != "ec" || vk.curve != "secp384r1" {
		curve := vk.curve
		if curve == "" {
			curve = "undefined"
		}
		return thrown(fmt.Errorf("VCEK is not EC secp384r1 (got %s/%s)", vk.typ, curve))
	}
	if _, err := ecPointOfKey(vk, "P-384"); err != nil {
		return thrown(err)
	}
	tbs, err := tbsOfCertificate(vcekDer)
	if err != nil {
		return thrown(err)
	}
	pub, _ := vk.pub.(*ecdsa.PublicKey)
	return "", pub, tbs
}

// ───────────────────────────────────────────────────────────── policy

type snpPolicy struct {
	measurements     []string
	hostData         []string
	chipIDs          []string
	allowDebug       bool
	requireEcdsaP384 bool
	minGuestSvn      *float64
	minReportedTcb   *big.Int
	minCommittedTcb  *big.Int
	minLaunchTcb     *big.Int
	requireVmpl      any // nil (default 0), "any", or a number
}

func (p *snpPolicy) check(r *snpReport) string {
	if p.requireEcdsaP384 && r.sigAlgo != snpSigAlgoECDSAP384 {
		return fmt.Sprintf("unexpected signature_algo %d", r.sigAlgo)
	}
	if !p.allowDebug && r.policy&snpPolicyDebugBit != 0 {
		return "guest policy has the DEBUG bit set (host can inspect the guest)"
	}
	if p.minGuestSvn != nil && float64(r.guestSvn) < *p.minGuestSvn {
		return fmt.Sprintf("guest_svn %d below minimum %s", r.guestSvn, jsNumString(*p.minGuestSvn))
	}
	u := func(v uint64) *big.Int { return new(big.Int).SetUint64(v) }
	if p.minReportedTcb != nil && u(r.reportedTcb).Cmp(p.minReportedTcb) < 0 {
		return "reported_tcb below minimum (rollback?)"
	}
	if p.minCommittedTcb != nil && u(r.committedTcb).Cmp(p.minCommittedTcb) < 0 {
		return "committed_tcb below minimum (rollback?)"
	}
	if p.minLaunchTcb != nil && u(r.launchTcb).Cmp(p.minLaunchTcb) < 0 {
		return "launch_tcb below minimum"
	}
	switch want := p.requireVmpl.(type) {
	case nil:
		if r.vmpl != 0 {
			return fmt.Sprintf("vmpl %d is not the required 0", r.vmpl)
		}
	case string:
		if want != "any" {
			return fmt.Sprintf("vmpl %d is not the required %s", r.vmpl, want)
		}
	default:
		f, ok := asFinite(want)
		if !ok || float64(r.vmpl) != f {
			return fmt.Sprintf("vmpl %d is not the required %s", r.vmpl, jsAnyString(want))
		}
	}
	if len(p.measurements) > 0 && !containsStr(p.measurements, toHexLower(r.measurement)) {
		return "measurement not in policy allowlist"
	}
	if len(p.hostData) > 0 && !containsStr(p.hostData, toHexLower(r.hostData)) {
		return "host_data not in policy allowlist"
	}
	if len(p.chipIDs) > 0 && !containsStr(p.chipIDs, toHexLower(r.chipID)) {
		return "chip_id not in policy allowlist"
	}
	return ""
}

func jsAnyString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	}
	if f, ok := asFinite(v); ok {
		return jsNumString(f)
	}
	return fmt.Sprint(v)
}

// parseJSBigInt is BigInt(v) for a JSON value; the error text is the reference's.
func parseJSBigInt(v any) (*big.Int, error) {
	switch t := v.(type) {
	case nil:
		return nil, errors.New("Cannot convert null to a BigInt")
	case bool:
		if t {
			return big.NewInt(1), nil
		}
		return new(big.Int), nil
	case string:
		s := jsTrim(t)
		if s == "" {
			return new(big.Int), nil
		}
		base := 10
		body := s
		if len(s) > 2 && s[0] == '0' {
			switch s[1] {
			case 'x', 'X':
				base, body = 16, s[2:]
			case 'o', 'O':
				base, body = 8, s[2:]
			case 'b', 'B':
				base, body = 2, s[2:]
			}
		}
		if base == 10 || (body != "" && body[0] != '+' && body[0] != '-') {
			if n, ok := new(big.Int).SetString(body, base); ok {
				return n, nil
			}
		}
		return nil, fmt.Errorf("Cannot convert %s to a BigInt", t)
	case json.Number:
		f, ok := asFinite(t)
		if !ok || f != math.Trunc(f) {
			return nil, fmt.Errorf("The number %s cannot be converted to a BigInt because it is not an integer", string(t))
		}
		if n, ok := new(big.Int).SetString(string(t), 10); ok {
			return n, nil
		}
		bf := new(big.Float).SetFloat64(f)
		n, _ := bf.Int(nil)
		return n, nil
	}
	return nil, errors.New("Cannot convert value to a BigInt")
}

// ───────────────────────────────────────────────────────────── the verifier

type amdVerifier struct {
	family  string
	pin     string
	binding string
	policy  snpPolicy
	skew    any
}

func hexListOf(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

func newAmdVerifier(cfg map[string]any) (*amdVerifier, error) {
	pol, _ := cfg["policy"].(map[string]any)
	if pol == nil {
		pol = map[string]any{}
	}
	// the wire config carries the u64 floors as decimal strings: converted before the constructor runs
	p := snpPolicy{requireEcdsaP384: pol["requireEcdsaP384"] != false, allowDebug: pol["allowDebug"] == true, requireVmpl: pol["requireVmpl"]}
	for _, f := range []struct {
		key string
		dst **big.Int
	}{{"minReportedTcb", &p.minReportedTcb}, {"minCommittedTcb", &p.minCommittedTcb}, {"minLaunchTcb", &p.minLaunchTcb}} {
		if v, present := pol[f.key]; present {
			n, err := parseJSBigInt(v)
			if err != nil {
				return nil, err
			}
			*f.dst = n
		}
	}
	family, _ := cfg["family"].(string)
	pin, known := amdARKSpkiSHA384[family]
	if !known {
		return nil, errors.New("createAmdSnpVerifier: family must be 'milan' | 'genoa' | 'turin'")
	}
	if o, ok := cfg["trustAnchorArkSpkiSha384"].(string); ok { // conformance harness only: replaces the built-in pin
		pin = o
	}
	binding, _ := cfg["binding"].(string)
	if binding != "report-data" && binding != "azure-runtime-data" {
		return nil, errors.New("createAmdSnpVerifier: binding must be 'report-data' or 'azure-runtime-data'")
	}
	ms, ok := hexListOf(pol["measurements"])
	if !ok || len(ms) == 0 {
		return nil, errors.New("createAmdSnpVerifier: policy.measurements must be a NON-EMPTY allowlist (accept-all is not permitted)")
	}
	p.measurements = lowerAll(ms)
	if l, ok := hexListOf(pol["hostData"]); ok {
		p.hostData = lowerAll(l)
	}
	if l, ok := hexListOf(pol["chipIds"]); ok {
		p.chipIDs = lowerAll(l)
	}
	if v, ok := asFinite(pol["minGuestSvn"]); ok {
		p.minGuestSvn = &v
	}
	return &amdVerifier{family: family, pin: pin, binding: binding, policy: p, skew: cfg["clockSkewMs"]}, nil
}

func evBytes(ev map[string]any, key string) ([]byte, bool) {
	s, ok := ev[key].(string)
	if !ok {
		return nil, false
	}
	return nodeB64(s), true
}

func evString(ev map[string]any, key string) (string, bool) {
	s, ok := ev[key].(string)
	return s, ok
}

// verifySnpReport is verifyGenuineSevSnpReport: the failure reason, or the parsed report.
func (v *amdVerifier) verifyReport(raw, vcekDer []byte, askArkPem string, nowMs int64, expected *AttestationBinding) (string, *snpReport) {
	rep, err := parseSnpReport(raw)
	if err != nil {
		return "report parse failed: " + errMsg(err), nil
	}
	if len(raw) != snpReportLen {
		return fmt.Sprintf("report length %d is not the canonical %d", len(raw), snpReportLen), nil
	}
	nonZero := func(b []byte) bool {
		for _, x := range b {
			if x != 0 {
				return true
			}
		}
		return false
	}
	if nonZero(raw[snpOffSigS+72:]) || nonZero(raw[snpOffSigR+48:snpOffSigR+72]) || nonZero(raw[snpOffSigS+48:snpOffSigS+72]) {
		return "report signature block has non-zero reserved bytes", nil
	}
	reason, vcekKey, vcekTbs := verifyAmdCertChain(vcekDer, askArkPem, v.pin, nowMs, v.skew)
	if reason != "" || vcekKey == nil || vcekTbs == nil {
		return "cert chain invalid: " + reason, nil
	}
	if !verifySnpReportSignature(rep, vcekKey) {
		return "report signature does not verify under VCEK", nil
	}
	if bindErr := checkVcekReportBinding(vcekTbs, rep); bindErr != "" {
		return bindErr, nil
	}
	if expected != nil {
		want, err := attestationBindingBytes(*expected)
		if err != nil {
			return "genuine verification error (fail closed): " + err.Error(), nil
		}
		if !timingSafeEq(want, rep.reportData) {
			return "report_data does not bind holder/grant/epoch/nonce", nil
		}
	}
	if pol := v.policy.check(rep); pol != "" {
		return pol, nil
	}
	return "", rep
}

func (v *amdVerifier) verify(ev map[string]any, expected *AttestationBinding, nowMs int64) HardwareResult {
	report, okR := evBytes(ev, "report")
	vcek, okV := evBytes(ev, "vcekDer")
	askArk, okA := evString(ev, "askArkPem")
	if ev == nil || !okR || !okV || !okA {
		return hwFail("no AMD SEV-SNP evidence for this action")
	}
	if expected == nil {
		return hwFail("no expected attestation binding supplied")
	}
	direct := v.binding == "report-data"
	var bindArg *AttestationBinding
	if direct {
		bindArg = expected
	}
	reason, rep := v.verifyReport(report, vcek, askArk, nowMs, bindArg)
	if rep == nil {
		return hwFail("SEV-SNP report invalid: " + reason)
	}
	if !direct {
		rd, ok := evBytes(ev, "runtimeData")
		if !ok {
			return hwFail("azure-runtime-data binding needs the runtime-data JSON bytes")
		}
		if why := checkAzureRuntimeDataBinding(rep.reportData, rd, expected); why != "" {
			return hwFail(why)
		}
	}
	return HardwareResult{
		OK: true, Bound: true,
		Measured:     newMeasured(toHexLower(rep.measurement), toHexLower(rep.chipID)),
		HostAsserted: map[string]string{"attestation_type": "amd-sev-snp", "family": v.family, "measurement": toHexLower(rep.measurement)},
	}
}
