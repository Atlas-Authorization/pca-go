package pca

// NVIDIA GPU confidential-computing attestation (Hopper / Blackwell): the SPDM 1.1 GET_MEASUREMENTS transcript signed by
// the GPU's device-identity key, the device certificate chain pinned to the NVIDIA Device Identity CA, the PCA challenge
// bound through the SPDM request nonce, pinned measurement blocks, and the optional collateral hook (signed RIMs, CRLs, OCSP
// and a firmware policy: attest_nvidia_rim.go, attest_nvidia_ocsp.go). Same checks, order and reason text as the reference
// verifier. Classical (ECDSA-P384 / SHA-384); no network I/O.

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	spdmReqLen   = 37
	spdmNonceLen = 32
	spdmSigLen   = 96
	nvidiaMaxChn = 5

	nvOpaqueDriverVersion = 3
	nvOpaqueVbiosVersion  = 6
	nvOpaqueChipInfo      = 35
)

type spdmMeasurement struct {
	index  int
	digest []byte
}

type spdmReport struct {
	requestNonce []byte
	measurements []spdmMeasurement
	opaque       map[int][]byte
	signature    []byte
	signedBytes  []byte
}

func le16(b []byte, o int) int { return int(b[o]) | int(b[o+1])<<8 }

// parseNvidiaSpdmEvidence parses a request||response transcript; it fails on any structural problem.
func parseNvidiaSpdmEvidence(b []byte) (*spdmReport, error) {
	if len(b) < spdmReqLen+8+spdmNonceLen+2+spdmSigLen {
		return nil, fmt.Errorf("parseNvidiaSpdmEvidence: transcript too short (%d)", len(b))
	}
	if b[1] != 0xe0 {
		return nil, fmt.Errorf("parseNvidiaSpdmEvidence: request code 0x%x is not GET_MEASUREMENTS", b[1])
	}
	rep := &spdmReport{requestNonce: append([]byte{}, b[4:4+spdmNonceLen]...), opaque: map[int][]byte{}}
	r := b[spdmReqLen:]
	if r[1] != 0x60 {
		return nil, errors.New("parseNvidiaSpdmEvidence: response code is not MEASUREMENTS")
	}
	numBlocks := int(r[4])
	recLen := int(r[5]) | int(r[6])<<8 | int(r[7])<<16
	o := 8
	if o+recLen+spdmNonceLen+2+spdmSigLen > len(r) {
		return nil, errors.New("parseNvidiaSpdmEvidence: measurement record length overruns transcript")
	}
	recEnd := o + recLen
	for o < recEnd {
		if o+4 > recEnd {
			return nil, errors.New("parseNvidiaSpdmEvidence: truncated measurement block header")
		}
		index := int(r[o])
		size := le16(r, o+2)
		bodyStart := o + 4
		if bodyStart+size > recEnd || size < 3 {
			return nil, errors.New("parseNvidiaSpdmEvidence: measurement block overruns record")
		}
		vsize := le16(r, bodyStart+1)
		if 3+vsize > size {
			return nil, errors.New("parseNvidiaSpdmEvidence: DMTF value overruns measurement block")
		}
		rep.measurements = append(rep.measurements, spdmMeasurement{index: index, digest: append([]byte{}, r[bodyStart+3:bodyStart+3+vsize]...)})
		o = bodyStart + size
	}
	if len(rep.measurements) != numBlocks {
		return nil, fmt.Errorf("parseNvidiaSpdmEvidence: header says %d blocks, parsed %d", numBlocks, len(rep.measurements))
	}
	o += spdmNonceLen
	opaqueLen := le16(r, o)
	o += 2
	if o+opaqueLen+spdmSigLen != len(r) {
		return nil, errors.New("parseNvidiaSpdmEvidence: opaque length + signature do not exactly fill the transcript")
	}
	opaqueEnd := o + opaqueLen
	for o < opaqueEnd {
		if o+4 > opaqueEnd {
			return nil, errors.New("parseNvidiaSpdmEvidence: truncated opaque TLV header")
		}
		t := le16(r, o)
		l := le16(r, o+2)
		o += 4
		if o+l > opaqueEnd {
			return nil, errors.New("parseNvidiaSpdmEvidence: opaque TLV overruns opaque data")
		}
		rep.opaque[t] = append([]byte{}, r[o:o+l]...)
		o += l
	}
	rep.signature = append([]byte{}, r[len(r)-spdmSigLen:]...)
	rep.signedBytes = append([]byte{}, b[:len(b)-spdmSigLen]...)
	return rep, nil
}

// jsSlice is String.prototype.slice for a byte string (negative indices count from the end).
func jsSlice(s string, from, to int) string {
	n := len(s)
	norm := func(i int) int {
		if i < 0 {
			i += n
			if i < 0 {
				i = 0
			}
		}
		if i > n {
			i = n
		}
		return i
	}
	a, b := norm(from), norm(to)
	if a >= b {
		return ""
	}
	return s[a:b]
}

// formatVbiosVersion is NVIDIA's VBIOS version rendering: byte-reverse, re-pair as dotted hex ("96.00.9f.00.04").
func formatVbiosVersion(raw []byte) string {
	rev := make([]byte, len(raw))
	for i := range raw {
		rev[len(raw)-1-i] = raw[i]
	}
	hx := toHexLower(rev)
	half := len(hx) / 2
	temp := jsSlice(hx, half, len(hx)) + jsSlice(hx, half-2, half)
	var parts []string
	for i := 0; i < len(temp); i += 2 {
		end := i + 2
		if end > len(temp) {
			end = len(temp)
		}
		parts = append(parts, temp[i:end])
	}
	return strings.Join(parts, ".")
}

// certIsCA is Node's X509Certificate.ca: BasicConstraints CA:TRUE, and keyCertSign when keyUsage is present.
func certIsCA(c *attCert) bool {
	info, err := readCertRoleInfo(c.Raw)
	if err != nil {
		return false
	}
	return info.hasBasicConstraints && info.ca && (!info.hasKeyUsage || info.keyCertSign)
}

func subjectLine(c *attCert) string {
	return strings.ReplaceAll(nameText(c.RawSubject), "\n", ", ")
}

// verifyNvidiaDeviceChain verifies the device chain (leaf first): every link signed, every issuer a CA, every certificate valid at
// nowMs, an ECDSA P-384 key throughout, the root self-signed and pinned by SPKI SHA-256.
func verifyNvidiaDeviceChain(pemText string, pins []string, nowMs int64) ([]*attCert, string) {
	blocks := pemCertBlocks(pemText)
	if len(blocks) == 0 {
		return nil, "device chain unparseable: parsePemChain: no certificates found"
	}
	if len(blocks) > nvidiaMaxChn {
		return nil, fmt.Sprintf("device chain unparseable: parsePemChain: chain longer than %d", nvidiaMaxChn)
	}
	chain := make([]*attCert, 0, len(blocks))
	for _, b := range blocks {
		c, err := certFromPEM(b)
		if err != nil {
			return nil, "device chain unparseable: " + errMsg(err)
		}
		chain = append(chain, c)
	}
	for i, c := range chain {
		if !derValidAt(c.Raw, nowMs, 0) {
			return nil, fmt.Sprintf("device chain cert #%d is outside its validity window", i)
		}
		k, err := keyOfCert(c)
		if err != nil || k.typ != "ec" || k.curve != "secp384r1" {
			return nil, fmt.Sprintf("device chain cert #%d is not an ECDSA P-384 key", i)
		}
	}
	for i := 0; i < len(chain)-1; i++ {
		issuer := chain[i+1]
		if !certIsCA(issuer) {
			return nil, fmt.Sprintf("device chain cert #%d issues a certificate but is not a CA", i+1)
		}
		if !certSigOKBy(chain[i], issuer) {
			return nil, fmt.Sprintf("device chain link #%d signature does not verify under its issuer", i)
		}
	}
	root := chain[len(chain)-1]
	if !certIsCA(root) || !certSigOKBy(root, root) {
		return nil, "device chain root is not a self-signed CA"
	}
	rk, err := keyOfCert(root)
	if err != nil {
		return nil, "device chain root is not a self-signed CA"
	}
	pinned := false
	for _, p := range pins {
		if strings.ToLower(p) == rk.spkiSHA256() {
			pinned = true
		}
	}
	if !pinned {
		return nil, "chain root is not a pinned NVIDIA root"
	}
	return chain, ""
}

// ───────────────────────────────────────────────────────────── the verifier

type nvidiaVerifier struct {
	pins    []string
	want    []nvMeasurement
	leafSub string
	hook    *nvidiaHook
	hasHook bool
}

type nvMeasurement struct {
	index  int
	digest string
}

// jsNumberFromString is Number(s) for a measurement-block key.
func jsNumberFromString(s string) (float64, bool) {
	t := jsTrim(s)
	if t == "" {
		return 0, true
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

func newNvidiaVerifier(cfg map[string]any) (*nvidiaVerifier, error) {
	v := &nvidiaVerifier{}
	var hook *nvidiaHook
	if col, ok := cfg["collateral"].(map[string]any); ok {
		h, err := newNvidiaHook(col)
		if err != nil {
			return nil, err
		}
		hook = h
	}
	pins, ok := asStrList(cfg["rootSpkiSha256"])
	if !ok || len(pins) == 0 {
		return nil, errors.New("createNvidiaSpdmVerifier: rootSpkiSha256 must pin at least one NVIDIA root (accept-all is not permitted)")
	}
	v.pins = pins
	pol, _ := cfg["policy"].(map[string]any)
	meas, _ := pol["measurements"].(map[string]any)
	if len(meas) == 0 && hook == nil {
		return nil, errors.New("createNvidiaSpdmVerifier: policy.measurements must be a NON-EMPTY pinned set unless a postVerify collateral hook supplies reference values (accept-all is not permitted)")
	}
	type entry struct {
		key string
		idx float64
		num bool
		dig string
	}
	var entries []entry
	for k, d := range meas {
		f, ok := jsNumberFromString(k)
		entries = append(entries, entry{key: k, idx: f, num: ok, dig: strings.ToLower(jsAnyString(d))})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].idx != entries[j].idx {
			return entries[i].idx < entries[j].idx
		}
		return entries[i].key < entries[j].key
	})
	for _, e := range entries {
		if !e.num || e.idx != math.Trunc(e.idx) || e.idx < 0 || e.idx > 255 {
			return nil, errors.New("createNvidiaSpdmVerifier: measurement index out of range")
		}
		v.want = append(v.want, nvMeasurement{index: int(e.idx), digest: e.dig})
	}
	v.leafSub, _ = pol["leafSubjectIncludes"].(string)
	v.hook = hook
	v.hasHook = hook != nil
	return v, nil
}

func (v *nvidiaVerifier) verify(ev map[string]any, expected *AttestationBinding, nowMs int64) HardwareResult {
	evidence, okE := evBytes(ev, "evidence")
	chainPem, okC := evString(ev, "certChainPem")
	if ev == nil || !okE || !okC {
		return hwFail("no NVIDIA GPU evidence for this action")
	}
	chain, why := verifyNvidiaDeviceChain(chainPem, v.pins, nowMs)
	if chain == nil {
		return hwFail(why)
	}
	leaf := chain[0]
	if v.leafSub != "" && !strings.Contains(nameText(leaf.RawSubject), v.leafSub) {
		return hwFail(fmt.Sprintf("device leaf subject does not contain '%s'", v.leafSub))
	}
	rep, err := parseNvidiaSpdmEvidence(evidence)
	if err != nil {
		return hwFail("GPU attestation report parse failed: " + errMsg(err))
	}
	lk, err := keyOfCert(leaf)
	pub, isEC := lk.pub.(*ecdsa.PublicKey)
	if err != nil || !isEC || !verifyRawECDSA(pub, sha384Sum(rep.signedBytes), rep.signature) {
		return hwFail("GPU attestation report signature does not verify under the device identity key")
	}
	if expected == nil {
		return hwFail("no expected attestation binding supplied")
	}
	raw, err := attestationBindingBytes(*expected)
	if err != nil {
		return hwFail("binding not constructible: " + err.Error())
	}
	if string(rep.requestNonce) != string(sha256Sum(raw)) {
		return hwFail("SPDM request nonce does not bind holder/grant/epoch/nonce (relayed or unbound report)")
	}
	byIndex := map[int]spdmMeasurement{}
	for _, m := range rep.measurements {
		byIndex[m.index] = m
	}
	for _, w := range v.want {
		m, ok := byIndex[w.index]
		if !ok {
			return hwFail(fmt.Sprintf("measurement block %d missing from report", w.index))
		}
		if toHexLower(m.digest) != w.digest {
			return hwFail(fmt.Sprintf("measurement block %d does not match the pinned digest", w.index))
		}
	}
	if v.hasHook {
		col, _ := ev["collateral"].(map[string]any)
		if why := v.hook.withBundle(col).run(rep, chain, nowMs); why != "" {
			return hwFail(why)
		}
	}
	sorted := append([]spdmMeasurement{}, rep.measurements...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].index < sorted[j].index })
	h := sha512.New384()
	for _, m := range sorted {
		h.Write(m.digest)
	}
	host := map[string]string{
		"attestation_type":        "nvidia-gpu-cc",
		"gpu_measurements_sha384": toHexLower(h.Sum(nil)),
		"leaf_subject":            strings.ReplaceAll(nameText(leaf.RawSubject), "\n", ", "),
	}
	if drv, ok := rep.opaque[nvOpaqueDriverVersion]; ok {
		host["driver_version"] = strings.TrimRight(string(drv), "\x00")
	}
	if vb, ok := rep.opaque[nvOpaqueVbiosVersion]; ok {
		host["vbios_version"] = formatVbiosVersion(vb)
	}
	return HardwareResult{OK: true, Bound: true, Measured: newMeasured("", ""), HostAsserted: host}
}
