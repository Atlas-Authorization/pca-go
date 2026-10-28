package pca

// NVIDIA GPU-CC collateral: Reference Integrity Manifests (SWID/CoRIM XML, enveloped XMLDSig, strict profile), the golden
// measurement comparison with NVIDIA's merge / alternatives / NVDEC0 rules, the driver / VBIOS version binding, certificate
// revocation through CRLs (here) and OCSP (attest_nvidia_ocsp.go), and a firmware policy. Fetching is never automatic: the
// RIMs, CRLs and OCSP responses arrive with the evidence. Same checks, order and reason text as the reference.

import (
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	nsDsig       = "http://www.w3.org/2000/09/xmldsig#"
	algC14N11    = "http://www.w3.org/2006/12/xml-c14n11"
	algEnveloped = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	algECDSA384  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	algSHA384    = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	nvdec0Off    = 0x55
	nvdecBlock   = 35
)

type rimGolden struct {
	index        int
	active       bool
	alternatives int
	size         int
	hashes       []string
}

type verifiedRim struct {
	product, version string
	golden           map[int]rimGolden
}

func stripJSSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if isJSSpace(r) {
			return -1
		}
		return r
	}, s)
}

func pemOfDerB64(b64 string) string {
	body := stripJSSpace(b64)
	var lines []string
	for i := 0; i < len(body); i += 64 {
		end := i + 64
		if end > len(body) {
			end = len(body)
		}
		lines = append(lines, body[i:end])
	}
	return "-----BEGIN CERTIFICATE-----\n" + strings.Join(lines, "\n") + "\n-----END CERTIFICATE-----"
}

var (
	hashAttrRe = regexp.MustCompile(`^Hash[0-9]+$`)
	lowerHexRe = regexp.MustCompile(`^[0-9a-f]+$`)
)

// verifyNvidiaRim verifies a RIM document and returns its golden measurements. A failure reason, or the manifest.
func verifyNvidiaRim(xml string, rimPins []string, nowMs int64) (*verifiedRim, string) {
	fail := func(r string) (*verifiedRim, string) { return nil, r }
	if xml == "" || utf8.RuneCountInString(xml) > 4_000_000 {
		return fail("RIM: empty or oversized document")
	}
	if len(rimPins) == 0 {
		return fail("RIM: no pinned RIM root configured")
	}
	doc, err := parseXML(xml)
	if err != nil {
		return fail("RIM: verification error (fail closed): " + errMsg(err))
	}
	if doc.violation != "" {
		return fail("RIM: " + doc.violation)
	}
	root := doc.root
	if root.local != "SoftwareIdentity" {
		return fail("RIM: root element is not SoftwareIdentity")
	}
	if root.descendantsNS(nsDsig, "Signature") != 1 {
		return fail("RIM: expected exactly one Signature element")
	}
	sigs := root.elementChildrenNS(nsDsig, "Signature")
	if len(sigs) != 1 {
		return fail("RIM: the Signature must be a direct child of the root")
	}
	sig := sigs[0]
	signedInfo := sig.elementChildrenNS(nsDsig, "SignedInfo")
	if len(signedInfo) != 1 {
		return fail("RIM: expected exactly one SignedInfo")
	}
	si := signedInfo[0]
	algOf := func(els []*xmlNode) string {
		if len(els) == 0 {
			return ""
		}
		return els[0].attr("Algorithm")
	}
	if algOf(si.elementChildrenNS(nsDsig, "CanonicalizationMethod")) != algC14N11 {
		return fail("RIM: CanonicalizationMethod must be C14N 1.1")
	}
	if algOf(si.elementChildrenNS(nsDsig, "SignatureMethod")) != algECDSA384 {
		return fail("RIM: SignatureMethod must be ECDSA-SHA384")
	}
	refs := si.elementChildrenNS(nsDsig, "Reference")
	if len(refs) != 1 {
		return fail("RIM: expected exactly one Reference")
	}
	ref := refs[0]
	if ref.attr("URI") != "" {
		return fail(`RIM: Reference URI must be "" (the whole document)`)
	}
	holder := ref
	if ts := ref.elementChildrenNS(nsDsig, "Transforms"); len(ts) > 0 {
		holder = ts[0]
	}
	var transforms []string
	for _, t := range holder.elementChildrenNS(nsDsig, "Transform") {
		transforms = append(transforms, t.attr("Algorithm"))
	}
	if len(transforms) != 2 || transforms[0] != algEnveloped || transforms[1] != algC14N11 {
		return fail("RIM: transforms must be exactly [enveloped-signature, C14N 1.1]")
	}
	if algOf(ref.elementChildrenNS(nsDsig, "DigestMethod")) != algSHA384 {
		return fail("RIM: DigestMethod must be SHA-384")
	}
	var digestValue, sigValueB64 string
	if d := ref.elementChildrenNS(nsDsig, "DigestValue"); len(d) > 0 {
		digestValue = stripJSSpace(d[0].textContent())
	}
	if d := sig.elementChildrenNS(nsDsig, "SignatureValue"); len(d) > 0 {
		sigValueB64 = stripJSSpace(d[0].textContent())
	}
	if digestValue == "" || sigValueB64 == "" {
		return fail("RIM: missing DigestValue / SignatureValue")
	}

	var certB64 []string
	if ki := sig.elementChildrenNS(nsDsig, "KeyInfo"); len(ki) > 0 {
		if xd := ki[0].elementChildrenNS(nsDsig, "X509Data"); len(xd) > 0 {
			for _, c := range xd[0].elementChildrenNS(nsDsig, "X509Certificate") {
				certB64 = append(certB64, c.textContent())
			}
		}
	}
	if len(certB64) == 0 {
		return fail("RIM: no signer certificates in KeyInfo")
	}
	pems := make([]string, len(certB64))
	for i, c := range certB64 {
		pems[i] = pemOfDerB64(c)
	}
	chain, why := verifyNvidiaDeviceChain(strings.Join(pems, "\n"), rimPins, nowMs)
	if chain == nil {
		return fail("RIM signer chain: " + why)
	}

	siCanon := canonicalize(si, si.parent.scope(), nil)
	sigRaw := nodeB64(sigValueB64)
	if len(sigRaw) != 96 {
		return fail("RIM: SignatureValue is not a 96-byte P-384 signature")
	}
	lk, err := keyOfCert(chain[0])
	pub, isEC := lk.pub.(*ecdsa.PublicKey)
	if err != nil || !isEC || !verifyRawECDSA(pub, sha384Sum([]byte(siCanon)), sigRaw) {
		return fail("RIM: SignedInfo signature does not verify under the signer certificate")
	}

	canon := canonicalize(root, map[string]string{}, sig)
	h := sha512.Sum384([]byte(canon))
	if base64.StdEncoding.EncodeToString(h[:]) != digestValue {
		return fail("RIM: document digest does not match the signed DigestValue")
	}

	var meta, payload *xmlNode
	for _, c := range root.elementChildren() {
		if meta == nil && c.local == "Meta" {
			meta = c
		}
		if payload == nil && c.local == "Payload" {
			payload = c
		}
	}
	if meta == nil || payload == nil {
		return fail("RIM: missing Meta / Payload")
	}
	golden := map[int]rimGolden{}
	for _, r := range payload.elementChildren() {
		if r.local != "Resource" || r.attr("type") != "Measurement" {
			continue
		}
		index, iok := jsNumberFromString(r.attr("index"))
		alts, aok := jsNumberFromString(r.attr("alternatives"))
		size, sok := jsNumberFromString(r.attr("size"))
		type hashAttr struct {
			n int
			v string
		}
		var hs []hashAttr
		for _, a := range r.attrs {
			if hashAttrRe.MatchString(a.local) {
				n, _ := strconv.Atoi(a.local[4:])
				hs = append(hs, hashAttr{n: n, v: strings.ToLower(a.value)})
			}
		}
		sort.SliceStable(hs, func(i, j int) bool { return hs[i].n < hs[j].n })
		isInt := func(f float64, ok bool, min float64) bool { return ok && f == float64(int64(f)) && f >= min }
		if !isInt(index, iok, 0) || !isInt(alts, aok, 1) || !isInt(size, sok, 1) {
			return fail("RIM: malformed Measurement resource")
		}
		hashes := make([]string, len(hs))
		for i, h := range hs {
			hashes[i] = h.v
		}
		bad := len(hashes) != int(alts)
		for _, h := range hashes {
			if !lowerHexRe.MatchString(h) || len(h) != int(size)*2 {
				bad = true
			}
		}
		if bad {
			return fail(fmt.Sprintf("RIM: Measurement %d hash list is inconsistent with alternatives/size", int(index)))
		}
		if _, dup := golden[int(index)]; dup {
			return fail(fmt.Sprintf("RIM: duplicate Measurement index %d", int(index)))
		}
		golden[int(index)] = rimGolden{index: int(index), active: strings.ToLower(r.attr("active")) == "true", alternatives: int(alts), size: int(size), hashes: hashes}
	}
	if len(golden) == 0 {
		return fail("RIM: no measurements")
	}
	return &verifiedRim{product: meta.attr("product"), version: meta.attr("colloquialVersion"), golden: golden}, ""
}

// ───────────────────────────────────────────────────────────── RIM ids named by the (signed) GPU report

type nvidiaRimIDs struct {
	chip, driver, vbios, driverVersion, vbiosVersion string
}

func opaqueASCII(b []byte) string {
	rs := make([]rune, len(b))
	for i, c := range b {
		rs[i] = rune(c)
	}
	s := strings.TrimRight(string(rs), "\x00")
	return jsTrim(s)
}

var chipNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9]{2,11}$`)

func nvidiaRimIDsForReport(rep *spdmReport) *nvidiaRimIDs {
	o := rep.opaque
	driverVersion := opaqueASCII(o[nvOpaqueDriverVersion])
	vb, hasVb := o[nvOpaqueVbiosVersion]
	project := strings.ToUpper(opaqueASCII(o[17]))
	projectSku := strings.ToUpper(opaqueASCII(o[18]))
	chipSku := strings.ToUpper(opaqueASCII(o[15]))
	if driverVersion == "" || !hasVb || project == "" || projectSku == "" || chipSku == "" {
		return nil
	}
	chip := "GH100"
	if raw, ok := o[nvOpaqueChipInfo]; ok {
		chip = opaqueASCII(raw)
		if !chipNameRe.MatchString(chip) {
			return nil
		}
	}
	vbiosVersion := formatVbiosVersion(vb)
	ids := &nvidiaRimIDs{chip: chip, driverVersion: driverVersion, vbiosVersion: vbiosVersion}
	if chip == "GH100" {
		ids.driver = "NV_GPU_DRIVER_GH100_" + driverVersion
	} else {
		ids.driver = "NV_GPU_CC_DRIVER_" + chip + "_" + driverVersion
	}
	ids.vbios = "NV_GPU_VBIOS_" + project + "_" + projectSku + "_" + chipSku + "_" + strings.ToUpper(strings.ReplaceAll(vbiosVersion, ".", ""))
	return ids
}

// compareReportToRims compares a report with the driver and VBIOS RIMs (NVIDIA's merge / alternatives / NVDEC0 rules); "" when it matches.
func compareReportToRims(rep *spdmReport, driver, vbios *verifiedRim) string {
	type src struct {
		g      rimGolden
		source string
	}
	merged := map[int]src{}
	for _, g := range driver.golden {
		if g.active {
			merged[g.index] = src{g, "driver"}
		}
	}
	var vIdx []int
	for i := range vbios.golden {
		vIdx = append(vIdx, i)
	}
	sort.Ints(vIdx)
	for _, i := range vIdx {
		g := vbios.golden[i]
		if !g.active {
			continue
		}
		if _, has := merged[g.index]; has {
			return fmt.Sprintf("driver and VBIOS RIMs both have an active measurement at index %d", g.index)
		}
		merged[g.index] = src{g, "vbios"}
	}
	if len(merged) == 0 {
		return "RIMs carry no active golden measurements"
	}
	runtime := map[int][]byte{}
	for _, m := range rep.measurements {
		runtime[m.index-1] = m.digest
	}
	if len(merged) > len(runtime) {
		return "RIMs list more active measurements than the report carries"
	}
	nvdec, hasNvdec := rep.opaque[11]
	nvdecDisabled := hasNvdec && len(nvdec) > 0 && nvdec[0] == nvdec0Off
	var idxs []int
	for i := range merged {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	mismatches := 0
	for _, index := range idxs {
		g := merged[index].g
		if index+1 == nvdecBlock && nvdecDisabled {
			continue
		}
		digest, has := runtime[index]
		hex := ""
		if has {
			hex = toHexLower(digest)
		}
		if !has || len(digest) != g.size || !containsStr(g.hashes, hex) {
			mismatches++
		}
	}
	if mismatches > 0 {
		return fmt.Sprintf("runtime measurements differ from the golden RIM values at %d index(es)", mismatches)
	}
	return ""
}

// checkNvidiaChainRevocation checks the device chain against CRLs: every CRL must verify under one chain certificate and be fresh,
// no chain certificate may be listed by its issuer's CRL, and each required issuer must have a verified CRL. "" when it holds.
func checkNvidiaChainRevocation(chain []*attCert, crls [][]byte, nowMs int64, requireIssuers []string) string {
	if len(crls) == 0 {
		return "no CRLs supplied"
	}
	covered := map[int]bool{}
	for ci, crl := range crls {
		issuerIdx := -1
		var revoked map[string]bool
		lastReason := "no chain certificate verifies it"
		for i, cert := range chain {
			k, err := keyOfCert(cert)
			if err != nil {
				continue
			}
			rv, why := verifyCRL(crl, k, nowMs)
			if why == "" {
				issuerIdx, revoked = i, rv
				break
			}
			if lastReason == "no chain certificate verifies it" || strings.Contains(lastReason, "signature does not verify") {
				lastReason = why
			}
		}
		if issuerIdx < 0 || revoked == nil {
			return fmt.Sprintf("CRL #%d rejected: %s", ci, lastReason)
		}
		covered[issuerIdx] = true
		for i := 0; i < len(chain)-1; i++ {
			if i+1 == issuerIdx && revoked[certSerialHex(chain[i])] {
				return fmt.Sprintf("chain certificate '%s' is revoked", subjectLine(chain[i]))
			}
		}
	}
	for _, need := range requireIssuers {
		found := false
		for i := range covered {
			if strings.Contains(nameText(chain[i].RawSubject), need) {
				found = true
			}
		}
		if !found {
			return fmt.Sprintf("no verified CRL issued by a certificate matching '%s'", need)
		}
	}
	return ""
}

// ───────────────────────────────────────────────────────────── firmware policy

var (
	dec10VersionRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)
	hex16VersionRe = regexp.MustCompile(`^[0-9a-fA-F]{1,4}(\.[0-9a-fA-F]{1,4})*$`)
)

func parseVersion(v string, radix int) ([]float64, bool) {
	re := dec10VersionRe
	if radix == 16 {
		re = hex16VersionRe
	}
	if !re.MatchString(v) {
		return nil, false
	}
	var out []float64
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.ParseUint(p, radix, 64)
		if err != nil {
			f, ferr := strconv.ParseFloat(p, 64)
			if ferr != nil || radix != 10 {
				return nil, false
			}
			out = append(out, f)
			continue
		}
		out = append(out, float64(n))
	}
	return out, true
}

func cmpVersion(a, b []float64) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y float64
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if d := x - y; d != 0 {
			if d < 0 {
				return -1
			}
			return 1
		}
	}
	return 0
}

type firmwarePolicy struct {
	minD, minV         []float64
	hasMinD, hasMinV   bool
	denyD, denyV       [][]float64
	minDText, minVText string
}

func compileFirmwarePolicy(fw map[string]any) (*firmwarePolicy, error) {
	p := &firmwarePolicy{}
	need := func(v string, radix int, what string) ([]float64, error) {
		parsed, ok := parseVersion(v, radix)
		if !ok {
			return nil, fmt.Errorf("nvidiaCollateralHook: malformed %s '%s'", what, v)
		}
		return parsed, nil
	}
	if s, _ := fw["minDriverVersion"].(string); s != "" {
		v, err := need(s, 10, "minDriverVersion")
		if err != nil {
			return nil, err
		}
		p.minD, p.hasMinD, p.minDText = v, true, s
	}
	if s, _ := fw["minVbiosVersion"].(string); s != "" {
		v, err := need(s, 16, "minVbiosVersion")
		if err != nil {
			return nil, err
		}
		p.minV, p.hasMinV, p.minVText = v, true, s
	}
	for _, s := range anyStrings(fw["denyDriverVersions"]) {
		v, err := need(s, 10, "denyDriverVersions entry")
		if err != nil {
			return nil, err
		}
		p.denyD = append(p.denyD, v)
	}
	for _, s := range anyStrings(fw["denyVbiosVersions"]) {
		v, err := need(s, 16, "denyVbiosVersions entry")
		if err != nil {
			return nil, err
		}
		p.denyV = append(p.denyV, v)
	}
	return p, nil
}

func (p *firmwarePolicy) check(ids *nvidiaRimIDs) string {
	if p == nil {
		return ""
	}
	d, dok := parseVersion(ids.driverVersion, 10)
	v, vok := parseVersion(ids.vbiosVersion, 16)
	if !dok {
		return fmt.Sprintf("driver version '%s' in the GPU report is not parseable", ids.driverVersion)
	}
	if !vok {
		return fmt.Sprintf("VBIOS version '%s' in the GPU report is not parseable", ids.vbiosVersion)
	}
	if p.hasMinD && cmpVersion(d, p.minD) < 0 {
		return fmt.Sprintf("driver %s is below the minimum %s", ids.driverVersion, p.minDText)
	}
	if p.hasMinV && cmpVersion(v, p.minV) < 0 {
		return fmt.Sprintf("VBIOS %s is below the minimum %s", ids.vbiosVersion, p.minVText)
	}
	for _, x := range p.denyD {
		if cmpVersion(d, x) == 0 {
			return fmt.Sprintf("driver %s is on the deny list", ids.driverVersion)
		}
	}
	for _, x := range p.denyV {
		if cmpVersion(v, x) == 0 {
			return fmt.Sprintf("VBIOS %s is on the deny list", ids.vbiosVersion)
		}
	}
	return ""
}

// ───────────────────────────────────────────────────────────── the collateral hook

// nvidiaHook is the post-verification collateral check of the NVIDIA verifier. Its bundle is the collateral the evidence carries.
type nvidiaHook struct {
	rimPins        []string
	revocation     string
	hasRevocation  bool
	requireCrls    bool
	requireIssuers []string
	firmware       *firmwarePolicy
	bundle         *nvidiaBundle
}

type nvidiaBundle struct {
	driverRim, vbiosRim string
	crls, ocsp          [][]byte
}

func newNvidiaHook(col map[string]any) (*nvidiaHook, error) {
	h := &nvidiaHook{requireCrls: col["requireCrls"] != false}
	pins, ok := asStrList(col["rimRootSpkiSha256"])
	if !ok || len(pins) == 0 {
		return nil, errors.New("nvidiaCollateralHook: rimRootSpkiSha256 must pin at least one root")
	}
	h.rimPins = pins
	if fw, ok := col["firmware"].(map[string]any); ok {
		p, err := compileFirmwarePolicy(fw)
		if err != nil {
			return nil, err
		}
		h.firmware = p
	}
	if r, ok := col["revocation"].(string); ok {
		h.revocation, h.hasRevocation = r, true
	}
	h.requireIssuers = anyStrings(col["requireCrlIssuers"])
	return h, nil
}

// withBundle returns the hook bound to the collateral of one evidence object (nil: none supplied).
func (h *nvidiaHook) withBundle(c map[string]any) *nvidiaHook {
	cp := *h
	if c == nil {
		cp.bundle = nil
		return &cp
	}
	b := &nvidiaBundle{}
	b.driverRim, _ = c["driverRimXml"].(string)
	b.vbiosRim, _ = c["vbiosRimXml"].(string)
	for _, s := range anyStrings(c["crls"]) {
		b.crls = append(b.crls, nodeB64(s))
	}
	for _, s := range anyStrings(c["ocsp"]) {
		b.ocsp = append(b.ocsp, nodeB64(s))
	}
	cp.bundle = b
	return &cp
}

// run is the hook proper: the failure reason, or "" when the collateral holds.
func (h *nvidiaHook) run(rep *spdmReport, chain []*attCert, nowMs int64) string {
	ids := nvidiaRimIDsForReport(rep)
	if ids == nil {
		return "GPU report does not carry the opaque fields needed to name its RIMs"
	}
	leaf := chain[0]
	subject := nameText(leaf.RawSubject)
	chipRe := regexp.MustCompile(`(^|[^A-Za-z0-9])` + regexp.QuoteMeta(ids.chip) + `([^A-Za-z0-9]|$)`)
	if !chipRe.MatchString(subject) {
		return fmt.Sprintf("device leaf subject '%s' is not a %s device certificate (chip family mismatch)", strings.ReplaceAll(subject, "\n", ", "), ids.chip)
	}
	if why := h.firmware.check(ids); why != "" {
		return "firmware policy: " + why
	}
	if h.bundle == nil {
		return "no RIM collateral supplied for this report"
	}
	d, dwhy := verifyNvidiaRim(h.bundle.driverRim, h.rimPins, nowMs)
	v, vwhy := verifyNvidiaRim(h.bundle.vbiosRim, h.rimPins, nowMs)
	if d == nil {
		return "driver RIM: " + dwhy
	}
	if v == nil {
		return "VBIOS RIM: " + vwhy
	}
	if d.product != ids.chip {
		return fmt.Sprintf("driver RIM product '%s' does not match the GPU chip '%s' (wrong-family manifest)", d.product, ids.chip)
	}
	if v.product != ids.chip {
		return fmt.Sprintf("VBIOS RIM product '%s' does not match the GPU chip '%s' (wrong-family manifest)", v.product, ids.chip)
	}
	if d.version != ids.driverVersion {
		return fmt.Sprintf("driver RIM version '%s' does not match the report's driver '%s'", d.version, ids.driverVersion)
	}
	if strings.ToUpper(strings.ReplaceAll(v.version, ".", "")) != strings.ToUpper(strings.ReplaceAll(ids.vbiosVersion, ".", "")) {
		return fmt.Sprintf("VBIOS RIM version '%s' does not match the report's VBIOS '%s'", v.version, ids.vbiosVersion)
	}
	if why := compareReportToRims(rep, d, v); why != "" {
		return why
	}
	mode := "crl"
	if h.hasRevocation {
		mode = h.revocation
	} else if !h.requireCrls {
		mode = ""
	}
	if len(h.bundle.crls) > 0 || mode == "crl" || mode == "both" {
		if why := checkNvidiaChainRevocation(chain, h.bundle.crls, nowMs, h.requireIssuers); why != "" {
			return "revocation: " + why
		}
	}
	if len(h.bundle.ocsp) > 0 || mode == "ocsp" || mode == "both" {
		if why := checkNvidiaChainOcsp(chain, h.bundle.ocsp, nowMs); why != "" {
			return "revocation (OCSP): " + why
		}
	}
	return ""
}
