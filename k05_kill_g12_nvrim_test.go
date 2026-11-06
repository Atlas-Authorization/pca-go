package pca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

const g12Now = int64(1_800_000_000_000)

// ---- a RIM signer: a pinned P-384 root and a GH100 leaf; documents signed through the package's own C14N

type g12Rig struct {
	rootKey, leafKey *ecdsa.PrivateKey
	root, leaf       *x509.Certificate
	pins             []string
	nb, na           time.Time
}

func g12NewRig(t *testing.T) *g12Rig {
	t.Helper()
	gen := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	r := &g12Rig{rootKey: gen(), leafKey: gen(), nb: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), na: time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC)}
	mk := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey) *x509.Certificate {
		tmpl.NotBefore, tmpl.NotAfter = r.nb, r.na
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, r.rootKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	r.root = mk(&x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "g12 root"}, BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1}}, nil, &r.rootKey.PublicKey)
	r.leaf = mk(&x509.Certificate{SerialNumber: big.NewInt(0x1234), Subject: pkix.Name{CommonName: "GH100 g12 leaf"}, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign, SubjectKeyId: []byte{2}}, r.root, &r.leafKey.PublicKey)
	h := sha256.Sum256(r.root.RawSubjectPublicKeyInfo)
	r.pins = []string{hex.EncodeToString(h[:])}
	return r
}

func (r *g12Rig) chain(t *testing.T) []*attCert {
	t.Helper()
	var out []*attCert
	for _, c := range []*x509.Certificate{r.leaf, r.root} {
		a, err := certFromPEM("-----BEGIN CERTIFICATE-----\n" + base64.StdEncoding.EncodeToString(c.Raw) + "\n-----END CERTIFICATE-----\n")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, a)
	}
	return out
}

func (r *g12Rig) crl(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, revoked ...*big.Int) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: r.nb, NextUpdate: r.na, SignatureAlgorithm: x509.ECDSAWithSHA256}
	for _, s := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: r.nb})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

const (
	g12NS  = `xmlns="http://standards.iso.org/iso/19770/-2/2015/schema.xsd" xmlns:ds="` + nsDsig + `"`
	g12CM  = `<ds:CanonicalizationMethod Algorithm="` + algC14N11 + `"/>`
	g12SM  = `<ds:SignatureMethod Algorithm="` + algECDSA384 + `"/>`
	g12TS  = `<ds:Transforms><ds:Transform Algorithm="` + algEnveloped + `"/><ds:Transform Algorithm="` + algC14N11 + `"/></ds:Transforms>`
	g12DM  = `<ds:DigestMethod Algorithm="` + algSHA384 + `"/>`
	g12Ref = `<ds:Reference URI="">` + g12TS + g12DM + `<ds:DigestValue>@D@</ds:DigestValue></ds:Reference>`
	g12SI  = `<ds:SignedInfo>` + g12CM + g12SM + g12Ref + `</ds:SignedInfo>`
	g12SV  = `<ds:SignatureValue>@S@</ds:SignatureValue>`
	g12Res = `<Resource type="Measurement" index="0" active="true" alternatives="1" size="1" Hash0="aa"/>`
)

func (r *g12Rig) keyInfo(certs ...*x509.Certificate) string {
	s := `<ds:KeyInfo><ds:X509Data>`
	for _, c := range certs {
		s += `<ds:X509Certificate>` + base64.StdEncoding.EncodeToString(c.Raw) + `</ds:X509Certificate>`
	}
	return s + `</ds:X509Data></ds:KeyInfo>`
}

func g12Doc(body, sig string) string {
	return `<SoftwareIdentity ` + g12NS + `>` + body + sig + `</SoftwareIdentity>`
}

func (r *g12Rig) template(body string) string {
	return g12Doc(body, `<ds:Signature>`+g12SI+g12SV+r.keyInfo(r.leaf, r.root)+`</ds:Signature>`)
}

// sign fills the DigestValue (SHA-384 of the canonical document without the Signature) and then the SignatureValue (the leaf's
// raw P-384 signature over the canonical SignedInfo).
func (r *g12Rig) sign(t *testing.T, body string) string {
	t.Helper()
	tmpl := r.template(body)
	doc, err := parseXML(strings.NewReplacer("@D@", "x", "@S@", "x").Replace(tmpl))
	if err != nil {
		t.Fatal(err)
	}
	sig := doc.root.elementChildrenNS(nsDsig, "Signature")[0]
	dh := sha512.Sum384([]byte(canonicalize(doc.root, map[string]string{}, sig)))
	withD := strings.ReplaceAll(tmpl, "@D@", base64.StdEncoding.EncodeToString(dh[:]))
	doc, err = parseXML(strings.ReplaceAll(withD, "@S@", "x"))
	if err != nil {
		t.Fatal(err)
	}
	si := doc.root.elementChildrenNS(nsDsig, "Signature")[0].elementChildrenNS(nsDsig, "SignedInfo")[0]
	sh := sha512.Sum384([]byte(canonicalize(si, si.parent.scope(), nil)))
	rr, ss, err := ecdsa.Sign(rand.Reader, r.leafKey, sh[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 96)
	rr.FillBytes(raw[:48])
	ss.FillBytes(raw[48:])
	return strings.ReplaceAll(withD, "@S@", base64.StdEncoding.EncodeToString(raw))
}

var g12SVRe = regexp.MustCompile(`<ds:SignatureValue>[^<]*</ds:SignatureValue>`)

func g12Golden(index int, active bool, size int, hashes ...string) rimGolden {
	return rimGolden{index: index, active: active, alternatives: len(hashes), size: size, hashes: hashes}
}

// ---- verifyNvidiaRim before any cryptography

func TestG12RimDocumentGates(t *testing.T) {
	r := g12NewRig(t)
	pins := r.pins
	_, perr := parseXML("<a>")
	if perr == nil {
		t.Fatal("premise")
	}
	for _, c := range []struct {
		name, xml string
		pins      []string
		want      string
	}{
		{"empty", "", pins, "RIM: empty or oversized document"},
		{"4000000 characters", strings.Repeat("a", 4_000_000), nil, "RIM: no pinned RIM root configured"},
		{"4000001 characters", strings.Repeat("a", 4_000_001), nil, "RIM: empty or oversized document"},
		{"no pins", "<x/>", nil, "RIM: no pinned RIM root configured"},
		{"unparseable", "<a>", pins, "RIM: verification error (fail closed): " + errMsg(perr)},
		{"comment", "<!--c--><SoftwareIdentity/>", pins, "RIM: XML comments are not permitted"},
		{"root", "<x/>", pins, "RIM: root element is not SoftwareIdentity"},
	} {
		if rim, why := verifyNvidiaRim(c.xml, c.pins, g12Now); rim != nil || why != c.want {
			t.Errorf("%s: %q", c.name, why)
		}
	}
}

func TestG12RimSignatureStructure(t *testing.T) {
	r := g12NewRig(t)
	body := `<Meta product="GH100" colloquialVersion="1"/><Payload>` + g12Res + `</Payload>`
	ki := r.keyInfo(r.leaf, r.root)
	sig := func(si, sv, ki string) string { return `<ds:Signature>` + si + sv + ki + `</ds:Signature>` }
	si := func(ref string) string { return `<ds:SignedInfo>` + g12CM + g12SM + ref + `</ds:SignedInfo>` }
	ref := func(inner string) string {
		return `<ds:Reference URI="">` + inner + g12DM + `<ds:DigestValue>@D@</ds:DigestValue></ds:Reference>`
	}
	tr := func(algs ...string) string {
		s := `<ds:Transforms>`
		for _, a := range algs {
			s += `<ds:Transform Algorithm="` + a + `"/>`
		}
		return s + `</ds:Transforms>`
	}
	const transforms = "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"
	const missing = "RIM: missing DigestValue / SignatureValue"
	const noCerts = "RIM: no signer certificates in KeyInfo"
	for _, c := range []struct{ name, xml, want string }{
		{"no Signature", g12Doc(body, ""), "RIM: expected exactly one Signature element"},
		{"nested Signature", g12Doc(`<Meta/><Payload><ds:Signature/></Payload>`, ""), "RIM: the Signature must be a direct child of the root"},
		{"no SignedInfo", g12Doc(body, `<ds:Signature></ds:Signature>`), "RIM: expected exactly one SignedInfo"},
		{"no CanonicalizationMethod", g12Doc(body, sig(`<ds:SignedInfo>`+g12SM+g12Ref+`</ds:SignedInfo>`, g12SV, ki)), "RIM: CanonicalizationMethod must be C14N 1.1"},
		{"wrong CanonicalizationMethod", g12Doc(body, sig(strings.Replace(g12SI, algC14N11+`"/><ds:SignatureMethod`, `x"/><ds:SignatureMethod`, 1), g12SV, ki)), "RIM: CanonicalizationMethod must be C14N 1.1"},
		{"wrong SignatureMethod", g12Doc(body, sig(strings.Replace(g12SI, algECDSA384, "x", 1), g12SV, ki)), "RIM: SignatureMethod must be ECDSA-SHA384"},
		{"no Reference", g12Doc(body, sig(si(""), g12SV, ki)), "RIM: expected exactly one Reference"},
		{"Reference URI", g12Doc(body, sig(si(strings.Replace(g12Ref, `URI=""`, `URI="#x"`, 1)), g12SV, ki)), `RIM: Reference URI must be "" (the whole document)`},
		{"no Transforms", g12Doc(body, sig(si(ref("")), g12SV, ki)), transforms},
		{"one Transform", g12Doc(body, sig(si(ref(tr(algEnveloped))), g12SV, ki)), transforms},
		{"three Transforms", g12Doc(body, sig(si(ref(tr(algEnveloped, algC14N11, algEnveloped))), g12SV, ki)), transforms},
		{"wrong DigestMethod", g12Doc(body, sig(si(strings.Replace(g12Ref, algSHA384, "x", 1)), g12SV, ki)), "RIM: DigestMethod must be SHA-384"},
		{"no DigestValue", g12Doc(body, sig(si(`<ds:Reference URI="">`+g12TS+g12DM+`</ds:Reference>`), g12SV, ki)), missing},
		{"no SignatureValue", g12Doc(body, sig(g12SI, "", ki)), missing},
		{"empty DigestValue", g12Doc(body, sig(si(ref(g12TS)), g12SV, ki)), missing},
		{"no KeyInfo", g12Doc(body, sig(g12SI, g12SV, "")), noCerts},
		{"no X509Data", g12Doc(body, sig(g12SI, g12SV, `<ds:KeyInfo></ds:KeyInfo>`)), noCerts},
		{"no certificates", g12Doc(body, sig(g12SI, g12SV, `<ds:KeyInfo><ds:X509Data></ds:X509Data></ds:KeyInfo>`)), noCerts},
		{"leaf only", g12Doc(body, sig(g12SI, g12SV, r.keyInfo(r.leaf))), "RIM signer chain: device chain root is not a self-signed CA"},
	} {
		xml := c.xml
		if c.name == "empty DigestValue" {
			xml = strings.Replace(xml, "@D@", "", 1)
		}
		xml = strings.NewReplacer("@D@", "AAAA", "@S@", "AAAA").Replace(xml)
		if rim, why := verifyNvidiaRim(xml, r.pins, g12Now); rim != nil || why != c.want {
			t.Errorf("%s: %q", c.name, why)
		}
	}
}

// ---- verifyNvidiaRim on signed documents

func TestG12RimSignedGoldenMeasurements(t *testing.T) {
	r := g12NewRig(t)
	xml := r.sign(t, `<Meta product="GH100" colloquialVersion="535.86"/><Payload>`+
		`<Resource type="Measurement" index="0" active="true" alternatives="2" size="1" Hash1="bb" Hash0="aa"/>`+
		`<Resource type="Measurement" index="1" active="false" alternatives="2" size="1" Hash01="cc" Hash1="dd"/>`+
		`<Resource type="Measurement" index="2" active="TRUE" alternatives="1" size="1" Hash0="EE"/>`+
		`</Payload>`)
	rim, why := verifyNvidiaRim(xml, r.pins, g12Now)
	if rim == nil {
		t.Fatalf("valid RIM: %s", why)
	}
	want := map[int]rimGolden{0: g12Golden(0, true, 1, "aa", "bb"), 1: g12Golden(1, false, 1, "cc", "dd"), 2: g12Golden(2, true, 1, "ee")}
	if rim.product != "GH100" || rim.version != "535.86" || !reflect.DeepEqual(rim.golden, want) {
		t.Fatalf("got %+v", rim)
	}
	// the signature value: not 96 bytes, then a wrong 96-byte one
	short := g12SVRe.ReplaceAllString(xml, `<ds:SignatureValue>AAAA</ds:SignatureValue>`)
	if rim, why := verifyNvidiaRim(short, r.pins, g12Now); rim != nil || why != "RIM: SignatureValue is not a 96-byte P-384 signature" {
		t.Errorf("short signature: %q", why)
	}
	forged := g12SVRe.ReplaceAllString(xml, `<ds:SignatureValue>`+base64.StdEncoding.EncodeToString(append(make([]byte, 95), 1))+`</ds:SignatureValue>`)
	if rim, why := verifyNvidiaRim(forged, r.pins, g12Now); rim != nil || why != "RIM: SignedInfo signature does not verify under the signer certificate" {
		t.Errorf("forged signature: %q", why)
	}
}

func TestG12RimSignedStructure(t *testing.T) {
	r := g12NewRig(t)
	meta := `<Meta product="GH100" colloquialVersion="1"/>`
	res := func(attrs string) string { return `<Payload><Resource type="Measurement" ` + attrs + `/></Payload>` }
	const malformed = "RIM: malformed Measurement resource"
	check := func(name, body string, want string) *verifiedRim {
		t.Helper()
		rim, why := verifyNvidiaRim(r.sign(t, body), r.pins, g12Now)
		if why != want || (want == "") != (rim != nil) {
			t.Errorf("%s: %q", name, why)
		}
		return rim
	}
	if rim := check("two Meta", meta+`<Meta product="OTHER" colloquialVersion="2"/><Payload>`+g12Res+`</Payload>`, ""); rim != nil && (rim.product != "GH100" || rim.version != "1") {
		t.Errorf("two Meta: the first counts, got %+v", rim)
	}
	if rim := check("two Payload", meta+`<Payload>`+g12Res+`</Payload><Payload>`+strings.Replace(g12Res, `index="0"`, `index="7"`, 1)+`</Payload>`, ""); rim != nil {
		if _, has := rim.golden[0]; !has || len(rim.golden) != 1 {
			t.Errorf("two Payload: the first counts, got %+v", rim.golden)
		}
	}
	check("no Meta", `<Payload>`+g12Res+`</Payload>`, "RIM: missing Meta / Payload")
	if rim := check("other children", meta+`<Payload><Foo/><Resource type="Other"/>`+g12Res+`</Payload>`, ""); rim != nil && len(rim.golden) != 1 {
		t.Errorf("other children: %+v", rim.golden)
	}
	check("fractional index", meta+res(`index="1.5" active="true" alternatives="1" size="1" Hash0="aa"`), malformed)
	check("non-numeric index", meta+res(`index="abc" active="true" alternatives="1" size="1" Hash0="aa"`), malformed)
	check("negative index", meta+res(`index="-1" active="true" alternatives="1" size="1" Hash0="aa"`), malformed)
	check("no alternatives", meta+res(`index="0" active="true" alternatives="0" size="1"`), malformed)
	check("size 0", meta+res(`index="0" active="true" alternatives="1" size="0" Hash0=""`), malformed)
	check("non-hex hash", meta+res(`index="0" active="true" alternatives="1" size="1" Hash0="zz"`), "RIM: Measurement 0 hash list is inconsistent with alternatives/size")
	check("no measurements", meta+`<Payload></Payload>`, "RIM: no measurements")
}

// ---- the RIM ids, the comparison and the hook

func g12Opaque() map[int][]byte {
	return map[int][]byte{3: []byte("535.86"), 6: {1, 2, 3, 4, 5, 6, 7, 8}, 14: []byte("c14"), 15: []byte("c15"), 16: []byte("c16"),
		17: []byte("p17"), 18: []byte("s18"), 19: []byte("s19")}
}

func TestG12RimIDsForReport(t *testing.T) {
	vbv := formatVbiosVersion([]byte{1, 2, 3, 4, 5, 6, 7, 8})
	ids := nvidiaRimIDsForReport(&spdmReport{opaque: g12Opaque()})
	want := nvidiaRimIDs{chip: "GH100", driver: "NV_GPU_DRIVER_GH100_535.86", vbios: "NV_GPU_VBIOS_P17_S18_C15_" + strings.ToUpper(strings.ReplaceAll(vbv, ".", "")),
		driverVersion: "535.86", vbiosVersion: vbv}
	if ids == nil || *ids != want {
		t.Fatalf("got %+v want %+v", ids, want)
	}
	for _, k := range []int{3, 6, 15, 17, 18} {
		o := g12Opaque()
		delete(o, k)
		if ids := nvidiaRimIDsForReport(&spdmReport{opaque: o}); ids != nil {
			t.Errorf("without opaque %d: %+v", k, ids)
		}
	}
	o := g12Opaque()
	o[nvOpaqueChipInfo] = []byte("GB100")
	if ids := nvidiaRimIDsForReport(&spdmReport{opaque: o}); ids == nil || ids.chip != "GB100" || ids.driver != "NV_GPU_CC_DRIVER_GB100_535.86" {
		t.Errorf("GB100: %+v", ids)
	}
	o[nvOpaqueChipInfo] = []byte("bad")
	if ids := nvidiaRimIDsForReport(&spdmReport{opaque: o}); ids != nil {
		t.Errorf("bad chip: %+v", ids)
	}
}

func g12Rims(gs ...rimGolden) *verifiedRim {
	m := map[int]rimGolden{}
	for _, g := range gs {
		m[g.index] = g
	}
	return &verifiedRim{golden: m}
}

func TestG12CompareReportToRims(t *testing.T) {
	const differ1 = "runtime measurements differ from the golden RIM values at 1 index(es)"
	one := &spdmReport{measurements: []spdmMeasurement{{index: 1, digest: []byte{0xaa}}}}
	for _, c := range []struct {
		name          string
		rep           *spdmReport
		driver, vbios *verifiedRim
		want          string
	}{
		{"match", one, g12Rims(g12Golden(0, true, 1, "aa")), g12Rims(), ""},
		{"no actives", one, g12Rims(g12Golden(0, false, 1, "aa")), g12Rims(g12Golden(1, false, 1, "aa")), "RIMs carry no active golden measurements"},
		{"more actives than measurements", one, g12Rims(g12Golden(0, true, 1, "aa"), g12Golden(1, true, 1, "aa")), g12Rims(), "RIMs list more active measurements than the report carries"},
		{"absent with an empty golden hash", &spdmReport{measurements: []spdmMeasurement{{index: 2, digest: []byte{1}}}}, g12Rims(g12Golden(0, true, 0, "")), g12Rims(), differ1},
		{"wrong size, listed hash", &spdmReport{measurements: []spdmMeasurement{{index: 1, digest: []byte{0xaa, 0xbb}}}}, g12Rims(g12Golden(0, true, 3, "aabb")), g12Rims(), differ1},
	} {
		if got := compareReportToRims(c.rep, c.driver, c.vbios); got != c.want {
			t.Errorf("%s: %q", c.name, got)
		}
	}
	// the smallest colliding index is reported (the VBIOS indices are walked in order)
	var gs []rimGolden
	for i := 1; i <= 6; i++ {
		gs = append(gs, g12Golden(i, true, 1, "aa"))
	}
	for i := 0; i < 10; i++ {
		if got := compareReportToRims(one, g12Rims(gs...), g12Rims(gs...)); got != "driver and VBIOS RIMs both have an active measurement at index 1" {
			t.Fatalf("collision: %q", got)
		}
	}
	// NVDEC0 (opaque 11 first byte 0x55) disables block 35 (golden index 34)
	nv := func(opaque map[int][]byte) string {
		rep := &spdmReport{measurements: []spdmMeasurement{{index: 35, digest: []byte{0xbb}}}, opaque: opaque}
		return compareReportToRims(rep, g12Rims(g12Golden(34, true, 1, "aa")), g12Rims())
	}
	if got := nv(map[int][]byte{11: {0x55}}); got != "" {
		t.Errorf("NVDEC0 off: %q", got)
	}
	for name, o := range map[string]map[int][]byte{"absent": {}, "empty": {11: {}}, "other byte": {11: {0x54}}} {
		if got := nv(o); got != differ1 {
			t.Errorf("NVDEC0 %s: %q", name, got)
		}
	}
}

func TestG12ChainRevocationByCRL(t *testing.T) {
	r := g12NewRig(t)
	chain := r.chain(t)
	if why := checkNvidiaChainRevocation(chain, [][]byte{r.crl(t, r.root, r.rootKey)}, g12Now, nil); why != "" {
		t.Fatalf("clean CRL: %q", why)
	}
	if why := checkNvidiaChainRevocation(chain, [][]byte{r.crl(t, r.root, r.rootKey, r.leaf.SerialNumber)}, g12Now, nil); why != "chain certificate '"+subjectLine(chain[0])+"' is revoked" {
		t.Errorf("revoked leaf: %q", why)
	}
	// a CRL that verifies under chain[0] (index 0 is a valid issuer index)
	if why := checkNvidiaChainRevocation(chain, [][]byte{r.crl(t, r.leaf, r.leafKey)}, g12Now, nil); why != "" {
		t.Errorf("CRL by the leaf: %q", why)
	}
}

func TestG12NvidiaHookRun(t *testing.T) {
	r := g12NewRig(t)
	chain := r.chain(t)
	vb := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	vbv := formatVbiosVersion(vb)
	rep := &spdmReport{measurements: []spdmMeasurement{{index: 1, digest: []byte{0xaa}}}, opaque: g12Opaque()}
	drv := func(product string) string {
		return r.sign(t, `<Meta product="`+product+`" colloquialVersion="535.86"/><Payload>`+g12Res+`</Payload>`)
	}
	vbx := func(product string) string {
		return r.sign(t, `<Meta product="`+product+`" colloquialVersion="`+vbv+`"/><Payload><Resource type="Measurement" index="5" active="false" alternatives="1" size="1" Hash0="bb"/></Payload>`)
	}
	run := func(b *nvidiaBundle) string { return (&nvidiaHook{rimPins: r.pins, bundle: b}).run(rep, chain, g12Now) }
	good := nvidiaBundle{driverRim: drv("GH100"), vbiosRim: vbx("GH100")}
	if why := run(&good); why != "" {
		t.Fatalf("baseline: %q", why)
	}
	if why := run(nil); why != "no RIM collateral supplied for this report" {
		t.Errorf("no bundle (leaf subject names the chip): %q", why)
	}
	if why := (&nvidiaHook{rimPins: r.pins}).run(&spdmReport{opaque: map[int][]byte{}}, chain, g12Now); why != "GPU report does not carry the opaque fields needed to name its RIMs" {
		t.Errorf("no ids: %q", why)
	}
	b := good
	b.vbiosRim = ""
	if why := run(&b); why != "VBIOS RIM: RIM: empty or oversized document" {
		t.Errorf("bad VBIOS RIM: %q", why)
	}
	b = good
	b.driverRim = drv("GB100")
	if why := run(&b); why != "driver RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)" {
		t.Errorf("driver product: %q", why)
	}
	b = good
	b.vbiosRim = vbx("GB100")
	if why := run(&b); why != "VBIOS RIM product 'GB100' does not match the GPU chip 'GH100' (wrong-family manifest)" {
		t.Errorf("VBIOS product: %q", why)
	}
	// revocation is not required here (no mode), but supplied CRLs / OCSP responses are still checked
	b = good
	b.crls = [][]byte{{1}}
	if why := run(&b); !strings.HasPrefix(why, "revocation: CRL #0 rejected: ") {
		t.Errorf("supplied CRL: %q", why)
	}
	b = good
	b.ocsp = [][]byte{{1}}
	if why := run(&b); !strings.HasPrefix(why, "revocation (OCSP): ") {
		t.Errorf("supplied OCSP: %q", why)
	}
}

// ---- versions, firmware policy and small helpers

func TestG12VersionsAndPolicy(t *testing.T) {
	if v, ok := parseVersion("12345", 10); !ok || !reflect.DeepEqual(v, []float64{12345}) {
		t.Errorf("five decimal digits: %v %v", v, ok)
	}
	if v, ok := parseVersion("18446744073709551616", 10); !ok || !reflect.DeepEqual(v, []float64{18446744073709551616}) {
		t.Errorf("2^64: %v %v", v, ok)
	}
	if v, ok := parseVersion("1"+strings.Repeat("0", 400), 10); !ok || !reflect.DeepEqual(v, []float64{math.Inf(1)}) { // parseInt: Infinity
		t.Errorf("beyond float64: %v %v", v, ok)
	}
	for _, c := range []struct {
		a, b []float64
		want int
	}{
		{[]float64{1}, []float64{1, 0, 1}, -1}, {[]float64{1, 0, 1}, []float64{1}, 1}, {[]float64{1}, []float64{1, 2}, -1}, {[]float64{1, 2}, []float64{1}, 1},
		{[]float64{2}, []float64{1}, 1}, {[]float64{1}, []float64{2}, -1}, {[]float64{0.5}, []float64{0}, 1}, {[]float64{1, 2}, []float64{1, 2}, 0},
	} {
		if got := cmpVersion(c.a, c.b); got != c.want {
			t.Errorf("cmpVersion(%v, %v) = %d", c.a, c.b, got)
		}
	}
	ids := &nvidiaRimIDs{driverVersion: "1", vbiosVersion: "1"}
	if why := (&firmwarePolicy{minV: []float64{9}}).check(ids); why != "" {
		t.Errorf("an unset minimum: %q", why)
	}
	if why := (&firmwarePolicy{minV: []float64{1}, hasMinV: true, minVText: "1"}).check(ids); why != "" {
		t.Errorf("at the minimum: %q", why)
	}
	if got := stripJSSpace(" a\tb c d\n"); got != "abcd" {
		t.Errorf("stripJSSpace = %q", got)
	}
	body := strings.Repeat("A", 64)
	if got := pemOfDerB64(body); got != "-----BEGIN CERTIFICATE-----\n"+body+"\n-----END CERTIFICATE-----" {
		t.Errorf("pemOfDerB64 = %q", got)
	}
}
