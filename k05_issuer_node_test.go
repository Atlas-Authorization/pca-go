package pca

// Verdicts read from Node 26: X509Certificate on really signed P-384 certificates with these exact bytes, the link being
// `child.checkIssued(issuer) && child.verify(issuer.publicKey)`. Extensions are written "oid=value" in hex.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
	"testing"
)

func k05inGen() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func k05inGenRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

var (
	k05inRootKey, k05inUpKey, k05inLeafKey = k05inGen(), k05inGen(), k05inGen()
	k05inRSAKey                            = k05inGenRSA()
	k05inV3                                = derTLV(0xa0, derTLV(0x02, []byte{2}))
	k05inCN                                = derTLV(0x06, []byte{0x55, 4, 3})
)

func k05inHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func k05inName(tag byte, value []byte) []byte {
	return derTLV(0x30, derTLV(0x31, derTLV(0x30, k05inCN, derTLV(tag, value))))
}

func k05inValidity() []byte {
	return derTLV(0x30, derTLV(0x17, []byte("250101000000Z")), derTLV(0x17, []byte("350101000000Z")))
}

// k05inCert signs a certificate with exactly these bytes.
func k05inCert(version, serial, iss, sub []byte, extSpec string, key, signer *ecdsa.PrivateKey) []byte {
	alg := derTLV(0x30, derTLV(0x06, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3}))
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	var exts [][]byte
	for _, e := range strings.Fields(extSpec) {
		id, value, _ := strings.Cut(e, "=")
		exts = append(exts, derTLV(0x30, derTLV(0x06, k05inHex(id)), derTLV(0x04, k05inHex(value))))
	}
	var block []byte
	if len(exts) > 0 {
		block = derTLV(0xa3, derTLV(0x30, exts...))
	}
	tbs := derTLV(0x30, version, derTLV(0x02, serial), alg, iss, k05inValidity(), sub, spki, block)
	d := sha512.Sum384(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, d[:])
	if err != nil {
		panic(err)
	}
	return derTLV(0x30, tbs, alg, derTLV(0x03, []byte{0}, sig))
}

func k05inPair(t *testing.T, childIss []byte, child, up string) (c, u *attCert) {
	t.Helper()
	upName := k05inName(0x0c, []byte("up"))
	u, err := parseCertDER(k05inCert(k05inV3, []byte{0x11}, k05inName(0x0c, []byte("root")), upName, up, k05inUpKey, k05inRootKey))
	if err != nil {
		t.Fatal(err)
	}
	if childIss == nil {
		childIss = upName
	}
	c, err = parseCertDER(k05inCert(k05inV3, []byte{0x22}, childIss, k05inName(0x0c, []byte("leaf")), child, k05inLeafKey, k05inUpKey))
	if err != nil {
		t.Fatal(err)
	}
	return c, u
}

func TestK05IssuerLinkAgainstNode(t *testing.T) {
	for _, r := range k05inLinkRows {
		c, u := k05inPair(t, nil, r.child, r.up)
		if !certSigOKBy(c, u) {
			t.Fatalf("%s: not really signed", r.name)
		}
		if got := certCheckIssued(c, u); got != r.want {
			t.Errorf("%s: %v, Node says %v", r.name, got, r.want)
		}
		if got := (&NodeCert{c}).CheckIssued(&NodeCert{u}); got != r.want {
			t.Errorf("%s: CheckIssued %v, Node says %v", r.name, got, r.want)
		}
	}
	if c, u := k05inPair(t, k05inName(0x0c, []byte("nope")), "", ""); certCheckIssued(c, u) {
		t.Error("the child names another issuer")
	}
}

func TestK05IssuerCAAgainstNode(t *testing.T) {
	for _, r := range k05inCARows {
		_, u := k05inPair(t, nil, "", r.up)
		if got := certIsCA(u); got != r.want {
			t.Errorf("%s: %v, Node says %v", r.name, got, r.want)
		}
		if got := (&NodeCert{u}).CA(); got != r.want {
			t.Errorf("%s: NodeCert.CA %v, Node says %v", r.name, got, r.want)
		}
	}
}

func TestK05CertSerialAgainstNode(t *testing.T) {
	root, up := k05inName(0x0c, []byte("root")), k05inName(0x0c, []byte("up"))
	for _, r := range []struct {
		serial string
		want   bool
	}{
		{"01", true},
		{"11", true},
		{"0080", true},
		{"ff7f", true},
		{"80", true},
		{"00", true},
		{"ff", true},
		{"111111111111111111111111111111111111111111", true},
		{"0011", false},
		{"ff80", false},
		{"0000", false},
		{"", false},
		{"ffff", false},
	} {
		c, err := parseCertDER(k05inCert(k05inV3, k05inHex(r.serial), root, up, "", k05inUpKey, k05inRootKey))
		if (err == nil) != r.want {
			t.Errorf("serial %q: %v, Node accepts: %v", r.serial, err, r.want)
		}
		if err == nil && hex.EncodeToString(c.Serial) != r.serial {
			t.Errorf("serial %q read as %x", r.serial, c.Serial)
		}
	}
	for _, r := range []struct {
		inner string
		want  bool
	}{
		{"020102", true},
		{"020109", true},
		{"0201ff", true},
		{"020100", true},
		{"02020002", false},
		{"0200", false},
		{"0201020500", false},
	} {
		_, err := parseCertDER(k05inCert(derTLV(0xa0, k05inHex(r.inner)), []byte{1}, root, up, "", k05inUpKey, k05inRootKey))
		if (err == nil) != r.want {
			t.Errorf("version %q: %v, Node accepts: %v", r.inner, err, r.want)
		}
	}
}

func TestK05CertNameValuesAgainstNode(t *testing.T) {
	root, up := k05inName(0x0c, []byte("root")), k05inName(0x0c, []byte("up"))
	for _, r := range []struct {
		tag   byte
		value string
		want  bool
	}{
		{0x0c, "", true},
		{0x0c, "00", true},
		{0x0c, "09", true},
		{0x0c, "41", true},
		{0x0c, "0041", true},
		{0x0c, "d800", false},
		{0x0c, "c328", false},
		{0x0c, "ffff", false},
		{0x0c, "00000041", true},
		{0x0c, "00110000", true},
		{0x0c, "0000d800", false},
		{0x0c, "efbfbe", true},
		{0x0c, "f48fbfbf", true},
		{0x1e, "", true},
		{0x1e, "00", false},
		{0x1e, "09", false},
		{0x1e, "41", false},
		{0x1e, "0041", true},
		{0x1e, "d800", false},
		{0x1e, "c328", true},
		{0x1e, "ffff", true},
		{0x1e, "00000041", true},
		{0x1e, "00110000", true},
		{0x1e, "0000d800", false},
		{0x1e, "efbfbe", false},
		{0x1e, "f48fbfbf", true},
		{0x1c, "", true},
		{0x1c, "00", false},
		{0x1c, "09", false},
		{0x1c, "41", false},
		{0x1c, "0041", false},
		{0x1c, "d800", false},
		{0x1c, "c328", false},
		{0x1c, "ffff", false},
		{0x1c, "00000041", true},
		{0x1c, "00110000", false},
		{0x1c, "0000d800", false},
		{0x1c, "efbfbe", false},
		{0x1c, "f48fbfbf", false},
		{0x03, "", false},
		{0x03, "00", true},
		{0x03, "09", false},
		{0x03, "41", false},
		{0x03, "0041", true},
		{0x03, "d800", false},
		{0x03, "c328", false},
		{0x03, "ffff", false},
		{0x03, "00000041", true},
		{0x03, "00110000", true},
		{0x03, "0000d800", true},
		{0x03, "efbfbe", false},
		{0x03, "f48fbfbf", false},
		{0x12, "41", true},
		{0x13, "41", true},
		{0x14, "41", true},
		{0x16, "41", true},
		{0x30, "41", true},
		{0x07, "41", true},
		{0x08, "41", true},
		{0x09, "41", true},
		{0x0b, "41", true},
		{0x0d, "41", true},
		{0x0e, "41", true},
		{0x0f, "41", true},
		{0x1d, "41", true},
		{0x0a, "41", false},
		{0x02, "41", false},
		{0x05, "41", false},
		{0x01, "41", false},
		{0x04, "41", false},
		{0x06, "41", false},
		{0x15, "41", false},
		{0x19, "41", false},
		{0x1a, "41", false},
		{0x1b, "41", false},
		{0x31, "41", false},
	} {
		n := k05inName(r.tag, k05inHex(r.value))
		if _, err := parseCertDER(k05inCert(k05inV3, []byte{1}, n, up, "", k05inUpKey, k05inRootKey)); (err == nil) != r.want {
			t.Errorf("issuer value %#x %q: %v, Node accepts: %v", r.tag, r.value, err, r.want)
		}
		if _, err := parseCertDER(k05inCert(k05inV3, []byte{1}, root, n, "", k05inUpKey, k05inRootKey)); (err == nil) != r.want {
			t.Errorf("subject value %#x %q: %v, Node accepts: %v", r.tag, r.value, err, r.want)
		}
	}
}

func TestK05PSSIntegersAgainstNode(t *testing.T) {
	h := derTLV(0x30, derTLV(0x06, k05inHex("608648016503040201")))
	mgf := derTLV(0x30, derTLV(0x06, k05inHex("2a864886f70d010108")), h)
	spki, err := x509.MarshalPKIXPublicKey(&k05inRSAKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []struct {
		salt    string
		saltLen int
		trailer string
		want    bool
	}{
		{"20", 32, "", true},
		{"0020", 32, "", false},
		{"ff", 190, "", false},
		{"00be", 190, "", true},
		{"20", 32, "01", true},
		{"20", 32, "0001", false},
		{"20", 32, "ff", false},
		{"20", 32, "02", false},
		{"ffe0", 32, "", false},
	} {
		params := [][]byte{derTLV(0xa0, h), derTLV(0xa1, mgf), derTLV(0xa2, derTLV(0x02, k05inHex(r.salt)))}
		if r.trailer != "" {
			params = append(params, derTLV(0xa3, derTLV(0x02, k05inHex(r.trailer))))
		}
		alg := derTLV(0x30, derTLV(0x06, k05inHex("2a864886f70d01010a")), derTLV(0x30, params...))
		tbs := derTLV(0x30, k05inV3, derTLV(0x02, []byte{1}), alg, k05inName(0x0c, []byte("root")), k05inValidity(), k05inName(0x0c, []byte("up")), spki)
		d := sha256.Sum256(tbs)
		sig, err := rsa.SignPSS(rand.Reader, k05inRSAKey, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: r.saltLen})
		if err != nil {
			t.Fatal(err)
		}
		c, err := parseCertDER(derTLV(0x30, tbs, alg, derTLV(0x03, []byte{0}, sig)))
		if err != nil {
			t.Fatal(err)
		}
		k, err := keyOfCert(c)
		if err != nil {
			t.Fatal(err)
		}
		if got := certSigOK(c, k); got != r.want {
			t.Errorf("salt %q trailer %q: %v, Node says %v", r.salt, r.trailer, got, r.want)
		}
	}
}

// The delegated responder path: a really signed responder that X509_check_issued refuses in Node is not the chain's.
func TestK05OcspDelegatedResponderIssuerLink(t *testing.T) {
	f := g02newFx(t)
	notSigned := g02no("delegated responder certificate is not signed by the supplied NVIDIA chain")
	good := g02ok("good")
	rid := g02byName(g02att(t, f.responder(t, nil, f.inter, f.interK).Raw))
	aki, san := asn1.ObjectIdentifier{2, 5, 29, 35}, asn1.ObjectIdentifier{2, 5, 29, 17}
	bad := derTLV(0x04, []byte{1})
	dir := func(n []byte) []byte { return derTLV(0xa4, n) }
	for _, r := range []struct {
		name string
		id   asn1.ObjectIdentifier
		v    []byte
		want ocspResult
	}{
		{"AKI serial of the issuer", aki, derTLV(0x30, derTLV(0x82, []byte{2})), good},
		{"AKI other serial", aki, derTLV(0x30, derTLV(0x82, []byte{3})), notSigned},
		{"AKI directory name of the issuer", aki, derTLV(0x30, derTLV(0xa1, dir(f.inter.RawIssuer))), good},
		{"AKI other directory name", aki, derTLV(0x30, derTLV(0xa1, dir(f.inter.RawSubject))), notSigned},
		{"AKI later name that does not decode", aki, derTLV(0x30, derTLV(0xa1, dir(f.inter.RawIssuer), derTLV(0xa4, bad))), notSigned},
		{"SAN that does not decode", san, derTLV(0x30, derTLV(0xa4, bad)), notSigned},
	} {
		resp := f.responder(t, func(c *x509.Certificate) { c.ExtraExtensions = []pkix.Extension{{Id: r.id, Value: r.v}} }, f.inter, f.interK)
		der := f.mod(t, func(x *g02rsp) { x.rid, x.certs, x.signer = rid, g02certs(resp.Raw), f.respK })
		if got := verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs); got != r.want {
			t.Errorf("%s: got %+v, want %+v", r.name, got, r.want)
		}
	}
}

var k05inLinkRows = []struct {
	name, child, up string
	want            bool
}{
	{"no extensions", "", "551d0e=040407070707", true},
	{"AKID key id", "551d23=3006800407070707", "551d0e=040407070707", true},
	{"AKID empty", "551d23=3000", "551d0e=040407070707", true},
	{"AKID all three", "551d23=301e800407070707a113a411300f310d300b06035504030c04726f6f74820111", "551d0e=040407070707", true},
	{"AKID name and serial", "551d23=3018a113a411300f310d300b06035504030c04726f6f74820111", "551d0e=040407070707", true},
	{"AKID key id and serial", "551d23=3009800407070707820111", "551d0e=040407070707", true},
	{"AKID no directory name", "551d23=3016800407070707a10b8209612e6578616d706c65820111", "551d0e=040407070707", true},
	{"AKID second directory name differs", "551d23=302e800407070707a126a411300f310d300b06035504030c04726f6f74a411300f310d300b06035504030c046e6f7065", "551d0e=040407070707", true},
	{"AKID empty names", "551d23=3008800407070707a100", "551d0e=040407070707", true},
	{"AKID other key id", "551d23=3006800408080808", "551d0e=040407070707", false},
	{"AKID other serial", "551d23=3009800407070707820112", "551d0e=040407070707", false},
	{"AKID padded serial", "551d23=300a80040707070782020011", "551d0e=040407070707", false},
	{"AKID empty serial", "551d23=30088004070707078200", "551d0e=040407070707", false},
	{"AKID padded negative serial", "551d23=300a8004070707078202ff80", "551d0e=040407070707", false},
	{"AKID other directory name", "551d23=301b800407070707a113a411300f310d300b06035504030c046e6f7065", "551d0e=040407070707", false},
	{"AKID other directory name, right serial", "551d23=301e800407070707a113a411300f310d300b06035504030c046e6f7065820111", "551d0e=040407070707", false},
	{"AKID DNS then other directory name", "551d23=3026800407070707a11e8209612e6578616d706c65a411300f310d300b06035504030c046e6f7065", "551d0e=040407070707", false},
	{"AKID other directory name first", "551d23=302e800407070707a126a411300f310d300b06035504030c046e6f7065a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID names overrun", "551d23=300a800407070707a1023005", "551d0e=040407070707", false},
	{"AKID name with undefined tag 0x89", "551d23=300b800407070707a103890101", "551d0e=040407070707", false},
	{"AKID directory name not a Name", "551d23=300d800407070707a105a403040101", "551d0e=040407070707", false},
	{"AKID later directory name not a Name", "551d23=3020800407070707a118a411300f310d300b06035504030c04726f6f74a403040101", "551d0e=040407070707", false},
	{"AKID directory name, two Names", "551d23=302c800407070707a124a422300f310d300b06035504030c04726f6f74300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID serial before key id", "551d23=3009820111800407070707", "551d0e=040407070707", false},
	{"AKID names before key id", "551d23=301ba113a411300f310d300b06035504030c04726f6f74800407070707", "551d0e=040407070707", false},
	{"AKID serial before names", "551d23=3018820111a113a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID key id twice", "551d23=300c800407070707800407070707", "551d0e=040407070707", false},
	{"AKID OCTET STRING member", "551d23=3003040101", "551d0e=040407070707", false},
	{"AKID not a SEQUENCE", "551d23=040101", "551d0e=040407070707", false},
	{"AKID empty value", "551d23=", "551d0e=040407070707", false},
	{"AKID twice", "551d23=3006800407070707 551d23=3006800407070707", "551d0e=040407070707", false},
	{"child SKID not an OCTET STRING", "551d0e=3000", "551d0e=040407070707", false},
	{"child SKID twice", "551d0e=040407070707 551d0e=040407070707", "551d0e=040407070707", false},
	{"issuer SKID not an OCTET STRING", "", "551d0e=3000", false},
	{"issuer SKID twice", "", "551d0e=040407070707 551d0e=040407070707", false},
	{"issuer without SKID, AKID key id", "551d23=3006800407070707", "", true},
	{"issuer AKID not a SEQUENCE", "", "551d0e=040407070707 551d23=040101", false},
	{"issuer AKID values do not matter", "", "551d0e=040407070707 551d23=3003820177", true},
	{"AKID later directory name: empty Name", "551d23=301f800407070707a117a411300f310d300b06035504030c04726f6f74a4023000", "551d0e=040407070707", true},
	{"AKID later directory name: empty RDN", "551d23=3021800407070707a119a411300f310d300b06035504030c04726f6f74a40430023100", "551d0e=040407070707", true},
	{"AKID later directory name: Name", "551d23=302f800407070707a127a411300f310d300b06035504030c04726f6f74a4123010310e300c06035504030c056c61746572", "551d0e=040407070707", true},
	{"AKID later directory name: empty UTF8", "551d23=302a800407070707a122a411300f310d300b06035504030c04726f6f74a40d300b3109300706035504030c00", "551d0e=040407070707", true},
	{"AKID later directory name: Printable high", "551d23=302c800407070707a124a411300f310d300b06035504030c04726f6f74a40f300d310b300906035504031302c3a9", "551d0e=040407070707", true},
	{"AKID later directory name: IA5 high", "551d23=302b800407070707a123a411300f310d300b06035504030c04726f6f74a40e300c310a300806035504031601e9", "551d0e=040407070707", true},
	{"AKID later directory name: T61 high", "551d23=302b800407070707a123a411300f310d300b06035504030c04726f6f74a40e300c310a300806035504031401e9", "551d0e=040407070707", true},
	{"AKID later directory name: two attributes", "551d23=3035800407070707a12da411300f310d300b06035504030c04726f6f74a41830163114300806035504060c0162300806035504030c0161", "551d0e=040407070707", true},
	{"AKID later directory name: two RDNs", "551d23=3037800407070707a12fa411300f310d300b06035504030c04726f6f74a41a3018310a300806035504030c0161310a300806035504030c0162", "551d0e=040407070707", true},
	{"AKID later directory name: BMP", "551d23=302c800407070707a124a411300f310d300b06035504030c04726f6f74a40f300d310b300906035504031e020041", "551d0e=040407070707", true},
	{"AKID later directory name: Universal", "551d23=302e800407070707a126a411300f310d300b06035504030c04726f6f74a411300f310d300b06035504031c0400000041", "551d0e=040407070707", true},
	{"AKID later directory name: Numeric", "551d23=302b800407070707a123a411300f310d300b06035504030c04726f6f74a40e300c310a30080603550403120131", "551d0e=040407070707", true},
	{"AKID later directory name: BIT STRING", "551d23=302c800407070707a124a411300f310d300b06035504030c04726f6f74a40f300d310b3009060355040303020001", "551d0e=040407070707", true},
	{"AKID later directory name: SEQUENCE", "551d23=302a800407070707a122a411300f310d300b06035504030c04726f6f74a40d300b3109300706035504033000", "551d0e=040407070707", true},
	{"AKID later directory name: RDN is a SEQUENCE", "551d23=3021800407070707a119a411300f310d300b06035504030c04726f6f74a40430023000", "551d0e=040407070707", false},
	{"AKID later directory name: RDN member not an attribute", "551d23=3024800407070707a11ca411300f310d300b06035504030c04726f6f74a40730053103040101", "551d0e=040407070707", false},
	{"AKID later directory name: attribute without value", "551d23=3028800407070707a120a411300f310d300b06035504030c04726f6f74a40b3009310730050603550403", "551d0e=040407070707", false},
	{"AKID later directory name: empty attribute", "551d23=3023800407070707a11ba411300f310d300b06035504030c04726f6f74a406300431023000", "551d0e=040407070707", false},
	{"AKID later directory name: attribute type not an OID", "551d23=3029800407070707a121a411300f310d300b06035504030c04726f6f74a40c300a310830060401010c0178", "551d0e=040407070707", false},
	{"AKID later directory name: attribute with two values", "551d23=302e800407070707a126a411300f310d300b06035504030c04726f6f74a411300f310d300b06035504030c01780c0179", "551d0e=040407070707", false},
	{"AKID later directory name: empty OID", "551d23=3028800407070707a120a411300f310d300b06035504030c04726f6f74a40b30093107300506000c0178", "551d0e=040407070707", false},
	{"AKID later directory name: OID 0x80", "551d23=302a800407070707a122a411300f310d300b06035504030c04726f6f74a40d300b31093007060280010c0178", "551d0e=040407070707", false},
	{"AKID later directory name: OID open", "551d23=302a800407070707a122a411300f310d300b06035504030c04726f6f74a40d300b31093007060255840c0178", "551d0e=040407070707", false},
	{"AKID later directory name: OID padded arc", "551d23=302b800407070707a123a411300f310d300b06035504030c04726f6f74a40e300c310a300806035580010c0178", "551d0e=040407070707", false},
	{"AKID later directory name: INTEGER", "551d23=302b800407070707a123a411300f310d300b06035504030c04726f6f74a40e300c310a30080603550403020101", "551d0e=040407070707", false},
	{"AKID later directory name: NULL", "551d23=302a800407070707a122a411300f310d300b06035504030c04726f6f74a40d300b3109300706035504030500", "551d0e=040407070707", false},
	{"AKID later directory name: ENUMERATED", "551d23=302b800407070707a123a411300f310d300b06035504030c04726f6f74a40e300c310a300806035504030a0101", "551d0e=040407070707", false},
	{"AKID later directory name: bad UTF8", "551d23=302c800407070707a124a411300f310d300b06035504030c04726f6f74a40f300d310b300906035504030c02c328", "551d0e=040407070707", false},
	{"AKID later directory name: UTF8 surrogate", "551d23=302d800407070707a125a411300f310d300b06035504030c04726f6f74a410300e310c300a06035504030c03eda080", "551d0e=040407070707", false},
	{"AKID later directory name: UTF8 overlong", "551d23=302c800407070707a124a411300f310d300b06035504030c04726f6f74a40f300d310b300906035504030c02c080", "551d0e=040407070707", false},
	{"AKID later directory name: BMP odd", "551d23=302d800407070707a125a411300f310d300b06035504030c04726f6f74a410300e310c300a06035504031e03004100", "551d0e=040407070707", false},
	{"AKID later directory name: BMP surrogate", "551d23=302e800407070707a126a411300f310d300b06035504030c04726f6f74a411300f310d300b06035504031e04d800dc00", "551d0e=040407070707", false},
	{"AKID later directory name: Universal short", "551d23=302d800407070707a125a411300f310d300b06035504030c04726f6f74a410300e310c300a06035504031c03000041", "551d0e=040407070707", false},
	{"AKID later directory name: Universal above Unicode", "551d23=302e800407070707a126a411300f310d300b06035504030c04726f6f74a411300f310d300b06035504031c0400110000", "551d0e=040407070707", false},
	{"AKID later directory name: Universal surrogate", "551d23=302e800407070707a126a411300f310d300b06035504030c04726f6f74a411300f310d300b06035504031c040000d800", "551d0e=040407070707", false},
	{"AKID later directory name: BIT STRING unused 9", "551d23=302c800407070707a124a411300f310d300b06035504030c04726f6f74a40f300d310b3009060355040303020901", "551d0e=040407070707", false},
	{"AKID later directory name: VisibleString", "551d23=302b800407070707a123a411300f310d300b06035504030c04726f6f74a40e300c310a300806035504031a0178", "551d0e=040407070707", false},
	{"AKID later directory name: GeneralString", "551d23=302b800407070707a123a411300f310d300b06035504030c04726f6f74a40e300c310a300806035504031b0178", "551d0e=040407070707", false},
	{"AKID later directory name: attribute overruns", "551d23=302c800407070707a124a411300f310d300b06035504030c04726f6f74a40f300d310b300906035504030c096161", "551d0e=040407070707", false},
	{"AKID later directory name: junk after attribute", "551d23=302e800407070707a126a411300f310d300b06035504030c04726f6f74a411300f310d300806035504030c0178040101", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName", "551d23=3027800407070707a11fa00a0603550403a0030c0178a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: otherName bad UTF8", "551d23=3028800407070707a120a00b0603550403a0040c02c328a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: otherName value INTEGER padded", "551d23=3028800407070707a120a00b0603550403a00402020001a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName value overruns", "551d23=3026800407070707a11ea0090603550403a0020c05a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName two values", "551d23=302a800407070707a122a00d0603550403a0060c01780c0179a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName no value", "551d23=3024800407070707a11ca0070603550403a000a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName trailing member", "551d23=3029800407070707a121a00c0603550403a0030c01780500a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName value [1]", "551d23=3027800407070707a11fa00a0603550403a1030c0178a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName type not an OID", "551d23=3025800407070707a11da008040101a0030c0178a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName empty", "551d23=301d800407070707a115a000a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName type only", "551d23=3022800407070707a11aa0050603550403a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: rfc822", "551d23=301e800407070707a1168101e9a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: DNS", "551d23=301e800407070707a1168201e9a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: empty DNS", "551d23=301d800407070707a1158200a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: URI", "551d23=301e800407070707a1168601e9a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: IP", "551d23=3020800407070707a1188703010203a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: empty IP", "551d23=301d800407070707a1158700a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: registeredID", "551d23=3020800407070707a1188803550403a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: registeredID empty", "551d23=301d800407070707a1158800a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: registeredID 0x80", "551d23=301f800407070707a11788028001a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: registeredID open", "551d23=301f800407070707a11788025584a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: x400 SEQUENCE", "551d23=301d800407070707a115a300a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: x400 any", "551d23=3020800407070707a118a303020101a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: x400 primitive", "551d23=301e800407070707a116830101a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: edi utf8", "551d23=3022800407070707a11aa505a1030c0178a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: edi both", "551d23=3027800407070707a11fa50aa0030c0178a1030c0178a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: edi BMP", "551d23=3023800407070707a11ba506a1041e020041a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", true},
	{"AKID GeneralName: edi BMP odd", "551d23=3022800407070707a11aa505a1031e0100a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: edi empty", "551d23=301d800407070707a115a500a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: edi [0] only", "551d23=3022800407070707a11aa505a0030c0178a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: edi empty [1]", "551d23=301f800407070707a117a502a100a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: edi IA5", "551d23=3022800407070707a11aa505a103160178a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: edi INTEGER", "551d23=3022800407070707a11aa505a103020101a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: edi [1] then [0]", "551d23=3027800407070707a11fa50aa1030c0178a0030c0178a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: edi not constructed", "551d23=301e800407070707a116850101a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: directoryName primitive", "551d23=301e800407070707a116840101a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: directoryName empty", "551d23=301d800407070707a115a400a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: undefined [9]", "551d23=301e800407070707a116890101a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: undefined [8] constructed", "551d23=301d800407070707a115a800a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"child basicConstraints: empty", "551d13=3000", "551d0e=040407070707", true},
	{"issuer basicConstraints: empty", "", "551d0e=040407070707 551d13=3000", true},
	{"child basicConstraints: cA true", "551d13=30030101ff", "551d0e=040407070707", true},
	{"issuer basicConstraints: cA true", "", "551d0e=040407070707 551d13=30030101ff", true},
	{"child basicConstraints: cA 0x55", "551d13=3003010155", "551d0e=040407070707", true},
	{"issuer basicConstraints: cA 0x55", "", "551d0e=040407070707 551d13=3003010155", true},
	{"child basicConstraints: cA false", "551d13=3003010100", "551d0e=040407070707", true},
	{"issuer basicConstraints: cA false", "", "551d0e=040407070707 551d13=3003010100", true},
	{"child basicConstraints: cA pathLen", "551d13=30060101ff020101", "551d0e=040407070707", true},
	{"issuer basicConstraints: cA pathLen", "", "551d0e=040407070707 551d13=30060101ff020101", true},
	{"child basicConstraints: pathLen alone", "551d13=3003020101", "551d0e=040407070707", true},
	{"issuer basicConstraints: pathLen alone", "", "551d0e=040407070707 551d13=3003020101", true},
	{"child basicConstraints: trailing bytes", "551d13=30000500", "551d0e=040407070707", true},
	{"issuer basicConstraints: trailing bytes", "", "551d0e=040407070707 551d13=30000500", true},
	{"child basicConstraints: pathLen first", "551d13=30060201010101ff", "551d0e=040407070707", false},
	{"issuer basicConstraints: pathLen first", "", "551d0e=040407070707 551d13=30060201010101ff", false},
	{"child basicConstraints: long cA", "551d13=30040102ffff", "551d0e=040407070707", false},
	{"issuer basicConstraints: long cA", "", "551d0e=040407070707 551d13=30040102ffff", false},
	{"child basicConstraints: empty cA", "551d13=30020100", "551d0e=040407070707", false},
	{"issuer basicConstraints: empty cA", "", "551d0e=040407070707 551d13=30020100", false},
	{"child basicConstraints: padded pathLen", "551d13=30070101ff02020001", "551d0e=040407070707", false},
	{"issuer basicConstraints: padded pathLen", "", "551d0e=040407070707 551d13=30070101ff02020001", false},
	{"child basicConstraints: empty pathLen", "551d13=30050101ff0200", "551d0e=040407070707", false},
	{"issuer basicConstraints: empty pathLen", "", "551d0e=040407070707 551d13=30050101ff0200", false},
	{"child basicConstraints: negative pathLen", "551d13=30060101ff0201ff", "551d0e=040407070707", false},
	{"issuer basicConstraints: negative pathLen", "", "551d0e=040407070707 551d13=30060101ff0201ff", false},
	{"child basicConstraints: trailing member", "551d13=30080101ff0201010500", "551d0e=040407070707", false},
	{"issuer basicConstraints: trailing member", "", "551d0e=040407070707 551d13=30080101ff0201010500", false},
	{"child basicConstraints: not a SEQUENCE", "551d13=040101", "551d0e=040407070707", false},
	{"issuer basicConstraints: not a SEQUENCE", "", "551d0e=040407070707 551d13=040101", false},
	{"child keyUsage: digitalSignature keyCertSign", "551d0f=03020284", "551d0e=040407070707", true},
	{"issuer keyUsage: digitalSignature keyCertSign", "", "551d0e=040407070707 551d0f=03020284", true},
	{"child keyUsage: empty BIT STRING", "551d0f=0300", "551d0e=040407070707", false},
	{"issuer keyUsage: empty BIT STRING", "", "551d0e=040407070707 551d0f=0300", false},
	{"child keyUsage: no bits", "551d0f=030100", "551d0e=040407070707", false},
	{"issuer keyUsage: no bits", "", "551d0e=040407070707 551d0f=030100", false},
	{"child keyUsage: unused 8", "551d0f=030208a0", "551d0e=040407070707", false},
	{"issuer keyUsage: unused 8", "", "551d0e=040407070707 551d0f=030208a0", false},
	{"child keyUsage: not a BIT STRING", "551d0f=040100", "551d0e=040407070707", false},
	{"issuer keyUsage: not a BIT STRING", "", "551d0e=040407070707 551d0f=040100", false},
	{"child keyUsage: overrun", "551d0f=030500", "551d0e=040407070707", false},
	{"issuer keyUsage: overrun", "", "551d0e=040407070707 551d0f=030500", false},
	{"child keyUsage: empty value", "551d0f=", "551d0e=040407070707", false},
	{"issuer keyUsage: empty value", "", "551d0e=040407070707 551d0f=", false},
	{"child keyUsage: all zero", "551d0f=03020000", "551d0e=040407070707", false},
	{"issuer keyUsage: all zero", "", "551d0e=040407070707 551d0f=03020000", false},
	{"child keyUsage: all masked", "551d0f=03020304", "551d0e=040407070707", false},
	{"issuer keyUsage: all masked", "", "551d0e=040407070707 551d0f=03020304", false},
	{"child keyUsage: bit under the mask", "551d0f=03020701", "551d0e=040407070707", false},
	{"issuer keyUsage: bit under the mask", "", "551d0e=040407070707 551d0f=03020701", false},
	{"child keyUsage: second byte only", "551d0f=0303000080", "551d0e=040407070707", true},
	{"issuer keyUsage: second byte only", "", "551d0e=040407070707 551d0f=0303000080", false},
	{"child keyUsage: third byte only", "551d0f=030400000004", "551d0e=040407070707", false},
	{"issuer keyUsage: third byte only", "", "551d0e=040407070707 551d0f=030400000004", false},
	{"child extendedKeyUsage: one", "551d25=300a06082b06010505070301", "551d0e=040407070707", true},
	{"issuer extendedKeyUsage: one", "", "551d0e=040407070707 551d25=300a06082b06010505070301", true},
	{"child extendedKeyUsage: empty", "551d25=3000", "551d0e=040407070707", true},
	{"issuer extendedKeyUsage: empty", "", "551d0e=040407070707 551d25=3000", true},
	{"child extendedKeyUsage: not an OID", "551d25=3003040101", "551d0e=040407070707", false},
	{"issuer extendedKeyUsage: not an OID", "", "551d0e=040407070707 551d25=3003040101", false},
	{"child extendedKeyUsage: OID 0x80", "551d25=300406028001", "551d0e=040407070707", false},
	{"issuer extendedKeyUsage: OID 0x80", "", "551d0e=040407070707 551d25=300406028001", false},
	{"child extendedKeyUsage: not a SEQUENCE", "551d25=040101", "551d0e=040407070707", false},
	{"issuer extendedKeyUsage: not a SEQUENCE", "", "551d0e=040407070707 551d25=040101", false},
	{"child subjectAltName: URI", "551d11=300b860968747470733a2f2f61", "551d0e=040407070707", true},
	{"issuer subjectAltName: URI", "", "551d0e=040407070707 551d11=300b860968747470733a2f2f61", true},
	{"child subjectAltName: empty", "551d11=3000", "551d0e=040407070707", true},
	{"issuer subjectAltName: empty", "", "551d0e=040407070707 551d11=3000", true},
	{"child subjectAltName: otherName", "551d11=300ca00a0603550403a0030c0178", "551d0e=040407070707", true},
	{"issuer subjectAltName: otherName", "", "551d0e=040407070707 551d11=300ca00a0603550403a0030c0178", true},
	{"child subjectAltName: otherName two values", "551d11=300fa00d0603550403a0060c01780c0179", "551d0e=040407070707", false},
	{"issuer subjectAltName: otherName two values", "", "551d0e=040407070707 551d11=300fa00d0603550403a0060c01780c0179", false},
	{"child subjectAltName: otherName no value", "551d11=3009a0070603550403a000", "551d0e=040407070707", false},
	{"issuer subjectAltName: otherName no value", "", "551d0e=040407070707 551d11=3009a0070603550403a000", false},
	{"child subjectAltName: otherName trailing", "551d11=300ea00c0603550403a0030c01780500", "551d0e=040407070707", false},
	{"issuer subjectAltName: otherName trailing", "", "551d0e=040407070707 551d11=300ea00c0603550403a0030c01780500", false},
	{"child subjectAltName: otherName [1]", "551d11=300ca00a0603550403a1030c0178", "551d0e=040407070707", false},
	{"issuer subjectAltName: otherName [1]", "", "551d0e=040407070707 551d11=300ca00a0603550403a1030c0178", false},
	{"child subjectAltName: undefined [9]", "551d11=3003890101", "551d0e=040407070707", false},
	{"issuer subjectAltName: undefined [9]", "", "551d0e=040407070707 551d11=3003890101", false},
	{"child subjectAltName: directoryName not a Name", "551d11=3005a403040101", "551d0e=040407070707", false},
	{"issuer subjectAltName: directoryName not a Name", "", "551d0e=040407070707 551d11=3005a403040101", false},
	{"child subjectAltName: directoryName bad UTF8", "551d11=3011a40f300d310b300906035504030c02c328", "551d0e=040407070707", false},
	{"issuer subjectAltName: directoryName bad UTF8", "", "551d0e=040407070707 551d11=3011a40f300d310b300906035504030c02c328", false},
	{"child subjectAltName: not a SEQUENCE", "551d11=040101", "551d0e=040407070707", false},
	{"issuer subjectAltName: not a SEQUENCE", "", "551d0e=040407070707 551d11=040101", false},
	{"child nameConstraints: permitted", "551d1e=3007a0053003820161", "551d0e=040407070707", true},
	{"issuer nameConstraints: permitted", "", "551d0e=040407070707 551d1e=3007a0053003820161", true},
	{"child nameConstraints: empty", "551d1e=3000", "551d0e=040407070707", true},
	{"issuer nameConstraints: empty", "", "551d0e=040407070707 551d1e=3000", true},
	{"child nameConstraints: both", "551d1e=300ea0053003820161a1053003820162", "551d0e=040407070707", true},
	{"issuer nameConstraints: both", "", "551d0e=040407070707 551d1e=300ea0053003820161a1053003820162", true},
	{"child nameConstraints: empty list", "551d1e=3002a000", "551d0e=040407070707", true},
	{"issuer nameConstraints: empty list", "", "551d0e=040407070707 551d1e=3002a000", true},
	{"child nameConstraints: min max", "551d1e=300da00b3009820161800100810101", "551d0e=040407070707", true},
	{"issuer nameConstraints: min max", "", "551d0e=040407070707 551d1e=300da00b3009820161800100810101", true},
	{"child nameConstraints: excluded first", "551d1e=300ea1053003820162a0053003820161", "551d0e=040407070707", false},
	{"issuer nameConstraints: excluded first", "", "551d0e=040407070707 551d1e=300ea1053003820162a0053003820161", false},
	{"child nameConstraints: subtree not a SEQUENCE", "551d1e=3005a003040101", "551d0e=040407070707", false},
	{"issuer nameConstraints: subtree not a SEQUENCE", "", "551d0e=040407070707 551d1e=3005a003040101", false},
	{"child nameConstraints: subtree no base", "551d1e=3004a0023000", "551d0e=040407070707", false},
	{"issuer nameConstraints: subtree no base", "", "551d0e=040407070707 551d1e=3004a0023000", false},
	{"child nameConstraints: max before min", "551d1e=300da00b3009820161810101800100", "551d0e=040407070707", false},
	{"issuer nameConstraints: max before min", "", "551d0e=040407070707 551d1e=300da00b3009820161810101800100", false},
	{"child nameConstraints: padded min", "551d1e=300ba009300782016180020001", "551d0e=040407070707", false},
	{"issuer nameConstraints: padded min", "", "551d0e=040407070707 551d1e=300ba009300782016180020001", false},
	{"child nameConstraints: primitive member", "551d1e=3003800101", "551d0e=040407070707", false},
	{"issuer nameConstraints: primitive member", "", "551d0e=040407070707 551d1e=3003800101", false},
	{"child nameConstraints: two bases", "551d1e=300aa0083006820161820162", "551d0e=040407070707", false},
	{"issuer nameConstraints: two bases", "", "551d0e=040407070707 551d1e=300aa0083006820161820162", false},
	{"child nameConstraints: base bare", "551d1e=3005a003820161", "551d0e=040407070707", false},
	{"issuer nameConstraints: base bare", "", "551d0e=040407070707 551d1e=3005a003820161", false},
	{"child nameConstraints: base undefined", "551d1e=3007a0053003890101", "551d0e=040407070707", false},
	{"issuer nameConstraints: base undefined", "", "551d0e=040407070707 551d1e=3007a0053003890101", false},
	{"child nameConstraints: not a SEQUENCE", "551d1e=040101", "551d0e=040407070707", false},
	{"issuer nameConstraints: not a SEQUENCE", "", "551d0e=040407070707 551d1e=040101", false},
	{"child cRLDistributionPoints: URI", "551d1f=3011300fa00da00b860968747470733a2f2f61", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: URI", "", "551d0e=040407070707 551d1f=3011300fa00da00b860968747470733a2f2f61", true},
	{"child cRLDistributionPoints: empty", "551d1f=3000", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: empty", "", "551d0e=040407070707 551d1f=3000", true},
	{"child cRLDistributionPoints: RDN name", "551d1f=3010300ea00ca10a300806035504030c0178", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: RDN name", "", "551d0e=040407070707 551d1f=3010300ea00ca10a300806035504030c0178", true},
	{"child cRLDistributionPoints: cRLIssuer", "551d1f=300f300da20b860968747470733a2f2f61", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: cRLIssuer", "", "551d0e=040407070707 551d1f=300f300da20b860968747470733a2f2f61", true},
	{"child cRLDistributionPoints: reasons", "551d1f=30153013a00da00b860968747470733a2f2f6181020180", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: reasons", "", "551d0e=040407070707 551d1f=30153013a00da00b860968747470733a2f2f6181020180", true},
	{"child cRLDistributionPoints: empty reasons", "551d1f=30143012a00da00b860968747470733a2f2f61810100", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: empty reasons", "", "551d0e=040407070707 551d1f=30143012a00da00b860968747470733a2f2f61810100", true},
	{"child cRLDistributionPoints: no names", "551d1f=30063004a002a000", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: no names", "", "551d0e=040407070707 551d1f=30063004a002a000", true},
	{"child cRLDistributionPoints: empty RDN", "551d1f=30063004a002a100", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: empty RDN", "", "551d0e=040407070707 551d1f=30063004a002a100", true},
	{"child cRLDistributionPoints: empty point", "551d1f=30023000", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: empty point", "", "551d0e=040407070707 551d1f=30023000", false},
	{"child cRLDistributionPoints: point not a SEQUENCE", "551d1f=3003040101", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: point not a SEQUENCE", "", "551d0e=040407070707 551d1f=3003040101", false},
	{"child cRLDistributionPoints: RDN member not an attribute", "551d1f=30093007a005a103040101", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: RDN member not an attribute", "", "551d0e=040407070707 551d1f=30093007a005a103040101", false},
	{"child cRLDistributionPoints: reasons alone", "551d1f=3006300481020180", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: reasons alone", "", "551d0e=040407070707 551d1f=3006300481020180", false},
	{"child cRLDistributionPoints: cRLIssuer undefined", "551d1f=30073005a203890101", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: cRLIssuer undefined", "", "551d0e=040407070707 551d1f=30073005a203890101", false},
	{"child cRLDistributionPoints: empty cRLIssuer", "551d1f=30043002a200", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: empty cRLIssuer", "", "551d0e=040407070707 551d1f=30043002a200", false},
	{"child cRLDistributionPoints: cRLIssuer first", "551d1f=301e301ca20b860968747470733a2f2f61a00da00b860968747470733a2f2f61", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: cRLIssuer first", "", "551d0e=040407070707 551d1f=301e301ca20b860968747470733a2f2f61a00da00b860968747470733a2f2f61", false},
	{"child cRLDistributionPoints: empty name", "551d1f=30043002a000", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: empty name", "", "551d0e=040407070707 551d1f=30043002a000", false},
	{"child cRLDistributionPoints: name [2]", "551d1f=3011300fa00da20b860968747470733a2f2f61", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: name [2]", "", "551d0e=040407070707 551d1f=3011300fa00da20b860968747470733a2f2f61", false},
	{"child cRLDistributionPoints: two names", "551d1f=301e301ca01aa00b860968747470733a2f2f61a00b860968747470733a2f2f61", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: two names", "", "551d0e=040407070707 551d1f=301e301ca01aa00b860968747470733a2f2f61a00b860968747470733a2f2f61", false},
	{"child cRLDistributionPoints: full name undefined", "551d1f=30093007a005a003890101", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: full name undefined", "", "551d0e=040407070707 551d1f=30093007a005a003890101", false},
	{"child cRLDistributionPoints: reasons unused 8", "551d1f=30153013a00da00b860968747470733a2f2f6181020880", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: reasons unused 8", "", "551d0e=040407070707 551d1f=30153013a00da00b860968747470733a2f2f6181020880", false},
	{"child cRLDistributionPoints: empty reasons field", "551d1f=30133011a00da00b860968747470733a2f2f618100", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: empty reasons field", "", "551d0e=040407070707 551d1f=30133011a00da00b860968747470733a2f2f618100", false},
	{"child cRLDistributionPoints: not a SEQUENCE", "551d1f=040101", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: not a SEQUENCE", "", "551d0e=040407070707 551d1f=040101", false},
	{"child basicConstraints twice", "551d13=3000 551d13=3000", "551d0e=040407070707", false},
	{"issuer basicConstraints twice", "", "551d0e=040407070707 551d13=3000 551d13=3000", false},
	{"child keyUsage twice", "551d0f=03020204 551d0f=03020204", "551d0e=040407070707", false},
	{"issuer keyUsage twice", "", "551d0e=040407070707 551d0f=03020204 551d0f=03020204", false},
	{"child extendedKeyUsage twice", "551d25=3000 551d25=3000", "551d0e=040407070707", false},
	{"issuer extendedKeyUsage twice", "", "551d0e=040407070707 551d25=3000 551d25=3000", false},
	{"child subjectAltName twice", "551d11=300b860968747470733a2f2f61 551d11=300b860968747470733a2f2f61", "551d0e=040407070707", false},
	{"issuer subjectAltName twice", "", "551d0e=040407070707 551d11=300b860968747470733a2f2f61 551d11=300b860968747470733a2f2f61", false},
	{"child nameConstraints twice", "551d1e=3000 551d1e=3000", "551d0e=040407070707", false},
	{"issuer nameConstraints twice", "", "551d0e=040407070707 551d1e=3000 551d1e=3000", false},
	{"child cRLDistributionPoints twice", "551d1f=3000 551d1f=3000", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints twice", "", "551d0e=040407070707 551d1f=3000 551d1f=3000", false},
	{"issuer keyUsage: bit 5 set", "", "551d0f=03020204", true},
	{"issuer keyUsage: bit 5 under the unused bits", "", "551d0f=03020304", false},
	{"issuer keyUsage: only digitalSignature", "", "551d0f=03020780", false},
	{"issuer keyUsage: bit 5 in a longer string", "", "551d0f=0303070480", true},
	{"repeated unknown extension", "2a0304=01 2a0304=01", "551d0e=040407070707", true},
	{"malformed certificatePolicies", "551d20=040101", "551d0e=040407070707", true},
	{"malformed authorityInfoAccess", "2b06010505070101=040101", "551d0e=040407070707", true},
	{"child malformed ipAddrBlocks", "2b06010505070107=040101", "551d0e=040407070707", false},
	{"issuer malformed ipAddrBlocks", "", "551d0e=040407070707 2b06010505070107=040101", false},
	{"child malformed autonomousSysIds", "2b06010505070108=040101", "551d0e=040407070707", false},
	{"issuer malformed autonomousSysIds", "", "551d0e=040407070707 2b06010505070108=040101", false},
	{"child malformed proxyCertInfo", "2b0601050507010e=040101", "551d0e=040407070707", false},
	{"issuer malformed proxyCertInfo", "", "551d0e=040407070707 2b0601050507010e=040101", false},
}

var k05inCARows = []struct {
	name, up string
	want     bool
}{
	{"issuer AKID not a SEQUENCE", "551d13=30030101ff 551d23=040101", false},
	{"issuer AKID values do not matter", "551d13=30030101ff 551d23=3003820177", true},
	{"issuer basicConstraints: empty", "551d13=3000", false},
	{"issuer basicConstraints: cA true", "551d13=30030101ff", true},
	{"issuer basicConstraints: cA 0x55", "551d13=3003010155", true},
	{"issuer basicConstraints: cA false", "551d13=3003010100", false},
	{"issuer basicConstraints: cA pathLen", "551d13=30060101ff020101", true},
	{"issuer basicConstraints: pathLen alone", "551d13=3003020101", false},
	{"issuer basicConstraints: trailing bytes", "551d13=30000500", false},
	{"issuer basicConstraints: pathLen first", "551d13=30060201010101ff", false},
	{"issuer basicConstraints: long cA", "551d13=30040102ffff", false},
	{"issuer basicConstraints: empty cA", "551d13=30020100", false},
	{"issuer basicConstraints: padded pathLen", "551d13=30070101ff02020001", false},
	{"issuer basicConstraints: empty pathLen", "551d13=30050101ff0200", false},
	{"issuer basicConstraints: negative pathLen", "551d13=30060101ff0201ff", false},
	{"issuer basicConstraints: trailing member", "551d13=30080101ff0201010500", false},
	{"issuer basicConstraints: not a SEQUENCE", "551d13=040101", false},
	{"issuer keyUsage: digitalSignature keyCertSign", "551d13=30030101ff 551d0f=03020284", true},
	{"issuer keyUsage: empty BIT STRING", "551d13=30030101ff 551d0f=0300", false},
	{"issuer keyUsage: no bits", "551d13=30030101ff 551d0f=030100", false},
	{"issuer keyUsage: unused 8", "551d13=30030101ff 551d0f=030208a0", false},
	{"issuer keyUsage: not a BIT STRING", "551d13=30030101ff 551d0f=040100", false},
	{"issuer keyUsage: overrun", "551d13=30030101ff 551d0f=030500", false},
	{"issuer keyUsage: empty value", "551d13=30030101ff 551d0f=", false},
	{"issuer keyUsage: all zero", "551d13=30030101ff 551d0f=03020000", false},
	{"issuer keyUsage: all masked", "551d13=30030101ff 551d0f=03020304", false},
	{"issuer keyUsage: bit under the mask", "551d13=30030101ff 551d0f=03020701", false},
	{"issuer keyUsage: second byte only", "551d13=30030101ff 551d0f=0303000080", false},
	{"issuer keyUsage: third byte only", "551d13=30030101ff 551d0f=030400000004", false},
	{"issuer extendedKeyUsage: one", "551d13=30030101ff 551d25=300a06082b06010505070301", true},
	{"issuer extendedKeyUsage: empty", "551d13=30030101ff 551d25=3000", true},
	{"issuer extendedKeyUsage: not an OID", "551d13=30030101ff 551d25=3003040101", false},
	{"issuer extendedKeyUsage: OID 0x80", "551d13=30030101ff 551d25=300406028001", false},
	{"issuer extendedKeyUsage: not a SEQUENCE", "551d13=30030101ff 551d25=040101", false},
	{"issuer subjectAltName: URI", "551d13=30030101ff 551d11=300b860968747470733a2f2f61", true},
	{"issuer subjectAltName: empty", "551d13=30030101ff 551d11=3000", true},
	{"issuer subjectAltName: otherName", "551d13=30030101ff 551d11=300ca00a0603550403a0030c0178", true},
	{"issuer subjectAltName: otherName two values", "551d13=30030101ff 551d11=300fa00d0603550403a0060c01780c0179", false},
	{"issuer subjectAltName: otherName no value", "551d13=30030101ff 551d11=3009a0070603550403a000", false},
	{"issuer subjectAltName: otherName trailing", "551d13=30030101ff 551d11=300ea00c0603550403a0030c01780500", false},
	{"issuer subjectAltName: otherName [1]", "551d13=30030101ff 551d11=300ca00a0603550403a1030c0178", false},
	{"issuer subjectAltName: undefined [9]", "551d13=30030101ff 551d11=3003890101", false},
	{"issuer subjectAltName: directoryName not a Name", "551d13=30030101ff 551d11=3005a403040101", false},
	{"issuer subjectAltName: directoryName bad UTF8", "551d13=30030101ff 551d11=3011a40f300d310b300906035504030c02c328", false},
	{"issuer subjectAltName: not a SEQUENCE", "551d13=30030101ff 551d11=040101", false},
	{"issuer nameConstraints: permitted", "551d13=30030101ff 551d1e=3007a0053003820161", true},
	{"issuer nameConstraints: empty", "551d13=30030101ff 551d1e=3000", true},
	{"issuer nameConstraints: both", "551d13=30030101ff 551d1e=300ea0053003820161a1053003820162", true},
	{"issuer nameConstraints: empty list", "551d13=30030101ff 551d1e=3002a000", true},
	{"issuer nameConstraints: min max", "551d13=30030101ff 551d1e=300da00b3009820161800100810101", true},
	{"issuer nameConstraints: excluded first", "551d13=30030101ff 551d1e=300ea1053003820162a0053003820161", false},
	{"issuer nameConstraints: subtree not a SEQUENCE", "551d13=30030101ff 551d1e=3005a003040101", false},
	{"issuer nameConstraints: subtree no base", "551d13=30030101ff 551d1e=3004a0023000", false},
	{"issuer nameConstraints: max before min", "551d13=30030101ff 551d1e=300da00b3009820161810101800100", false},
	{"issuer nameConstraints: padded min", "551d13=30030101ff 551d1e=300ba009300782016180020001", false},
	{"issuer nameConstraints: primitive member", "551d13=30030101ff 551d1e=3003800101", false},
	{"issuer nameConstraints: two bases", "551d13=30030101ff 551d1e=300aa0083006820161820162", false},
	{"issuer nameConstraints: base bare", "551d13=30030101ff 551d1e=3005a003820161", false},
	{"issuer nameConstraints: base undefined", "551d13=30030101ff 551d1e=3007a0053003890101", false},
	{"issuer nameConstraints: not a SEQUENCE", "551d13=30030101ff 551d1e=040101", false},
	{"issuer cRLDistributionPoints: URI", "551d13=30030101ff 551d1f=3011300fa00da00b860968747470733a2f2f61", true},
	{"issuer cRLDistributionPoints: empty", "551d13=30030101ff 551d1f=3000", true},
	{"issuer cRLDistributionPoints: RDN name", "551d13=30030101ff 551d1f=3010300ea00ca10a300806035504030c0178", true},
	{"issuer cRLDistributionPoints: cRLIssuer", "551d13=30030101ff 551d1f=300f300da20b860968747470733a2f2f61", true},
	{"issuer cRLDistributionPoints: reasons", "551d13=30030101ff 551d1f=30153013a00da00b860968747470733a2f2f6181020180", true},
	{"issuer cRLDistributionPoints: empty reasons", "551d13=30030101ff 551d1f=30143012a00da00b860968747470733a2f2f61810100", true},
	{"issuer cRLDistributionPoints: no names", "551d13=30030101ff 551d1f=30063004a002a000", true},
	{"issuer cRLDistributionPoints: empty RDN", "551d13=30030101ff 551d1f=30063004a002a100", true},
	{"issuer cRLDistributionPoints: empty point", "551d13=30030101ff 551d1f=30023000", false},
	{"issuer cRLDistributionPoints: point not a SEQUENCE", "551d13=30030101ff 551d1f=3003040101", false},
	{"issuer cRLDistributionPoints: RDN member not an attribute", "551d13=30030101ff 551d1f=30093007a005a103040101", false},
	{"issuer cRLDistributionPoints: reasons alone", "551d13=30030101ff 551d1f=3006300481020180", false},
	{"issuer cRLDistributionPoints: cRLIssuer undefined", "551d13=30030101ff 551d1f=30073005a203890101", false},
	{"issuer cRLDistributionPoints: empty cRLIssuer", "551d13=30030101ff 551d1f=30043002a200", false},
	{"issuer cRLDistributionPoints: cRLIssuer first", "551d13=30030101ff 551d1f=301e301ca20b860968747470733a2f2f61a00da00b860968747470733a2f2f61", false},
	{"issuer cRLDistributionPoints: empty name", "551d13=30030101ff 551d1f=30043002a000", false},
	{"issuer cRLDistributionPoints: name [2]", "551d13=30030101ff 551d1f=3011300fa00da20b860968747470733a2f2f61", false},
	{"issuer cRLDistributionPoints: two names", "551d13=30030101ff 551d1f=301e301ca01aa00b860968747470733a2f2f61a00b860968747470733a2f2f61", false},
	{"issuer cRLDistributionPoints: full name undefined", "551d13=30030101ff 551d1f=30093007a005a003890101", false},
	{"issuer cRLDistributionPoints: reasons unused 8", "551d13=30030101ff 551d1f=30153013a00da00b860968747470733a2f2f6181020880", false},
	{"issuer cRLDistributionPoints: empty reasons field", "551d13=30030101ff 551d1f=30133011a00da00b860968747470733a2f2f618100", false},
	{"issuer cRLDistributionPoints: not a SEQUENCE", "551d13=30030101ff 551d1f=040101", false},
	{"issuer basicConstraints twice", "551d13=3000 551d13=3000", false},
	{"issuer keyUsage twice", "551d13=30030101ff 551d0f=03020204 551d0f=03020204", false},
	{"issuer extendedKeyUsage twice", "551d13=30030101ff 551d25=3000 551d25=3000", false},
	{"issuer subjectAltName twice", "551d13=30030101ff 551d11=300b860968747470733a2f2f61 551d11=300b860968747470733a2f2f61", false},
	{"issuer nameConstraints twice", "551d13=30030101ff 551d1e=3000 551d1e=3000", false},
	{"issuer cRLDistributionPoints twice", "551d13=30030101ff 551d1f=3000 551d1f=3000", false},
	{"issuer keyUsage: bit 5 set", "551d13=30030101ff 551d0f=03020204", true},
	{"issuer keyUsage: bit 5 under the unused bits", "551d13=30030101ff 551d0f=03020304", false},
	{"issuer keyUsage: only digitalSignature", "551d13=30030101ff 551d0f=03020780", false},
	{"issuer keyUsage: bit 5 in a longer string", "551d13=30030101ff 551d0f=0303070480", true},
	{"issuer malformed ipAddrBlocks", "551d13=30030101ff 2b06010505070107=040101", false},
	{"issuer malformed autonomousSysIds", "551d13=30030101ff 2b06010505070108=040101", false},
	{"issuer malformed proxyCertInfo", "551d13=30030101ff 2b0601050507010e=040101", false},
}
