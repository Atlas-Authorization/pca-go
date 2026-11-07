package pcasigstore

// Verdicts read from Node 26: X509Certificate on really signed P-384 certificates with these exact bytes, the link being
// `child.checkIssued(issuer) && child.verify(issuer.publicKey)`. Extensions are written "oid=value" in hex.
// The last rows are an issuer with a repeated unknown extension: parseCert refuses it, node:crypto reads it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

func k05inGen() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

var k05inRootKey, k05inUpKey, k05inLeafKey = k05inGen(), k05inGen(), k05inGen()

func k05inHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func k05inName(cn string) []byte {
	return enc(0x30, enc(0x31, enc(0x30, g07sCat(enc(0x06, []byte{0x55, 4, 3}), enc(0x0c, []byte(cn))))))
}

func k05inCert(serial byte, iss, sub []byte, extSpec string, key, signer *ecdsa.PrivateKey) []byte {
	alg := enc(0x30, enc(0x06, []byte{0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 3}))
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	var exts []byte
	for _, e := range strings.Fields(extSpec) {
		id, value, _ := strings.Cut(e, "=")
		exts = append(exts, enc(0x30, g07sCat(enc(0x06, k05inHex(id)), enc(0x04, k05inHex(value))))...)
	}
	var block []byte
	if extSpec != "" {
		block = enc(0xa3, enc(0x30, exts))
	}
	validity := enc(0x30, g07sCat(enc(0x17, []byte("250101000000Z")), enc(0x17, []byte("350101000000Z"))))
	tbs := enc(0x30, g07sCat(enc(0xa0, enc(0x02, []byte{2})), enc(0x02, []byte{serial}), alg, iss, validity, sub, spki, block))
	d := sha512.Sum384(tbs)
	sig, err := ecdsa.SignASN1(rand.Reader, signer, d[:])
	if err != nil {
		panic(err)
	}
	return enc(0x30, g07sCat(tbs, alg, enc(0x03, append([]byte{0}, sig...))))
}

func k05inParse(t *testing.T, der []byte) *pca.NodeCert {
	t.Helper()
	c, err := pca.ParseNodeCert(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestK05IssuerLinkAgainstNode(t *testing.T) {
	root, upName := k05inName("root"), k05inName("up")
	for _, r := range k05inLinkRows {
		upRaw := k05inCert(0x11, root, upName, r.up, k05inUpKey, k05inRootKey)
		cRaw := k05inCert(0x22, upName, k05inName("leaf"), r.child, k05inLeafKey, k05inUpKey)
		up, c := k05inParse(t, upRaw), k05inParse(t, cRaw)
		if !c.SignedBy(up) {
			t.Fatalf("%s: not really signed", r.name)
		}
		if got := checkIssued(c, cRaw, up, upRaw); got != r.want {
			t.Errorf("%s: %v, Node says %v", r.name, got, r.want)
		}
	}
	upRaw := k05inCert(0x11, root, upName, "", k05inUpKey, k05inRootKey)
	cRaw := k05inCert(0x22, k05inName("nope"), k05inName("leaf"), "", k05inLeafKey, k05inUpKey)
	if checkIssued(k05inParse(t, cRaw), cRaw, k05inParse(t, upRaw), upRaw) {
		t.Error("the child names another issuer")
	}
}

var k05inLinkRows = []struct {
	name, child, up string
	want            bool
}{
	{"AKID key id", "551d23=3006800407070707", "551d0e=040407070707", true},
	{"AKID all three", "551d23=301e800407070707a113a411300f310d300b06035504030c04726f6f74820111", "551d0e=040407070707", true},
	{"AKID other key id", "551d23=3006800408080808", "551d0e=040407070707", false},
	{"AKID other serial", "551d23=3009800407070707820112", "551d0e=040407070707", false},
	{"AKID padded serial", "551d23=300a80040707070782020011", "551d0e=040407070707", false},
	{"AKID other directory name", "551d23=301b800407070707a113a411300f310d300b06035504030c046e6f7065", "551d0e=040407070707", false},
	{"AKID other directory name, right serial", "551d23=301e800407070707a113a411300f310d300b06035504030c046e6f7065820111", "551d0e=040407070707", false},
	{"AKID other directory name first", "551d23=302e800407070707a126a411300f310d300b06035504030c046e6f7065a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"issuer SKID not an OCTET STRING", "", "551d0e=3000", false},
	{"issuer SKID twice", "", "551d0e=040407070707 551d0e=040407070707", false},
	{"issuer AKID not a SEQUENCE", "", "551d0e=040407070707 551d23=040101", false},
	{"AKID later directory name: Name", "551d23=302f800407070707a127a411300f310d300b06035504030c04726f6f74a4123010310e300c06035504030c056c61746572", "551d0e=040407070707", true},
	{"AKID later directory name: bad UTF8", "551d23=302c800407070707a124a411300f310d300b06035504030c04726f6f74a40f300d310b300906035504030c02c328", "551d0e=040407070707", false},
	{"AKID GeneralName: otherName two values", "551d23=302a800407070707a122a00d0603550403a0060c01780c0179a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"AKID GeneralName: undefined [9]", "551d23=301e800407070707a116890101a411300f310d300b06035504030c04726f6f74", "551d0e=040407070707", false},
	{"child basicConstraints: padded pathLen", "551d13=30070101ff02020001", "551d0e=040407070707", false},
	{"issuer basicConstraints: padded pathLen", "", "551d0e=040407070707 551d13=30070101ff02020001", false},
	{"child keyUsage: not a BIT STRING", "551d0f=040100", "551d0e=040407070707", false},
	{"issuer keyUsage: not a BIT STRING", "", "551d0e=040407070707 551d0f=040100", false},
	{"child keyUsage: all masked", "551d0f=03020304", "551d0e=040407070707", false},
	{"issuer keyUsage: all masked", "", "551d0e=040407070707 551d0f=03020304", false},
	{"child extendedKeyUsage: one", "551d25=300a06082b06010505070301", "551d0e=040407070707", true},
	{"issuer extendedKeyUsage: one", "", "551d0e=040407070707 551d25=300a06082b06010505070301", true},
	{"child extendedKeyUsage: not an OID", "551d25=3003040101", "551d0e=040407070707", false},
	{"issuer extendedKeyUsage: not an OID", "", "551d0e=040407070707 551d25=3003040101", false},
	{"child subjectAltName: URI", "551d11=300b860968747470733a2f2f61", "551d0e=040407070707", true},
	{"issuer subjectAltName: URI", "", "551d0e=040407070707 551d11=300b860968747470733a2f2f61", true},
	{"child subjectAltName: directoryName not a Name", "551d11=3005a403040101", "551d0e=040407070707", false},
	{"issuer subjectAltName: directoryName not a Name", "", "551d0e=040407070707 551d11=3005a403040101", false},
	{"child nameConstraints: permitted", "551d1e=3007a0053003820161", "551d0e=040407070707", true},
	{"issuer nameConstraints: permitted", "", "551d0e=040407070707 551d1e=3007a0053003820161", true},
	{"child nameConstraints: subtree no base", "551d1e=3004a0023000", "551d0e=040407070707", false},
	{"issuer nameConstraints: subtree no base", "", "551d0e=040407070707 551d1e=3004a0023000", false},
	{"child cRLDistributionPoints: URI", "551d1f=3011300fa00da00b860968747470733a2f2f61", "551d0e=040407070707", true},
	{"issuer cRLDistributionPoints: URI", "", "551d0e=040407070707 551d1f=3011300fa00da00b860968747470733a2f2f61", true},
	{"child cRLDistributionPoints: empty point", "551d1f=30023000", "551d0e=040407070707", false},
	{"issuer cRLDistributionPoints: empty point", "", "551d0e=040407070707 551d1f=30023000", false},
	{"issuer keyUsage: bit 5 set", "", "551d0f=03020204", true},
	{"issuer keyUsage: bit 5 under the unused bits", "", "551d0f=03020304", false},
	{"issuer keyUsage: bit 5 in a longer string", "", "551d0f=0303070480", true},
	{"child malformed proxyCertInfo", "2b0601050507010e=040101", "551d0e=040407070707", false},
	{"issuer malformed proxyCertInfo", "", "551d0e=040407070707 2b0601050507010e=040101", false},
	{"issuer parseCert refuses: no AKI", "", "551d13=30030101ff 551d0e=040407070707 2a0304=01 2a0304=01", true},
	{"issuer parseCert refuses: serial", "551d23=3003820111", "551d13=30030101ff 551d0e=040407070707 2a0304=01 2a0304=01", true},
	{"issuer parseCert refuses: other serial", "551d23=3003820112", "551d13=30030101ff 551d0e=040407070707 2a0304=01 2a0304=01", false},
	{"issuer parseCert refuses: key id", "551d23=3006800407070707", "551d13=30030101ff 551d0e=040407070707 2a0304=01 2a0304=01", true},
	{"issuer parseCert refuses: other key id", "551d23=3006800408080808", "551d13=30030101ff 551d0e=040407070707 2a0304=01 2a0304=01", false},
	{"issuer parseCert refuses: other directory name", "551d23=3006a104a4023000", "551d13=30030101ff 551d0e=040407070707 2a0304=01 2a0304=01", false},
}
