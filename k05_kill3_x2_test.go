package pca

import (
	"encoding/asn1"
	"testing"
	"time"
)

// A BasicOCSPResponse is exactly SEQUENCE { tbs SEQUENCE, signatureAlgorithm SEQUENCE, signature BIT STRING, ... }: one wrong member tag refuses it.
func TestK05X2OcspBasicMemberTags(t *testing.T) {
	f := g02newFx(t)
	alg := derTLV(0x30, g02oid("1.2.840.10045.4.3.2"))
	sig := derTLV(0x03, []byte{0})
	want := g02rej("malformed BasicOCSPResponse")
	for name, basic := range map[string][]byte{
		"tbs a SET":             derTLV(0x30, derTLV(0x31), alg, sig),
		"algorithm a SET":       derTLV(0x30, derTLV(0x30), derTLV(0x31, g02oid("1.2.840.10045.4.3.2")), sig),
		"signature not BIT STR": derTLV(0x30, derTLV(0x30), alg, derTLV(0x04, []byte{0})),
	} {
		if got := verifyNvidiaOcspResponse(g02wrapBasic(basic), f.leafA, f.interA, f.chain, f.nowMs); got != want {
			t.Errorf("%s: got %+v, want %+v", name, got, want)
		}
	}
}

// A CertID is exactly { hashAlgorithm SEQUENCE, issuerNameHash OCTET STRING, issuerKeyHash OCTET STRING, serialNumber INTEGER }.
func TestK05X2OcspCertIDShape(t *testing.T) {
	f := g02newFx(t)
	at := g02now.Add(-time.Hour)
	oid := g02oid("1.3.14.3.2.26")
	null := []byte{0x05, 0x00}
	alg := derTLV(0x30, oid, null)
	nameRaw, keyRaw := g02sha1(f.interA.RawSubject), g02sha1(g02bits(t, f.interA.RawSPKI))
	name, key := derTLV(0x04, nameRaw), derTLV(0x04, keyRaw)
	serial, err := asn1.Marshal(f.leaf.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	want := g02rej("malformed CertID")
	for label, cid := range map[string][]byte{
		"three members":     derTLV(0x30, alg, name, key),
		"five members":      derTLV(0x30, alg, name, key, serial, null),
		"hashAlgorithm SET": derTLV(0x30, derTLV(0x31, oid, null), name, key, serial),
		"name an INTEGER":   derTLV(0x30, alg, derTLV(0x02, nameRaw), key, serial),
		"key an INTEGER":    derTLV(0x30, alg, name, derTLV(0x02, keyRaw), serial),
		"serial an OCTET":   derTLV(0x30, alg, name, key, derTLV(0x04, f.leaf.SerialNumber.Bytes())),
	} {
		der := f.mod(t, func(r *g02rsp) { r.singles = [][]byte{g02single(cid, g02good, g02gt(at))} })
		if got := verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs); got != want {
			t.Errorf("%s: got %+v, want %+v", label, got, want)
		}
	}
}

// The CertID binds serial AND issuerNameHash AND issuerKeyHash (attest-nvidia-ocsp.ts header): one differing hash is no match.
func TestK05X2OcspCertIDEachHashBinds(t *testing.T) {
	f := g02newFx(t)
	at := g02now.Add(-time.Hour)
	alg := derTLV(0x30, g02oid("1.3.14.3.2.26"), []byte{0x05, 0x00})
	name, key := derTLV(0x04, g02sha1(f.interA.RawSubject)), derTLV(0x04, g02sha1(g02bits(t, f.interA.RawSPKI)))
	other := derTLV(0x04, g02sha1([]byte("another issuer")))
	serial, err := asn1.Marshal(f.leaf.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	want := g02no("no SingleResponse matches the certificate (serial / issuer hashes differ)")
	for label, cid := range map[string][]byte{
		"name differs": derTLV(0x30, alg, other, key, serial),
		"key differs":  derTLV(0x30, alg, name, other, serial),
	} {
		der := f.mod(t, func(r *g02rsp) { r.singles = [][]byte{g02single(cid, g02good, g02gt(at))} })
		if got := verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs); got != want {
			t.Errorf("%s: got %+v, want %+v", label, got, want)
		}
	}
}

// A primitive certs member whose content is not DER is a malformed certs field, not an empty one.
func TestK05X2OcspCertsMemberNotDER(t *testing.T) {
	f := g02newFx(t)
	der := f.mod(t, func(r *g02rsp) {
		r.signer = f.otherK // the issuer's own signature fails, so the embedded certificates are read
		r.certs = derTLV(0xa0, derTLV(0x04, []byte{0x30, 0x7f}))
	})
	if got, want := verifyNvidiaOcspResponse(der, f.leafA, f.interA, f.chain, f.nowMs), g02rej("malformed certs"); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// attest-nvidia-rim.ts: transforms are exactly [enveloped-signature, C14N 1.1], position by position.
func TestK05X2RimTransformEachPosition(t *testing.T) {
	const want = "RIM: transforms must be exactly [enveloped-signature, C14N 1.1]"
	for label, algs := range map[string][2]string{
		"first differs":  {"x", algC14N11},
		"second differs": {algEnveloped, "x"},
		"swapped":        {algC14N11, algEnveloped},
	} {
		ts := `<ds:Transforms><ds:Transform Algorithm="` + algs[0] + `"/><ds:Transform Algorithm="` + algs[1] + `"/></ds:Transforms>`
		xml := g12Doc(`<Meta/><Payload/>`, `<ds:Signature><ds:SignedInfo>`+g12CM+g12SM+`<ds:Reference URI="">`+ts+g12DM+
			`<ds:DigestValue>AAAA</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>`)
		if rim, why := verifyNvidiaRim(xml, []string{"00"}, g12Now); rim != nil || why != want {
			t.Errorf("%s: %q", label, why)
		}
	}
}

// Date.parse("12:34") is NaN in V8. A five-character string must not reach the offset check, which indexes n-6.
func TestK05X2DateParseFiveCharacters(t *testing.T) {
	if ms, ok := jsDateParse("12:34"); ok || ms != 0 {
		t.Fatalf("got %d %v, want a refusal", ms, ok)
	}
}

// attest-intel-collateral.ts: seamAttributes is body.slice(112, 120), so its first byte is body[112].
func TestK05X2CollateralSeamAttributesFirstByte(t *testing.T) {
	f := g06newFx(t)
	g06withQuote(t, g06okBase())
	body := g06body()
	body[112] = 0x01 // under the all-ones mask of g06tcbInfo
	g06wantFail(t, verifyIntelTdxCollateral(g06quote(body, g06qeBody(), g06pem(f.pck.Raw, f.ca.Raw, f.root.Raw)), f.col, g06now, nil, f.pin, false),
		"TCB evaluation: TD report SEAM attributes do not match the TDX module identity")
}
