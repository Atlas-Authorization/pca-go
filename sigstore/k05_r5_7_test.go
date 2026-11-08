package pcasigstore

// r5-7: sigstore.go survivors. Each test pins the reference's behaviour (packages/pca-attest-eat/src/sigstore.ts) on an input
// the mutated code answers differently.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

// b64 refuses a string with line breaks even when its length is a multiple of 4 (the decoder alone would skip them), with
// the reference's message.
func TestR5N7_B64Refusals(t *testing.T) {
	for _, in := range []any{"AAAA\n\n\n\n", "AAAA\r\n\r\n", "AA", "AA=A", "A===", "AA==\n", nil, json.Number("1")} {
		if err := catch(func() { b64(in) }); err == nil || err.Error() != "not base64" {
			t.Errorf("b64(%v): %v", in, err)
		}
	}
}

func r5n7ExtDER(san []byte) []byte {
	return enc(0x30, append(enc(0x06, []byte{0x55, 0x1d, 0x11}), enc(0x04, san)...))
}

// The first [3] wrapper in the TBS carries the extensions.
func TestR5N7_ParseCertFirstExtensionsWrapper(t *testing.T) {
	a := enc(0xa3, enc(0x30, r5n7ExtDER([]byte{0x30, 0})))
	b := enc(0xa3, enc(0x30, r5n7ExtDER([]byte{0x30, 2, 0x82, 0})))
	der := enc(0x30, enc(0x30, append(append([]byte{}, a...), b...)))
	pc := parseCert(der)
	if want := bytes.Index(der, a); pc.extsWrapper.start != want {
		t.Fatalf("wrapper starts at %d, want %d", pc.extsWrapper.start, want)
	}
	if e := pc.ext("2.5.29.17"); e == nil || !bytes.Equal(e.value, []byte{0x30, 0}) {
		t.Fatalf("extension of the first wrapper: %+v", e)
	}
}

func TestR5N7_SANMustBeOneSequence(t *testing.T) {
	for _, c := range []struct {
		name string
		san  []byte
		want bool
	}{
		{"not a SEQUENCE, length exact", []byte{0x04, 0}, false},
		{"SEQUENCE with a trailing byte", []byte{0x30, 0, 0xff}, false},
		{"empty SEQUENCE", []byte{0x30, 0}, true},
		{"one GeneralName", []byte{0x30, 2, 0x82, 0}, true},
		{"entry that is not a GeneralName", []byte{0x30, 2, 0x04, 0}, false},
	} {
		if got := sanDecodes(g07sMiniCert(c.san)); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// An intermediate that may sign (keyCertSign) but is not a CA is no link of the chain: the CA flag is checked on every
// certificate above the leaf, the first of them included.
func TestR5N7_ChainOKIntermediateMustBeCA(t *testing.T) {
	rootKey, interKey, leafKey := g07sEC(t), g07sEC(t), g07sEC(t)
	rootC, rootDER := g07sCert(t, g07sCAtpl("r5n7 root"), &rootKey.PublicKey, nil, rootKey)
	interC, interDER := g07sCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "r5n7 intermediate"},
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}, &interKey.PublicKey, rootC, rootKey)
	_, leafDER := g07sCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "r5n7 leaf"}, KeyUsage: x509.KeyUsageDigitalSignature},
		&leafKey.PublicKey, interC, interKey)
	ca := &PinnedCA{chain: []*pca.NodeCert{g07sNC(t, leafDER), g07sNC(t, interDER), g07sNC(t, rootDER)}, raw: [][]byte{leafDER, interDER, rootDER}}
	if chainOK(ca, 1_700_000_000_000) {
		t.Error("a non-CA intermediate was accepted")
	}
}

// An entry that is skipped (not v1, an unsupported algorithm, a timestamp out of range, a key not valid then) does not end the
// search: a later entry still decides.
func TestR5N7_SCTSkippedEntryDoesNotEndTheSearch(t *testing.T) {
	f := newSCTFixture(t)
	issuer := fullCert(f.ca.Raw)
	retired := bytes.Repeat([]byte{7}, 32)
	f.roots.ctlogs = append(f.roots.ctlogs, PinnedLog{keyID: retired, key: &f.logKey.PublicKey, valid: validity{0, 1}})
	for _, c := range []struct {
		name string
		mut  func(s []byte)
	}{
		{"not v1", func(s []byte) { s[0] = 1 }},
		{"hash algorithm", func(s []byte) { s[43] = 5 }},
		{"timestamp past 2^53-1", func(s []byte) { s[33] = 0xff }},
		{"log key not valid at the timestamp", func(s []byte) { copy(s[1:33], retired) }},
	} {
		leaf, _ := f.leaf(func(tbs []byte) []byte {
			first := f.sct(tbs, f.logID, nil, nil)
			c.mut(first)
			return list(append(entry(first), entry(f.sct(tbs, f.logID, nil, nil))...))
		})
		if got := verifySCT(leaf, issuer, f.roots); got != "" {
			t.Errorf("%s: %q", c.name, got)
		}
	}
}

// Two pinned logs with one key id: the first pinned one is the log (its key verifies the SCT).
func TestR5N7_SCTFirstPinnedLogWins(t *testing.T) {
	f := newSCTFixture(t)
	issuer := fullCert(f.ca.Raw)
	wrong, _ := ecdsa.GenerateKey(f.logKey.Curve, rand.Reader)
	f.roots.ctlogs = append(f.roots.ctlogs, PinnedLog{keyID: f.logID, key: &wrong.PublicKey, valid: validity{0, forever}})
	leaf, _ := f.leaf(func(tbs []byte) []byte { return list(entry(f.sct(tbs, f.logID, nil, nil))) })
	if got := verifySCT(leaf, issuer, f.roots); got != "" {
		t.Fatalf("got %q", got)
	}
}

// A timestamp authority that did not sign it is skipped; the next one decides.
func TestR5N7_RFC3161LaterAuthorityDecides(t *testing.T) {
	f := g07sNewFx(t)
	data := []byte("the signature")
	tok := g07sTSAToken(t, f.tsaKey, data, g07sGenTime)
	badKey := g07sEC(t)
	_, badDER := g07sCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "r5n7 other tsa"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}, &badKey.PublicKey, nil, badKey)
	bad := PinnedCA{chain: []*pca.NodeCert{g07sNC(t, badDER)}, raw: [][]byte{badDER}, valid: validity{0, forever}}
	var ms int64
	if err := catch(func() { ms = verifyRFC3161(tok, data, []PinnedCA{bad, f.roots.tsas[0]}) }); err != nil || ms != g07sIntegrated*1000 {
		t.Fatalf("got %d %v", ms, err)
	}
}

// A signature line for another log name is skipped (Rekor v2 notes carry the log's name); the next line is still read.
func TestR5N7_CheckpointOtherNameLineIsSkipped(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log := &PinnedLog{keyID: bytes.Repeat([]byte{9}, 32), key: pub, v2Name: "rekor.example"}
	root := bytes.Repeat([]byte{1}, 32)
	body := "o\n1\n" + g07sStd(root) + "\n"
	sig := ed25519.Sign(priv, []byte(body))
	line := func(name string) string { return "— " + name + " " + g07sStd(g07sCat(log.keyID[:4], sig)) }
	text := body + "\n" + line("other.example") + "\n" + line("rekor.example") + "\n"
	var got string
	if err := catch(func() { got = verifyCheckpoint(text, log, 1, root) }); err != nil || got != "" {
		t.Fatalf("got %q %v", got, err)
	}
	only := body + "\n" + line("other.example") + "\n"
	if err := catch(func() { got = verifyCheckpoint(only, log, 1, root) }); err != nil || got != "no checkpoint signature by the pinned log key" {
		t.Fatalf("only the other name: %q %v", got, err)
	}
}

// Two pinned transparency logs with one key id: the first is the log.
func TestR5N7_FirstPinnedTransparencyLogWins(t *testing.T) {
	f := g07sNewFx(t)
	other := g07sEC(t)
	f.roots.tlogs = append(f.roots.tlogs, PinnedLog{keyID: f.logID, key: &other.PublicKey, valid: validity{0, forever}})
	if r := VerifySigstoreBundleCore(f.bundle(g07sOpt{}), f.roots); !r.OK {
		t.Fatalf("refused: %s: %s", r.Code, r.Detail)
	}
}

// A fault raised at each stage is reported under that stage's code.
func TestR5N7_StageOfAFault(t *testing.T) {
	f := g07sNewFx(t)
	roots := *f.roots
	roots.ctlogs = []PinnedLog{{keyID: bytes.Repeat([]byte{1}, 32), key: &f.logKey.PublicKey, valid: validity{0, forever}}}
	bundle := f.bundle(g07sOpt{})
	defer func() { stageFault = nil }()
	for _, site := range []string{"tlog_count", "tlog_kind", "cert_chain", "sct", "signature"} {
		stageFault = func(s string) {
			if s == site {
				throw("injected")
			}
		}
		use := f.roots
		if site == "sct" {
			use = &roots // the SCT stage runs only when the root pins a CT log
		}
		if r := VerifySigstoreBundleCore(bundle, use); r.OK || r.Code != site || r.Detail != "fail closed: injected" {
			t.Errorf("%s: %v %q %q", site, r.OK, r.Code, r.Detail)
		}
	}
	stageFault = nil
	if r := VerifySigstoreBundleCore(bundle, f.roots); !r.OK {
		t.Fatalf("no fault: %s: %s", r.Code, r.Detail)
	}
}
