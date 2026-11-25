package fndsakit

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

// Cross-implementation known answers (testdata/ref-fndsa-kat.json, hex): not NIST vectors (FIPS 206 has none published).
type wasmCase struct {
	Variant    string `json:"variant"`
	KeygenSeed string `json:"keygen_seed_label"` // label: the seed is SHAKE256(label)[:32]
	SignSeed   string `json:"sign_seed_label"`
	Vk         string `json:"vk"`
	Msg        string `json:"msg"`
	Sig        string `json:"sig"`
}

type cCase struct {
	Variant string `json:"variant"`
	Vk      string `json:"vk"`
	Msg     string `json:"msg"`
	Sig     string `json:"sig"`
}

type katFile struct {
	WasmSigned []wasmCase `json:"wasm_signed"`
	CSigned    []cCase    `json:"c_signed"`
}

func h(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func loadKat(t *testing.T) katFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/ref-fndsa-kat.json")
	if err != nil {
		t.Fatal(err)
	}
	var k katFile
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	if len(k.WasmSigned) == 0 || len(k.CSigned) == 0 {
		t.Fatal("the known-answer file has no cases")
	}
	return k
}

func shakeSeed(label string) []byte {
	out := make([]byte, 32)
	s := sha3.NewSHAKE256()
	s.Write([]byte(label))
	s.Read(out)
	return out
}

func flip(b []byte, i int) []byte {
	c := append([]byte(nil), b...)
	c[i] ^= 1
	return c
}

func TestWasmSignedByteExact(t *testing.T) {
	for _, c := range loadKat(t).WasmSigned {
		sk, vk, err := Keygen(c.Variant, shakeSeed(c.KeygenSeed))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(vk, h(t, c.Vk)) {
			t.Fatalf("%s: keygen does not give the reference vk", c.Variant)
		}
		sig, err := Sign(c.Variant, sk, h(t, c.Msg), shakeSeed(c.SignSeed))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sig, h(t, c.Sig)) {
			t.Fatalf("%s: signature is not byte for byte the reference's", c.Variant)
		}
		if ok, err := Verify(c.Variant, vk, h(t, c.Msg), sig); err != nil || !ok {
			t.Fatalf("%s: own signature does not verify (%v)", c.Variant, err)
		}
	}
}

func TestCSignedVerifies(t *testing.T) {
	for _, c := range loadKat(t).CSigned {
		if ok, err := Verify(c.Variant, h(t, c.Vk), h(t, c.Msg), h(t, c.Sig)); err != nil || !ok {
			t.Fatalf("%s: the C implementation's signature does not verify (%v)", c.Variant, err)
		}
	}
	for _, c := range loadKat(t).WasmSigned {
		if ok, _ := Verify(c.Variant, h(t, c.Vk), h(t, c.Msg), h(t, c.Sig)); !ok {
			t.Fatalf("%s: the reference's signature does not verify", c.Variant)
		}
	}
}

func TestTamperingAndBadInputIsRefused(t *testing.T) {
	c := loadKat(t).CSigned[1] // case 0 signs the empty message
	v, vk, msg, sig := c.Variant, h(t, c.Vk), h(t, c.Msg), h(t, c.Sig)
	no := func(name string, ok bool, err error) {
		t.Helper()
		if ok || err != nil {
			t.Fatalf("%s: want a clean refusal, got %v %v", name, ok, err)
		}
	}
	ok, err := Verify(v, vk, msg, flip(sig, 10))
	no("flipped sig", ok, err)
	ok, err = Verify(v, vk, append(append([]byte(nil), msg...), 'x'), sig)
	no("changed msg", ok, err)
	ok, err = Verify(v, flip(vk, 5), msg, sig)
	no("flipped vk", ok, err)
	ok, err = Verify(v, vk, msg, sig[:len(sig)-1])
	no("short sig", ok, err)
	ok, err = Verify(v, vk[:len(vk)-1], msg, sig)
	no("short vk", ok, err)
	ok, err = Verify(v, vk, make([]byte, MessageCap+1), sig)
	no("8193-byte message", ok, err)
	ok, err = Verify("fn-dsa-768", vk, msg, sig)
	no("unknown variant", ok, err)
	ok, err = Verify(v, nil, nil, nil)
	no("nil inputs", ok, err)
	ok, err = Verify(v, []byte{}, []byte{}, []byte{})
	no("empty inputs", ok, err)
	ok, err = Verify(v, vk, nil, sig)
	no("zero-length message that was not signed", ok, err)

	k := loadKat(t).WasmSigned[0]
	sk, _, err := Keygen(k.Variant, shakeSeed(k.KeygenSeed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sign("fn-dsa-768", sk, msg, nil); err == nil {
		t.Fatal("sign accepted an unknown variant")
	}
	if _, err := Sign(k.Variant, sk[:len(sk)-1], msg, nil); err == nil {
		t.Fatal("sign accepted a short secret key")
	}
	if _, err := Sign(k.Variant, nil, msg, nil); err == nil {
		t.Fatal("sign accepted a nil secret key")
	}
	if _, err := Sign(k.Variant, sk, make([]byte, MessageCap+1), nil); err == nil {
		t.Fatal("sign accepted an 8193-byte message (it must refuse, never truncate)")
	}
	if _, err := Sign(k.Variant, sk, msg, make([]byte, SeedBytes-1)); err == nil {
		t.Fatal("sign accepted a short seed")
	}
	if _, _, err := Keygen(k.Variant, nil); err == nil {
		t.Fatal("keygen accepted a nil seed")
	}
}

// A zero-length message is a legal message: it signs and verifies, and a signature over it does not verify over anything else.
func TestZeroLengthMessageIsValid(t *testing.T) {
	for _, v := range []string{"fn-dsa-512", "fn-dsa-1024"} {
		sk, vk, err := KeygenRandom(v)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(v, sk, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := Verify(v, vk, []byte{}, sig); !ok {
			t.Fatalf("%s: empty message does not verify", v)
		}
		if ok, _ := Verify(v, vk, []byte{0}, sig); ok {
			t.Fatalf("%s: signature over the empty message verified over another message", v)
		}
	}
}

func TestRandomSeedRoundTrip(t *testing.T) {
	for _, v := range []string{"fn-dsa-512", "fn-dsa-1024"} {
		sk, vk, err := KeygenRandom(v)
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("atlas fn-dsa round trip")
		a, err := Sign(v, sk, msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Sign(v, sk, msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(a, b) {
			t.Fatalf("%s: two fresh-seed signatures are identical", v)
		}
		for _, s := range [][]byte{a, b} {
			if ok, _ := Verify(v, vk, msg, s); !ok {
				t.Fatalf("%s: round trip failed", v)
			}
			if ok, _ := Verify(v, vk, msg, flip(s, 3)); ok {
				t.Fatalf("%s: a tampered signature verified", v)
			}
		}
	}
}

// Sign-then-verify through the core's framing (plain FN-DSA and the Ed25519 hybrid) over this backend.
func TestFramingWithRealBackend(t *testing.T) {
	if err := pca.SetFalconBackend(NewBackend()); err != nil {
		t.Fatal(err)
	}
	defer pca.ResetFalconBackend()
	leaf := func() map[string]any {
		return map[string]any{"ver": 2, "action": map[string]any{"verb": "revoke", "resource": "sess/1"}, "aud": "rs",
			"iat": 1800000000000, "exp": 1800000060000}
	}
	edSeed := bytes.Repeat([]byte{7}, 32)
	for _, alg := range []string{"fn-dsa-512", "fn-dsa-1024", "hybrid-ed25519-fn-dsa-512", "hybrid-ed25519-fn-dsa-1024"} {
		suite, _ := pca.ResolveFnDsaAlg(alg)
		sk, vk, err := KeygenRandom(suite.Variant)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pca.SignPcaWithFndsa(alg, leaf(), vk, sk, edSeed)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		holder := ""
		if suite.HasEd25519 {
			holder = edHolder(edSeed)
		}
		ok, err := pca.VerifyPcaFndsa(alg, leaf(), holder, out["pq_pk"], out["sig"], out["pq_sig"])
		if err != nil || !ok {
			t.Fatalf("%s: framed signature does not verify (%v)", alg, err)
		}
		tampered := leaf()
		tampered["aud"] = "other"
		if ok, _ := pca.VerifyPcaFndsa(alg, tampered, holder, out["pq_pk"], out["sig"], out["pq_sig"]); ok {
			t.Fatalf("%s: a tampered leaf verified", alg)
		}
		if suite.HasEd25519 { // both halves are required
			if ok, _ := pca.VerifyPcaFndsa(alg, leaf(), holder, out["pq_pk"], out["sig"], ""); ok {
				t.Fatalf("%s: verified without the FN-DSA half", alg)
			}
		}
	}
}

// The KAT signatures verify through the core's pure-suite dispatch once the real backend is registered, and deny before.
func TestCoreSuiteDispatchWithRealBackend(t *testing.T) {
	pca.ResetFalconBackend()
	for _, c := range loadKat(t).CSigned {
		if pca.VerifyPqSuiteRaw(c.Variant, h(t, c.Vk), h(t, c.Msg), h(t, c.Sig)) {
			t.Fatalf("%s: verified with no backend registered", c.Variant)
		}
	}
	if err := pca.SetFalconBackend(NewBackend()); err != nil {
		t.Fatal(err)
	}
	defer pca.ResetFalconBackend()
	for _, c := range loadKat(t).CSigned {
		vk, msg, sig := h(t, c.Vk), h(t, c.Msg), h(t, c.Sig)
		if !pca.VerifyPqSuiteRaw(c.Variant, vk, msg, sig) {
			t.Fatalf("%s: KAT does not verify through the core suite", c.Variant)
		}
		if pca.VerifyPqSuiteRaw(c.Variant, flip(vk, 0), msg, sig) || (len(msg) > 0 && pca.VerifyPqSuiteRaw(c.Variant, vk, flip(msg, 0), sig)) ||
			pca.VerifyPqSuiteRaw(c.Variant, vk, msg, flip(sig, 5)) || pca.VerifyPqSuiteRaw(c.Variant, vk[1:], msg, sig) {
			t.Fatalf("%s: a tampered or wrong-length input verified", c.Variant)
		}
	}
	for _, v := range []string{"fn-dsa-512", "fn-dsa-1024"} {
		sk, vk, err := KeygenRandom(v)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := pca.FnDsaSign(v, sk, []byte("leaf"))
		if err != nil {
			t.Fatal(err)
		}
		if !pca.VerifyPqSuiteRaw(v, vk, []byte("leaf"), sig) {
			t.Fatalf("%s: sign then core verify failed", v)
		}
	}
}
