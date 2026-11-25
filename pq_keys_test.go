package pca

import (
	"bytes"
	"os"
	"testing"
)

func fill(n int, b byte) []byte { return bytes.Repeat([]byte{b}, n) }

func TestPqKeysConstantsAndRegistry(t *testing.T) {
	if CompositeSignatureBytes != 3373 || SlhDsaSha2128fSeedBytes != 48 || SlhDsaSha2256sSeedBytes != 96 {
		t.Fatal("size constants drifted")
	}
	if !IsKnownSigAlg("ml-dsa-87") || !IsKnownSigAlg("ed25519") || IsKnownSigAlg("ML-DSA-87") || IsKnownSigAlg("") || IsKnownSigAlg(5) {
		t.Fatal("IsKnownSigAlg")
	}
	if !IsPinnedPqKey(PinnedPqKey{}) || IsPinnedPqKey("x") || IsPinnedPqKey(nil) {
		t.Fatal("IsPinnedPqKey")
	}
	st := GetLessBackendStatus()
	if st.Available != IsLessBackendActive() || (st.Reason == "") != st.Available {
		t.Fatal("LESS status")
	}
	if IsFnDsaBackendActive() {
		t.Skip("an FN-DSA backend is registered")
	}
	if _, err := FnDsa512Keygen(fill(32, 1)); err == nil {
		t.Fatal("keygen without a backend must refuse")
	}
	if FnDsa1024Verify(fill(FnDsa1024PublicKeyBytes, 0), []byte("m"), fill(FnDsa1024SignatureBytes, 0)) || FnDsa512VerifyB64u("", nil, "") {
		t.Fatal("FN-DSA verify must fail closed")
	}
}

func TestPqKeysMlDsaAndSlhDsaRoundTrip(t *testing.T) {
	kp, err := MlDsa65Keygen(fill(MlDsa65SeedBytes, 7))
	if err != nil || len(kp.PublicKey) != MlDsa65PublicKeyBytes {
		t.Fatal(err)
	}
	again, _ := MlDsa65Keygen(fill(32, 7))
	if !bytes.Equal(again.PublicKey, kp.PublicKey) {
		t.Fatal("keygen must be deterministic")
	}
	sig, err := MlDsa65Sign(kp.SecretKey, []byte("hello"))
	if err != nil || !MlDsa65Verify(kp.PublicKey, []byte("hello"), sig) || MlDsa65Verify(kp.PublicKey, []byte("hellp"), sig) {
		t.Fatal("ml-dsa-65 round trip")
	}
	if !MlDsa65VerifyB64u(callerVouchedPqKey(EncodeMlDsaPublicKey(kp.PublicKey)), []byte("hello"), b64.EncodeToString(sig)) {
		t.Fatal("b64u verify")
	}
	if _, err := MlDsa65Keygen(fill(31, 7)); err == nil {
		t.Fatal("short seed")
	}
	k87, _ := MlDsa87Keygen(fill(32, 9))
	s87, _ := MlDsa87Sign(k87.SecretKey, []byte("m"))
	if !MlDsa87Verify(k87.PublicKey, []byte("m"), s87) || MlDsa65Verify(k87.PublicKey, []byte("m"), s87) ||
		!MlDsa87VerifyB64u(EncodeMlDsa87PublicKey(k87.PublicKey), []byte("m"), b64.EncodeToString(s87)) {
		t.Fatal("ml-dsa-87 round trip")
	}
	sk, err := SlhDsa128fKeygen(fill(SlhDsaSha2128fSeedBytes, 3))
	if err != nil || len(sk.PublicKey) != SlhDsaSha2128fPublicKeyBytes || len(sk.SecretKey) != SlhDsaSha2128fSecretKeyBytes {
		t.Fatal(err)
	}
	ss, err := SlhDsa128fSign(sk.SecretKey, []byte("hello"))
	if err != nil || len(ss) != SlhDsaSha2128fSignatureBytes || !SlhDsa128fVerify(sk.PublicKey, []byte("hello"), ss) ||
		SlhDsa128fVerify(sk.PublicKey, []byte("hellp"), ss) || !SlhDsa128fVerifyB64u(EncodeSlhDsaPublicKey(sk.PublicKey), []byte("hello"), b64.EncodeToString(ss)) {
		t.Fatal("slh-dsa-128f round trip")
	}
	if _, err := SlhDsa128fKeygen(fill(47, 3)); err == nil {
		t.Fatal("short slh seed")
	}
	if _, err := SlhDsa256sKeygen(fill(95, 3)); err == nil {
		t.Fatal("short slh256 seed")
	}
	if _, err := SlhDsa128fSign(sk.SecretKey[1:], []byte("x")); err == nil {
		t.Fatal("malformed slh secret key")
	}
	k256, err := SlhDsa256sKeygen(fill(SlhDsaSha2256sSeedBytes, 4))
	if err != nil || len(k256.PublicKey) != SlhDsaSha2256sPublicKeyBytes || len(k256.SecretKey) != SlhDsaSha2256sSecretKeyBytes {
		t.Fatal(err)
	}
}

func TestPqKeysCompositeAndSuiteArtifact(t *testing.T) {
	ed, _ := KeyPairFromSeedB64u(b64.EncodeToString(fill(32, 5)))
	ml, _ := MlDsa65Keygen(fill(32, 6))
	msg := []byte("message")
	sig, err := CompositeSign(ed.Seed(), ml.SecretKey, msg, []byte("ctx"))
	if err != nil || len(sig) != CompositeSignatureBytes {
		t.Fatal(err)
	}
	edPub, _ := DecodeB64uStrict(ed.Public, 32)
	if !CompositeVerify(edPub, ml.PublicKey, msg, sig, []byte("ctx")) || CompositeVerify(edPub, ml.PublicKey, msg, sig, nil) ||
		CompositeVerify(edPub, ml.PublicKey, msg, sig[1:], []byte("ctx")) || CompositeVerify(edPub, ml.PublicKey, []byte("other"), sig, []byte("ctx")) {
		t.Fatal("composite verify")
	}
	if _, err := CompositeRepresentative(msg, fill(256, 1)); err == nil || CompositeVerify(edPub, ml.PublicKey, msg, sig, fill(256, 1)) {
		t.Fatal("ctx over 255 bytes")
	}
	pq, err := GeneratePqKeyPairFromSeed("ML-DSA-65", fill(32, 6))
	if err != nil {
		t.Fatal(err)
	}
	if f, err := SignSuiteArtifact(nil, ed, msg); err != nil || len(f) != 1 || f["sig"] == "" {
		t.Fatalf("ed25519 must carry only sig: %v %v", f, err)
	}
	s := &SuiteOpts{Alg: "hybrid-ed25519-ml-dsa-65", Pq: pq}
	f, err := SignSuiteArtifact(s, ed, msg)
	pk, ok := SuitePqPublicKey(s)
	if err != nil || !ok || f["alg"] != s.Alg || f["pq_pk"] != pk || f["pq_sig"] == "" || pk != EncodeMlDsaPublicKey(ml.PublicKey) {
		t.Fatalf("hybrid artifact fields: %v %v", f, err)
	}
	if _, err := SignSuiteArtifact(&SuiteOpts{Alg: "ml-dsa-87", Pq: pq}, ed, msg); err == nil {
		t.Fatal("a mismatching key pair must refuse")
	}
	if _, ok := SuitePqPublicKey(nil); ok {
		t.Fatal("ed25519 has no pq_pk")
	}
}

// TestPqKeysReplayProducerKeygen replays the shared keygen vectors through the raw-byte keygen functions.
func TestPqKeysReplayProducerKeygen(t *testing.T) {
	raw, err := os.ReadFile(dir + "producer-pq-vectors.json")
	if err != nil {
		t.Skip("producer-pq-vectors.json not present")
	}
	v, err := ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for name, k := range v.(map[string]any)["pq_keys"].(map[string]any) {
		km := k.(map[string]any)
		seed, _ := DecodeB64uStrict(prodStr(km, "seed"), -1)
		var pub []byte
		switch prodStr(km, "family") {
		case "ml-dsa-65":
			kp, _ := MlDsa65Keygen(seed)
			pub = kp.PublicKey
		case "ml-dsa-87":
			kp, _ := MlDsa87Keygen(seed)
			pub = kp.PublicKey
		case "slh-dsa-sha2-128f":
			kp, _ := SlhDsa128fKeygen(seed)
			pub = kp.PublicKey
		case "slh-dsa-sha2-256s":
			kp, _ := SlhDsa256sKeygen(seed)
			pub = kp.PublicKey
		default:
			continue
		}
		if b64.EncodeToString(pub) != prodStr(km, "public") {
			t.Fatalf("%s: public key differs from the reference keygen", name)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no keygen vectors replayed")
	}
}
