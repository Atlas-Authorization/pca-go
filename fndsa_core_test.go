package pca

import (
	"bytes"
	"errors"
	"testing"
)

// With no backend registered fn-dsa-512/1024 are registered-but-unimplemented: refused with unsupported_suite, never verified.
func TestFnDsaCoreSuiteNoBackendDenies(t *testing.T) {
	ResetFalconBackend()
	for _, c := range []struct {
		alg    string
		pk, sg int
	}{{"fn-dsa-512", FnDsa512PublicKeyBytes, FnDsa512SignatureBytes}, {"fn-dsa-1024", FnDsa1024PublicKeyBytes, FnDsa1024SignatureBytes}} {
		if _, ok := resolveSigAlg(c.alg, true); ok {
			t.Fatalf("%s resolves with no backend", c.alg)
		}
		if why := validateSignatureWire(map[string]any{"alg": c.alg, "sig": "AA"}); why != UnsupportedSuite+": "+c.alg {
			t.Fatalf("%s: reason %q", c.alg, why)
		}
		if VerifyPqSuiteRaw(c.alg, make([]byte, c.pk), []byte("m"), make([]byte, c.sg)) {
			t.Fatalf("%s verified with no backend", c.alg)
		}
		for _, a := range SupportedSuites() {
			if a == c.alg {
				t.Fatalf("%s listed as supported with no backend", c.alg)
			}
		}
	}
}

// With a backend registered the suites are known: correct lengths reach the backend, wrong lengths do not, a backend error denies.
func TestFnDsaCoreSuiteDispatch(t *testing.T) {
	defer ResetFalconBackend()
	calls, accept := 0, true
	var fail error
	if err := SetFalconBackend(&FalconBackend{Verify: func(pk, msg, sig []byte) (bool, error) {
		calls++
		return accept, fail
	}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		alg    string
		pk, sg int
	}{{"fn-dsa-512", FnDsa512PublicKeyBytes, FnDsa512SignatureBytes}, {"fn-dsa-1024", FnDsa1024PublicKeyBytes, FnDsa1024SignatureBytes}} {
		pk, sg := bytes.Repeat([]byte{1}, c.pk), bytes.Repeat([]byte{2}, c.sg)
		if !VerifyPqSuiteRaw(c.alg, pk, []byte("m"), sg) {
			t.Fatalf("%s: a backend accept did not verify", c.alg)
		}
		n := calls
		if VerifyPqSuiteRaw(c.alg, pk[1:], []byte("m"), sg) || VerifyPqSuiteRaw(c.alg, pk, []byte("m"), sg[1:]) || calls != n {
			t.Fatalf("%s: a wrong length reached the backend or verified", c.alg)
		}
		accept = false
		if VerifyPqSuiteRaw(c.alg, pk, []byte("m"), sg) {
			t.Fatalf("%s: a backend reject verified", c.alg)
		}
		accept, fail = true, errors.New("boom")
		if VerifyPqSuiteRaw(c.alg, pk, []byte("m"), sg) {
			t.Fatalf("%s: a backend error verified", c.alg)
		}
		accept, fail = true, nil
		if why := validateSignatureWire(map[string]any{"alg": c.alg, "sig": "AA"}); why == UnsupportedSuite+": "+c.alg {
			t.Fatalf("%s: still unsupported with a backend", c.alg)
		}
	}
}

// The agent-side signer signs fn-dsa-* only through a registered backend; with none it refuses with unsupported_suite as before.
func TestFnDsaSignerSeam(t *testing.T) {
	t.Cleanup(ResetFalconBackend)
	ResetFalconBackend()
	vk, sk := bytes.Repeat([]byte{1}, FnDsa512PublicKeyBytes), bytes.Repeat([]byte{2}, 1345)
	if _, err := NewFnDsaKeyPair("fn-dsa-512", vk, sk, nil); !errors.Is(err, ErrUnsupportedSigner) {
		t.Fatalf("no backend: %v", err)
	}
	var seen []byte
	if err := SetFalconBackend(&FalconBackend{
		Verify: func(_, _, _ []byte) (bool, error) { return false, nil },
		SignSeeded: func(_, _, seed []byte) ([]byte, error) {
			seen = seed
			return make([]byte, FnDsa512SignatureBytes), nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	seed := bytes.Repeat([]byte{9}, 32)
	kp, err := NewFnDsaKeyPair("fn-dsa-512", vk, sk, seed)
	if err != nil {
		t.Fatal(err)
	}
	sig, _, err := SignWithSuite(&SuiteOpts{Alg: "fn-dsa-512", Pq: kp}, nil, []byte("m"))
	if err != nil || sig == "" || !bytes.Equal(seen, seed) {
		t.Fatalf("seeded sign: %v", err)
	}
	if _, err := NewFnDsaKeyPair("fn-dsa-512", vk[1:], sk, nil); err == nil {
		t.Fatal("a short public key was accepted")
	}
	ResetFalconBackend()
	if _, _, err := SignWithSuite(&SuiteOpts{Alg: "fn-dsa-512", Pq: kp}, nil, []byte("m")); !errors.Is(err, ErrUnsupportedSigner) {
		t.Fatalf("after reset: %v", err)
	}
}
