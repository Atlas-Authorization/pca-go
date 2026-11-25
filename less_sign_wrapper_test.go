//go:build less && cgo

package pca

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

// Direct tests of the keygen and sign exports of lessc/atlas_less.c: round trips through verify, the C's own fail-closed
// checks through the raw seams (every buffer real and large enough, so a mutant that skips a check reads and writes only valid
// memory), and child-process cases for the checks whose mutants dereference NULL or overrun. They are part of the kill set of
// the lessc-mutants job (lessc-mutate.sh).

func lessSeedOf(mul, add int) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i*mul + add)
	}
	return b
}

func TestLessWrapperKeygenSignRoundTrip(t *testing.T) {
	var pks [][]byte
	for _, ks := range [][]byte{lessSeedOf(7, 1), lessSeedOf(13, 5)} {
		pk, sk, err := LessCat1Keygen(ks)
		if err != nil || len(pk) != lessPublicKeyBytes || len(sk) != LessCat1SecretKeyBytes {
			t.Fatalf("keygen: %d %d %v", len(pk), len(sk), err)
		}
		if bytes.Equal(pk, make([]byte, len(pk))) || bytes.Equal(sk, make([]byte, len(sk))) {
			t.Fatal("keygen returned an all-zero key")
		}
		pk2, sk2, _ := LessCat1Keygen(ks)
		if !bytes.Equal(pk, pk2) || !bytes.Equal(sk, sk2) {
			t.Fatal("the same seed must give the same key pair")
		}
		pks = append(pks, pk)
		for i, msg := range [][]byte{nil, []byte("a"), bytes.Repeat([]byte{0xA5}, 3), bytes.Repeat([]byte("pca less sign "), 40)} {
			sig, err := LessCat1Sign(sk, msg, lessSeedOf(3, 9+i))
			if err != nil {
				t.Fatalf("sign %d: %v", i, err)
			}
			if len(sig) < lessSignatureMinBytes || len(sig) > lessSignatureMaxBytes || (lessSignatureMaxBytes-len(sig))%lessSignatureStep != 0 {
				t.Fatalf("sign %d: signature length %d", i, len(sig))
			}
			if !cgoLessCat1Verify(pk, msg, sig) {
				t.Fatalf("sign %d: own signature does not verify", i)
			}
			if cgoLessCat1Verify(pk, append(append([]byte{}, msg...), 1), sig) {
				t.Fatalf("sign %d: verifies another message", i)
			}
			again, _ := LessCat1Sign(sk, msg, lessSeedOf(3, 9+i))
			if !bytes.Equal(sig, again) {
				t.Fatalf("sign %d: the same seed must give the same signature", i)
			}
		}
	}
	if bytes.Equal(pks[0], pks[1]) {
		t.Fatal("different seeds gave the same public key")
	}
	_, sk, _ := LessCat1Keygen(lessSeedOf(7, 1))
	sig, _ := LessCat1Sign(sk, []byte("m"), lessSeedOf(3, 9))
	if cgoLessCat1Verify(pks[1], []byte("m"), sig) {
		t.Fatal("verifies under another public key")
	}
}

func TestLessWrapperKeygenRawChecks(t *testing.T) {
	pkN, skN := uint64(lessPublicKeyBytes), uint64(LessCat1SecretKeyBytes)
	pk, sk, seed := make([]byte, pkN+8), make([]byte, skN+8), lessSeedOf(5, 3)
	seed = append(seed, lessSeedOf(11, 2)...)
	call := func(pkCap, skCap, seedLen uint64) bool {
		return lessCat1KeygenRaw(lessPtr(pk), pkCap, lessPtr(sk), skCap, lessPtr(seed), seedLen)
	}
	if !call(pkN, skN, 32) || !call(pkN, skN, 64) {
		t.Fatal("raw keygen refused a legal call")
	}
	for _, c := range [][3]uint64{{pkN - 1, skN, 32}, {pkN + 1, skN, 32}, {pkN, skN - 1, 32}, {pkN, skN + 1, 32}, {0, skN, 32}, {pkN, 0, 32}, {pkN, skN, 31}, {pkN, skN, 1}, {pkN, skN, 0}} {
		if call(c[0], c[1], c[2]) {
			t.Errorf("raw keygen accepted pk_cap %d sk_cap %d seed_len %d", c[0], c[1], c[2])
		}
	}
}

func TestLessWrapperSignRawChecks(t *testing.T) {
	if os.Getenv("PCA_LESS_SIGN_RAW_CASE") != "" {
		t.Skip("in a child process")
	}
	_, sk0, _ := LessCat1Keygen(lessSeedOf(7, 1))
	sk := append(append([]byte{}, sk0...), make([]byte, 32)...) // real bytes past the key: a longer sk_len reads valid memory
	seed := append(lessSeedOf(3, 9), lessSeedOf(11, 2)...)
	msg := []byte("raw sign check")
	_, _, sigMax := lessCat1Sizes()
	sig := make([]byte, 2*sigMax)
	skN := uint64(len(sk0))
	call := func(skLen uint64, m []byte, mLen uint64, seedLen, sigCap uint64) (bool, uint64) {
		var n uint64
		ok, _ := lessCat1SignRaw(lessPtr(sk), skLen, lessPtr(m), mLen, lessPtr(seed), seedLen, lessPtr(sig), sigCap, &n)
		return ok, n
	}
	for _, c := range []struct{ seedLen, sigCap uint64 }{{32, sigMax}, {64, sigMax}, {32, 2 * sigMax}} {
		if ok, n := call(skN, msg, uint64(len(msg)), c.seedLen, c.sigCap); !ok || n == 0 {
			t.Fatalf("raw sign refused a legal call (seed_len %d sig_cap %d)", c.seedLen, c.sigCap)
		}
	}
	// NULL msg with length 0 is the empty message
	if ok, n := call(skN, nil, 0, 32, sigMax); !ok || n == 0 {
		t.Fatal("raw sign refused the empty message given as NULL")
	}
	for _, c := range []struct {
		name                         string
		skLen, mLen, seedLen, sigCap uint64
		nilMsg                       bool
	}{
		{"sk_len-1", skN - 1, 3, 32, sigMax, false}, {"sk_len+1", skN + 1, 3, 32, sigMax, false}, {"sk_len 0", 0, 3, 32, sigMax, false},
		{"seed_len 31", skN, 3, 31, sigMax, false}, {"seed_len 1", skN, 3, 1, sigMax, false}, {"seed_len 0", skN, 3, 0, sigMax, false},
		{"sig_cap max-1", skN, 3, 32, sigMax - 1, false}, {"sig_cap 0", skN, 3, 32, 0, false},
		{"NULL msg with length", skN, 3, 32, sigMax, true},
	} {
		m := msg
		if c.nilMsg {
			m = nil
		}
		if ok, _ := call(c.skLen, m, c.mLen, c.seedLen, c.sigCap); ok {
			t.Errorf("raw sign accepted %s", c.name)
		}
	}
	// the overflow guard: a length at the bound passes it and then fails to allocate (ENOMEM); one past it is refused before any
	// allocation (errno stays 0); nothing is read from the message in either case
	bound := lessSignOverflowBound()
	var n uint64
	if ok, err := lessCat1SignRaw(lessPtr(sk), skN, lessPtr(msg), bound, lessPtr(seed), 32, lessPtr(sig), sigMax, &n); ok || !errors.Is(err, syscall.Errno(12)) {
		t.Errorf("msg_len at the overflow bound: ok %v errno %v, want ENOMEM", ok, err)
	}
	for _, c := range lessSignRawChildCases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLessWrapperSignRawChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), "PCA_LESS_SIGN_RAW_CASE="+c)
		out, err := cmd.CombinedOutput()
		if err != nil || !bytes.Contains(out, []byte("lessc-raw-result=false")) {
			t.Errorf("%s: want a clean refusal, got err %v, output:\n%s", c, err, out)
		}
	}
}

// Cases whose mutants dereference NULL or overrun: each runs in a child process (this test binary, re-executed), so a mutant's
// crash is a test failure in the parent, not a dead test run. The unmutated C refuses each before reading anything.
var lessSignRawChildCases = []string{"sign-nil-sk", "sign-nil-seed", "sign-nil-sig", "sign-nil-sig-len", "sign-len-bound-plus-1", "sign-len-max",
	"keygen-nil-pk", "keygen-nil-sk", "keygen-nil-seed"}

func TestLessWrapperSignRawChild(t *testing.T) {
	c := os.Getenv("PCA_LESS_SIGN_RAW_CASE")
	if c == "" {
		t.Skip("child process of TestLessWrapperSignRawChecks")
	}
	_, sk, _ := LessCat1Keygen(lessSeedOf(7, 1))
	pk := make([]byte, lessPublicKeyBytes)
	seed := lessSeedOf(3, 9)
	msg := []byte("raw sign check")
	_, _, sigMax := lessCat1Sizes()
	sig := make([]byte, 2*sigMax)
	var n uint64
	sp, mp, sdp, gp, np := lessPtr(sk), lessPtr(msg), lessPtr(seed), lessPtr(sig), &n
	mLen := uint64(len(msg))
	kpk, ksk, ksd := lessPtr(pk), lessPtr(make([]byte, len(sk))), lessPtr(seed)
	switch c {
	case "sign-nil-sk":
		sp = nil
	case "sign-nil-seed":
		sdp = nil
	case "sign-nil-sig":
		gp = nil
	case "sign-nil-sig-len":
		np = nil
	case "sign-len-bound-plus-1": // the first length past the guard: cap would wrap to 0
		mLen = lessSignOverflowBound() + 1
	case "sign-len-max":
		mLen = ^uint64(0)
	case "keygen-nil-pk":
		kpk = nil
	case "keygen-nil-sk":
		ksk = nil
	case "keygen-nil-seed":
		ksd = nil
	default:
		t.Fatalf("unknown case %q", c)
	}
	var r bool
	if len(c) > 6 && c[:6] == "keygen" {
		r = lessCat1KeygenRaw(kpk, uint64(len(pk)), ksk, uint64(len(sk)), ksd, 32)
	} else {
		r, _ = lessCat1SignRaw(sp, uint64(len(sk)), mp, mLen, sdp, 32, gp, sigMax, np)
	}
	fmt.Printf("lessc-raw-result=%v\n", r)
}
