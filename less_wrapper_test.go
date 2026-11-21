//go:build less && cgo

package pca

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"unsafe"
)

// Direct tests of cgoLessCat1Verify (and through it lessc/atlas_less.c) with inputs the known answers never send: every
// signature length around the legal range, re-split attached messages, the empty message, and an allocation failure, plus
// the C's own fail-closed checks through lessCat1VerifyRaw (no Go-side checks). They are the kill set of the lessc-mutants
// job (lessc-mutate.sh).

// lessWrapperEmptyMsgSig is a less-cat1 signature (1297 bytes) over the EMPTY message under less-vectors.json keys.main,
// made by the TS reference backend (@atlasauth/pca-less-wasm, keygen seed "less-kg-main", signing seed
// "lessc-empty-message"). No vector signs the empty message, and only a valid one tells "empty" from "NULL with a length".
const lessWrapperEmptyMsgSig = "zIh-R3RHm5O0qrNwRjxswhSGdlSh7MMBhxCZNOZLwB23FMrTlQ2soMz8O10ckW7G708NLo9LEqtx5EV0SAgwd3aAThOICq26un5ZWvsGeehtpjibiQT9Yyh3PZ-kdgIKR7gypNuB-anisqdc7zh5Bkvy8HiSuVzuEVxIFqAZrwsIK_LuR636Nmd4wpZ0fyvbYOqhz0OTR4xApOkJ0JbJBQQzjeJ04bplyHX9TA2ji34bTC_yXfQwGodEF8i7wUwP5lmVU_3GF1L74ZQJoA-bKTCvpTKl8hbq0MrwKXZeVQSwROXEsDviM98Sb08OQOzXEblUbL1XJxxFJxc_byGGBeS6D8nxqMRyG6Qsk6q4GqHWcMwUyoc2E423ut_cM2QOX0B-QnpwOfJC-frIzyO-oqoyQgy7swpw4tev2goVKA-DTMzsQ3S9wCrQ8-6f2m6OonoNxMTbEpxtY6aMSyhbCWxT4mDMF7wHPAZcaMFft231CZG3SfWjCgHd9IRzPc0GnNGF1iwLOK6Qc0eSxEgaThHK4TsnzunZ7-ttL2U9IgW7Cmr7qVx-jOVgYByPOeWBpM9h9cGrhKc4sYF4_Nw6BGp0BwZj1nwTexwczv1DG6n3gjXTZE7dAy-OBY0qM18AquPos6QUMNufxHinRfVxaROOcwONPghvYjnU3yo00whTPuYVcFjjflxH9kLhMVBHn_vikAJXMzeqrFbUD0LTBl7Qw6Xhwxpr-noltKr0BiO24IqAvfQECaP2M17rPZ0CpmUDvU4mrRpPnGJfuwgCUtwlxO9YOg8pfYj2XpLR-AfvRszZdMml7kMpCpJe95KU8bH7HMz8I2nwgREhEqPjDvwk-khkv2GB5JsZgx6bYe_QzopEe6KekyJ7bhbPCOoFnBdNyiuuvenDyOPbeLRLFXuj8g-DZQotOMuOCOUnmABXss-wujJIHTyjBZFPXiVZOXJOwWi-m0nO0H2ugf2iCHCZFxawx_-K2G4YTCX8duQjwf94CeTdFdoI3dlFaaEBs77P4Ld0_fxuJBFqHi2dx_OAaCcSYPscUUA5ZOJRJwa035akRoS6eG-vDIrJaeyzlBTef8VoABgiN3Rn5YTXDa6zGJ4d_C3MAs_WMjA1HRhvKofYJNEd2niP9cwFu6UEYZNSLh-G2Pyn4rjeROS5W8wLMVhtB1zd2nSgziiZpgOvkpTp0O_tgD_m9VySD6AGRS3MaYoAcc5tK_4Df2UjAhuXfLUKJrovC_7If5pVZyeg2WuBAITwatgZTD0OPssHQ88eFbw2ZQEyjZIOgaS8gW2q9uZfRHuxv6IH-aGd2ApK_w3aXB1r_WPZBopWEyF6Kmlk9JtQRwfnrILTuYpiCrtGO8krVG3yLcilr5WkCAkP3V7q8bWSSFUvwanwKE0NvhHLaOgHAefzdW4f1_tBlFA8DYlyGMJdPWY5BntBfgnfQ3qKLBi6311UucMMfBq4orA-UbRDpmObUxUgbbOtDX6iemN0_qqFTiQbHoCMxlxVn5GXMGcegoGXsuLWwfcLFpCs5flwfQPIhwyRu8dxV7hiFWEm1PCB1RLZyU8XADLScz08-lRXMu1GOJkA8wWZwSFULs3vHUfL6yBPoGdQgBrQEB8JR7xZXAGVPTVFhxbowWWSkQ58Mt7IHJNLMdAST0Rj4RH4emocVGl9UoIuKxYrbdof1CzQr1uBBzv2qCFX1GRcdDhKAthNs2oE9MqdCQ"

type lessWrapperFix struct {
	pk, pkOther, msg, sig, sigOther, sigEmpty []byte
}

func lessWrapperFixture(t *testing.T) lessWrapperFix {
	t.Helper()
	var doc struct {
		Sizes map[string]int `json:"sizes"`
		Keys  map[string]struct {
			PqPk string `json:"pq_pk"`
		} `json:"keys"`
		Vectors []struct {
			Name    string `json:"name"`
			Message string `json:"message"`
			Sig     any    `json:"sig"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(mustRead(t, dir+"less-vectors.json"), &doc); err != nil {
		t.Fatal(err)
	}
	dec := func(what string, s any, n int) []byte {
		str, _ := s.(string)
		b, ok := DecodeB64uStrict(str, n)
		if !ok {
			t.Fatalf("fixture %s", what)
		}
		return b
	}
	var f lessWrapperFix
	f.pk = dec("keys.main", doc.Keys["main"].PqPk, lessPublicKeyBytes)
	f.pkOther = dec("keys.other", doc.Keys["other"].PqPk, lessPublicKeyBytes)
	for _, v := range doc.Vectors {
		switch v.Name {
		case "less-cat1-valid":
			f.msg, f.sig = dec(v.Name, v.Message, -1), dec(v.Name, v.Sig, -1)
		case "less-cat1-valid-other-key":
			f.sigOther = dec(v.Name, v.Sig, -1)
			if !bytes.Equal(dec(v.Name, v.Message, -1), f.msg) {
				t.Fatal("fixture: the two valid vectors sign different messages")
			}
		}
	}
	f.sigEmpty = dec("empty-message sig", lessWrapperEmptyMsgSig, -1)
	// the re-split and one-more-seed cases below need a valid signature with room for one more seed slot
	if len(f.msg) <= lessSignatureStep || len(f.sig)+lessSignatureStep > lessSignatureMaxBytes || len(f.sigOther) == 0 {
		t.Fatalf("fixture: msg %d bytes, sig %d bytes, other sig %d bytes", len(f.msg), len(f.sig), len(f.sigOther))
	}
	// the wrapper's size constants (and the C SIG_MIN / SIG_MAX / CRYPTO_PUBLICKEYBYTES they mirror) equal the vectors' sizes
	want := map[string]int{"pq_pk": lessPublicKeyBytes, "sig_min": lessSignatureMinBytes, "sig_max": lessSignatureMaxBytes, "sig_step": lessSignatureStep}
	for k, n := range want {
		if doc.Sizes[k] != n {
			t.Fatalf("less-vectors.json sizes.%s = %d, the Go constant is %d", k, doc.Sizes[k], n)
		}
	}
	return f
}

func lessCat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// the C size accessors and the Go constants (SIG_MIN = LESS_SIGNATURE_SIZE(0), SIG_MAX = LESS_SIGNATURE_SIZE(11))
func TestLessWrapperSizes(t *testing.T) {
	lessWrapperFixture(t)
	if pk, lo, hi := lessCat1Sizes(); pk != lessPublicKeyBytes || lo != lessSignatureMinBytes || hi != lessSignatureMaxBytes {
		t.Fatalf("C accessors: pk %d, sig %d..%d", pk, lo, hi)
	}
	if pk, sig := pqLessCat1.lens(); pk != 97484 || sig != 1329 {
		t.Fatalf("lens %d %d", pk, sig)
	}
	if lessSignatureMinBytes != 1153 || lessSignatureStep != 16 || (lessSignatureMaxBytes-lessSignatureMinBytes)%lessSignatureStep != 0 {
		t.Fatalf("min %d step %d", lessSignatureMinBytes, lessSignatureStep)
	}
}

func TestLessWrapperValid(t *testing.T) {
	f := lessWrapperFixture(t)
	if !cgoLessCat1Verify(f.pk, f.msg, f.sig) || !cgoLessCat1Verify(f.pkOther, f.msg, f.sigOther) {
		t.Fatal("valid signature refused")
	}
	// the empty message: a nil slice and an empty non-nil slice both reach the C with msg NULL, msg_len 0
	if !cgoLessCat1Verify(f.pk, nil, f.sigEmpty) || !cgoLessCat1Verify(f.pk, []byte{}, f.sigEmpty) {
		t.Fatal("valid empty-message signature refused")
	}
	if cgoLessCat1Verify(f.pk, []byte{0}, f.sigEmpty) || cgoLessCat1Verify(f.pkOther, nil, f.sigEmpty) {
		t.Fatal("empty-message signature accepted for another message or key")
	}
	if cgoLessCat1Verify(f.pkOther, f.msg, f.sig) || cgoLessCat1Verify(f.pk, f.msg, f.sigOther) {
		t.Fatal("signature accepted under the other key")
	}
}

// Only the exact signature verifies; the legal lengths (1153..1329 in steps of 16) reach the C, the rest are refused first.
// One more seed slot (16 bytes) or one fewer is refused by the C reference itself.
func TestLessWrapperSignatureLengths(t *testing.T) {
	f := lessWrapperFixture(t)
	for _, tc := range []struct{ msg, sig []byte }{{f.msg, f.sig}, {nil, f.sigEmpty}} {
		for n := 0; n <= lessSignatureMaxBytes+2*lessSignatureStep; n++ {
			c := bytes.Repeat([]byte{0xa5}, n)
			copy(c, tc.sig)
			if got := cgoLessCat1Verify(f.pk, tc.msg, c); got != (n == len(tc.sig)) {
				t.Errorf("sig of %d bytes (the valid one has %d): got %v", n, len(tc.sig), got)
			}
		}
	}
	for _, c := range [][]byte{lessCat(f.sig, make([]byte, lessSignatureStep)), f.sig[:len(f.sig)-lessSignatureStep], lessCat(f.sig, []byte{0}), f.sig[:len(f.sig)-1], nil} {
		if cgoLessCat1Verify(f.pk, f.msg, c) {
			t.Errorf("sig of %d bytes accepted", len(c))
		}
	}
}

func TestLessWrapperPublicKeyLength(t *testing.T) {
	f := lessWrapperFixture(t)
	for _, pk := range [][]byte{f.pk[:len(f.pk)-1], lessCat(f.pk, []byte{0}), f.pk[:1], nil, lessCat(f.pk, f.pk[:lessSignatureStep])} {
		if cgoLessCat1Verify(pk, f.msg, f.sig) {
			t.Errorf("pk of %d bytes accepted", len(pk))
		}
	}
}

// Detached verify must authenticate exactly msg: the same msg||sig split at another point opens under the key (the C reference
// reads the signature length from the trailing seed count), so only the wrapper's opened-length check refuses it.
func TestLessWrapperMessage(t *testing.T) {
	f := lessWrapperFixture(t)
	for _, i := range []int{0, len(f.msg) / 2, len(f.msg) - 1} {
		m := bytes.Clone(f.msg)
		m[i] ^= 1
		if cgoLessCat1Verify(f.pk, m, f.sig) {
			t.Errorf("message with byte %d flipped (same length) accepted", i)
		}
	}
	k := len(f.msg) - lessSignatureStep
	if cgoLessCat1Verify(f.pk, f.msg[:k], lessCat(f.msg[k:], f.sig)) {
		t.Error("a strict prefix of the signed message accepted (msg||sig re-split, signature 16 bytes longer)")
	}
	if cgoLessCat1Verify(f.pk, lessCat(f.msg, f.sig[:lessSignatureStep]), f.sig[lessSignatureStep:]) {
		t.Error("the signed message extended by signature bytes accepted (msg||sig re-split, signature 16 bytes shorter)")
	}
	if cgoLessCat1Verify(f.pk, nil, f.sig) || cgoLessCat1Verify(f.pk, []byte{}, f.sig) {
		t.Error("signature over a non-empty message accepted for the empty message")
	}
	if cgoLessCat1Verify(f.pk, f.msg[:len(f.msg)-1], f.sig) || cgoLessCat1Verify(f.pk, lessCat(f.msg, []byte{0}), f.sig) {
		t.Error("signature accepted for a message one byte shorter or longer")
	}
	if !cgoLessCat1Verify(f.pk, f.msg, f.sig) {
		t.Fatal("valid signature refused after the negative cases")
	}
}

// A message too large for the C side to allocate msg_len + sig_len: the answer is 0 (fail closed). The slice is a header over
// one real byte; the C never reads msg before both mallocs succeed, and 2^62 bytes exceeds every 64-bit user address space.
func TestLessWrapperAllocFailure(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("needs a 64-bit int")
	}
	f := lessWrapperFixture(t)
	one := []byte{f.msg[0]}
	huge := unsafe.Slice(&one[0], 1<<62)
	if cgoLessCat1Verify(f.pk, huge, f.sig) {
		t.Fatal("verify accepted when the signed-message buffer could not be allocated")
	}
}

func lessPtr(b []byte) unsafe.Pointer { return unsafe.Pointer(unsafe.SliceData(b)) }

// The C's own length checks, Go checks bypassed. Every buffer is real and at least as long as the length passed, so a mutant
// that skips a check reads only valid memory and answers in-process. Only the checked length is wrong in each case.
func TestLessWrapperRawLengths(t *testing.T) {
	f := lessWrapperFixture(t)
	raw := func(pk []byte, pkLen int, sig []byte, sigLen int) bool {
		return lessCat1VerifyRaw(lessPtr(pk), uint64(pkLen), lessPtr(f.msg), uint64(len(f.msg)), lessPtr(sig), uint64(sigLen))
	}
	if !raw(f.pk, len(f.pk), f.sig, len(f.sig)) {
		t.Fatal("raw: valid signature refused")
	}
	// pk_len +-1 over a key that is otherwise valid (the C reads exactly CRYPTO_PUBLICKEYBYTES of it)
	pkPlus := lessCat(f.pk, []byte{0})
	if raw(f.pk, len(f.pk)-1, f.sig, len(f.sig)) || raw(pkPlus, len(pkPlus), f.sig, len(f.sig)) {
		t.Error("raw: public-key length off by one accepted")
	}
	// sig_len +-1, below min, above max; min - 16 and max + 16 are step-aligned, so only the bound fails there
	big := lessCat(f.sig, bytes.Repeat([]byte{0}, 2*lessSignatureMaxBytes))
	for _, n := range []int{len(f.sig) - 1, len(f.sig) + 1, lessSignatureMinBytes - 1, lessSignatureMinBytes - lessSignatureStep, lessSignatureMaxBytes + 1, lessSignatureMaxBytes + lessSignatureStep} {
		if raw(f.pk, len(f.pk), big, n) {
			t.Errorf("raw: signature length %d accepted", n)
		}
	}
}

// Cases whose mutants dereference NULL or overrun a buffer: each runs in a child process (this test binary, re-executed), so
// a mutant's crash is a test failure here, not a dead test run. The unmutated C refuses each before reading anything.
var lessRawChildCases = []string{"nil-pk", "nil-sig", "nil-msg-with-length", "msg-len-max", "msg-len-wraps-to-zero", "msg-len-boundary"}

func TestLessWrapperRawChild(t *testing.T) {
	c := os.Getenv("PCA_LESS_RAW_CASE")
	if c == "" {
		t.Skip("child process of TestLessWrapperRawChecks")
	}
	f := lessWrapperFixture(t)
	pk, msg, sig := lessPtr(f.pk), lessPtr(f.msg), lessPtr(f.sig)
	pkLen, msgLen, sigLen := uint64(len(f.pk)), uint64(len(f.msg)), uint64(len(f.sig))
	switch c {
	case "nil-pk":
		pk = nil
	case "nil-sig":
		sig = nil
	case "nil-msg-with-length":
		msg = nil
	case "msg-len-max": // > (size_t)-1 - sig_len
		msgLen = math.MaxUint64
	case "msg-len-wraps-to-zero": // the first value over the bound: msg_len + sig_len would wrap to 0
		msgLen = math.MaxUint64 - sigLen + 1
	case "msg-len-boundary": // == the bound: passes line 65, then malloc(SIZE_MAX) fails, nothing is read
		msgLen = math.MaxUint64 - sigLen
	default:
		t.Fatalf("unknown case %q", c)
	}
	fmt.Printf("lessc-raw-result=%v\n", lessCat1VerifyRaw(pk, pkLen, msg, msgLen, sig, sigLen))
}

func TestLessWrapperRawChecks(t *testing.T) {
	if os.Getenv("PCA_LESS_RAW_CASE") != "" {
		t.Skip("in a child process")
	}
	for _, c := range lessRawChildCases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLessWrapperRawChild$", "-test.count=1")
		cmd.Env = append(os.Environ(), "PCA_LESS_RAW_CASE="+c)
		out, err := cmd.CombinedOutput()
		if err != nil || !bytes.Contains(out, []byte("lessc-raw-result=false")) {
			t.Errorf("%s: want a clean refusal, got err %v, output:\n%s", c, err, out)
		}
	}
}

// The length checks on lines 64-65 never change the result (crypto_sign_open's own length parse and the message-length
// comparison refuse every illegal length), but whether a length got past them is observable: with msg_len at the overflow
// boundary (SIZE_MAX - sig_len) an admitted length reaches malloc(SIZE_MAX), which fails with ENOMEM (POSIX), while a
// refused one returns before any allocation and leaves errno 0. Nothing is read from the buffers in either case.
func TestLessWrapperLengthChecksReachAlloc(t *testing.T) {
	f := lessWrapperFixture(t)
	_, sigMin, sigMax := lessCat1Sizes()
	buf := make([]byte, 2*sigMax)
	try := func(sigLen uint64) error {
		ok, err := lessCat1VerifyRawErrno(lessPtr(f.pk), uint64(len(f.pk)), lessPtr(f.msg), math.MaxUint64-sigLen, lessPtr(buf), sigLen)
		if ok {
			t.Fatalf("sig_len %d at the overflow boundary accepted", sigLen)
		}
		return err
	}
	for _, n := range []uint64{sigMin, sigMax} {
		if err := try(n); !errors.Is(err, syscall.ENOMEM) {
			t.Errorf("legal sig_len %d: errno %v, want ENOMEM (the overflow boundary itself is admitted)", n, err)
		}
	}
	for _, n := range []uint64{sigMin - 16, sigMax + 16, sigMin + 1, sigMax - 1} {
		if err := try(n); err != nil {
			t.Errorf("illegal sig_len %d got past the length checks (errno %v)", n, err)
		}
	}
}
