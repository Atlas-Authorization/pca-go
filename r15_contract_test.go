package pca

import (
	"math"
	"strings"
	"testing"
)

func TestProportionCutoffIsExact(t *testing.T) {
	for _, c := range []struct{ h, w, want float64 }{{1, 2000, 1107}, {8, 512, 13}, {0.5, 512, 410}} {
		got, err := ProportionCutoff(c.h, c.w)
		if err != nil || got != c.want {
			t.Fatalf("h=%v w=%v: got %v err %v, want %v", c.h, c.w, got, err, c.want)
		}
	}
	for _, c := range [][2]float64{{0.0625, 512}, {65, 512}, {1.1, 512}, {math.NaN(), 512}, {8, 1}, {8, 65537}, {8, 2.5}, {8, math.NaN()}} {
		if _, err := ProportionCutoff(c[0], c[1]); err == nil {
			t.Errorf("h=%v w=%v must be refused", c[0], c[1])
		}
	}
	// the old float recurrence returned w+1 here and so disabled the test
	if got, _ := ProportionCutoff(1, 2000); got >= 2001 {
		t.Fatalf("cutoff %v is unreachable", got)
	}
}

func TestHealthTestBytesProportionDomain(t *testing.T) {
	buf := make([]byte, 600)
	for i := range buf {
		buf[i] = byte(i * 7)
	}
	h := 1.1
	if v := HealthTestBytes(buf, HealthTestOptions{H: &h}); v.OK || v.Test != "repetition-count" {
		t.Fatalf("h that is not a multiple of 1/8 must give the failed repetition verdict: %+v", v)
	}
	one := []byte{1}
	if v := HealthTestBytes(one, HealthTestOptions{}); !v.OK {
		t.Fatalf("a one-byte window skips the proportion test: %+v", v)
	}
	// a window of 2000 at h=1 is judged against 1107, not disabled
	h1, w := 1.0, 2000.0
	run := make([]byte, 2000)
	for i := range run {
		run[i] = byte(i % 2)
	}
	if v := HealthTestBytes(run, HealthTestOptions{H: &h1, Window: &w}); !v.OK {
		t.Fatalf("1000 matches in a 2000 window are below 1107: %+v", v)
	}
	for i := range run {
		run[i] = 0
		if i%5 == 4 {
			run[i] = 1
		}
	}
	if v := HealthTestBytes(run, HealthTestOptions{H: &h1, Window: &w}); v.OK || v.Test != "adaptive-proportion" {
		t.Fatalf("1600 matches in a 2000 window reach 1107: %+v", v)
	}
}

func TestDetMathPinnedValues(t *testing.T) {
	negZero := math.Copysign(0, -1)
	if !math.IsInf(DetLn(0), -1) || !math.IsInf(DetLn(negZero), -1) || !math.IsInf(DetLog2(0), -1) || !math.IsInf(DetLog2(negZero), -1) {
		t.Fatal("detLn and detLog2 of zero are -Infinity")
	}
	if !math.IsNaN(DetLog2(-1)) || !math.IsNaN(DetLog2(math.NaN())) || DetExp(math.Inf(-1)) != 0 {
		t.Fatal("detLog2 of a negative or NaN is NaN; detExp(-Infinity) is 0")
	}
	if DetLn(1) != 0 || !math.IsNaN(DetLn(-1)) || !math.IsNaN(DetLn(math.NaN())) || !math.IsInf(DetLn(math.Inf(1)), 1) {
		t.Fatal("detLn special values")
	}
	if got := DetLn(100); got != 4.605170185988092 {
		t.Fatalf("detLn(100) = %v", got)
	}
	if got := DetLn(0.5); got != -0.6931471805599453 {
		t.Fatalf("detLn(0.5) = %v", got)
	}
	for _, e := range []int{-1074, -1022, -10, -1, 0, 1, 3, 52, 1023} {
		if got := DetLog2(math.Ldexp(1, e)); got != float64(e) {
			t.Fatalf("detLog2(2^%d) = %v", e, got)
		}
	}
	if DetExp(0) != 1 || !math.IsInf(DetExp(710), 1) || DetExp(-746) != 0 || !math.IsNaN(DetExp(math.NaN())) {
		t.Fatal("detExp special values")
	}
	if got := DetExp(1); got != 2.718281828459045 {
		t.Fatalf("detExp(1) = %v", got)
	}
	if DetPowInt(2, 10) != 1024 || DetPowInt(0.5, 3) != 0.125 || DetPowInt(7, 0) != 1 {
		t.Fatal("detPowInt")
	}
	// the smallest subnormal is checked against its exact value: some platforms' math.Log does not normalise a subnormal argument
	if d := math.Abs(DetLn(5e-324) - (-1074 * math.Ln2)); d > 4*0x1p-52*1074*math.Ln2 {
		t.Errorf("detLn(5e-324) off by %v", d)
	}
	for _, x := range []float64{2, 0.5, 100, 1e-5, 0.9, 1.1, 3, 1e10, 1e-300, 1e300, math.MaxFloat64} {
		want := math.Log(x)
		if d := math.Abs(DetLn(x) - want); d > 4*0x1p-52*math.Abs(want) {
			t.Errorf("detLn(%v) off by %v", x, d)
		}
	}
}

func TestWalletBetaUpperExactIsClopperPearson(t *testing.T) {
	got, err := WalletBetaUpperExact(0.05, 3, 7)
	want, _ := ClopperPearsonUpper(2, 9, 0.05)
	if err != nil || got != want {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
	for _, c := range [][2]float64{{0, 1}, {1, 0}, {1.5, 2}} {
		if _, err := WalletBetaUpperExact(0.05, c[0], c[1]); err == nil {
			t.Errorf("a=%v b=%v must be refused", c[0], c[1])
		}
	}
}

// A sigma opening goes on the wire in the reference's member order (s, then nonce): the other parties hash the frame as received,
// so a different order makes the transcript digests disagree (the mixed-language meshes blamed this party).
func TestSigmaOpeningFrameKeepsTheReferenceMemberOrder(t *testing.T) {
	got, err := MpcStringify(map[string]any{"nonce": "ab", "s": []any{"01", "02"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"s":["01","02"],"nonce":"ab"}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	frame, err := MpcEncodeFrame(float64(1), "msg", "sid", int64(0), "sig-o", map[string]any{"nonce": "ab", "s": []any{"01"}})
	if err != nil || !strings.Contains(string(frame), `"d":{"s":["01"],"nonce":"ab"}`) {
		t.Fatalf("the frame carries the opening in the reference order: %q (%v)", frame, err)
	}
}

// The transcript digest hashes what each party broadcast as JSON.stringify of the parsed frame, which keeps the member order the
// sender wrote. A sender that writes a sigma opening as {nonce, s} (an implementation whose objects are sorted) is hashed in that
// order, not rewritten to {s, nonce}: rewriting made this party's digest differ from every other implementation's.
func TestTranscriptHashesAPeersMemberOrderAsReceived(t *testing.T) {
	for _, c := range []struct{ frame, want string }{
		{`{"d":{"nonce":"ab","s":["01","02"]}}`, `{"nonce":"ab","s":["01","02"]}`},
		{`{"d":{"s":["01","02"],"nonce":"ab"}}`, `{"s":["01","02"],"nonce":"ab"}`},
	} {
		m := mpcParseObject([]byte(c.frame))
		got, err := MpcStringify(m["d"])
		if err != nil || got != c.want {
			t.Fatalf("frame %s: stringified %q (%v), want %q", c.frame, got, err, c.want)
		}
	}
	// a map built here has no recorded order: the reference's construction order for a sigma opening
	own, err := MpcStringify(map[string]any{"nonce": "ab", "s": []any{"01"}})
	if err != nil || own != `{"s":["01"],"nonce":"ab"}` {
		t.Fatalf("own opening %q (%v)", own, err)
	}
}
