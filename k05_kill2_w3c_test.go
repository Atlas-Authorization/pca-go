package pca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)

// attest-azure-maa.ts:428: an ES256 token under anything but a P-256 key is refused, even when the signature is 64 bytes and
// verifies. The P-384 key is recovered from a chosen (r, s) with r < 2^256, so r||s fits 64 bytes: Q = r^-1 (sR - zG).
func TestW3cES256RefusesP384EvenIfTheSignatureVerifies(t *testing.T) {
	input := []byte("h.p")
	digest := sha256Sum(input)
	c := elliptic.P384()
	n := c.Params().N
	var rx, ry *big.Int
	for x := int64(2); rx == nil; x++ {
		buf := make([]byte, 49)
		buf[0] = 2
		big.NewInt(x).FillBytes(buf[1:])
		rx, ry = elliptic.UnmarshalCompressed(c, buf)
	}
	s := big.NewInt(1)
	rInv := new(big.Int).ModInverse(rx, n)
	z := new(big.Int).SetBytes(digest)
	ux, uy := c.ScalarMult(rx, ry, new(big.Int).Mod(new(big.Int).Mul(rInv, s), n).Bytes())
	vx, vy := c.ScalarBaseMult(new(big.Int).Mod(new(big.Int).Neg(new(big.Int).Mul(rInv, z)), n).Bytes())
	qx, qy := c.Add(ux, uy, vx, vy)
	pub := &ecdsa.PublicKey{Curve: c, X: qx, Y: qy}
	sig := make([]byte, 64)
	rx.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	if !verifyRawECDSA(pub, digest, sig) {
		t.Fatal("fixture: the recovered P-384 key must verify the 64-byte signature")
	}
	if jwsES256OK(sig, input, certKey{pub: pub}) {
		t.Error("ES256 accepted a P-384 key")
	}

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r2, s2, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		t.Fatal(err)
	}
	good := make([]byte, 64)
	r2.FillBytes(good[:32])
	s2.FillBytes(good[32:])
	if !jwsES256OK(good, input, certKey{pub: &k.PublicKey}) {
		t.Error("a valid P-256 ES256 signature was refused")
	}
}

// attest-nvidia-ocsp.ts:102-105: minute and second have no second guard (a roll-over stays in the same day), so only the range
// check refuses them; every other out-of-range field is refused too.
func TestW3cOcspTimeRanges(t *testing.T) {
	for _, s := range []string{"20260101006000Z", "20260101000060Z", "20260101240000Z", "20261301000000Z", "20260001000000Z", "20260100000000Z", "20260132000000Z", "20260230000000Z"} {
		if _, ok := ocspTimeMs(s, false); ok {
			t.Errorf("GeneralizedTime %s accepted", s)
		}
	}
	for _, s := range []string{"260101006000Z", "260101000060Z", "260101240000Z", "261301000000Z", "260230000000Z"} {
		if _, ok := ocspTimeMs(s, true); ok {
			t.Errorf("UTCTime %s accepted", s)
		}
	}
	want := time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC).UnixMilli()
	if ms, ok := ocspTimeMs("20260101235959Z", false); !ok || ms != want {
		t.Errorf("GeneralizedTime: %d %v", ms, ok)
	}
	if ms, ok := ocspTimeMs("260101235959Z", true); !ok || ms != want {
		t.Errorf("UTCTime: %d %v", ms, ok)
	}
}

// server/authorize.ts:524: a refused result, or an invalid operation, is never authorized, even when the bound operation matches.
func TestW3cIsAuthorizedForGuards(t *testing.T) {
	params := map[string]any{"a": json.Number("1")}
	d, err := ParamsDigest(params)
	if err != nil {
		t.Fatal(err)
	}
	op := &Operation{Verb: "v", Resource: "r", Params: params}
	bound := &AuthorizedOperation{Verb: "v", Resource: "r", ParamsDigest: d}
	if !IsAuthorizedFor(AuthorizeResult{Allow: true, Operation: bound}, op) {
		t.Fatal("the exact allowed operation must be authorized")
	}
	if IsAuthorizedFor(AuthorizeResult{Allow: false, Operation: bound}, op) {
		t.Error("a refused result authorized its operation")
	}
	empty, err := ParamsDigest(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if IsAuthorizedFor(AuthorizeResult{Allow: true, Operation: &AuthorizedOperation{Verb: "v", Resource: "r", ParamsDigest: empty}}, &Operation{Verb: "v", Resource: "r"}) {
		t.Error("an operation without params was authorized")
	}
	if IsAuthorizedFor(AuthorizeResult{Allow: true, Operation: &AuthorizedOperation{Resource: "r", ParamsDigest: d}}, &Operation{Resource: "r", Params: params}) {
		t.Error("an operation without a verb was authorized")
	}
}

// server/authorize.ts:156 and :392: the call's workflow step is read only when the workflow option is configured.
func TestW3cWorkflowStepIgnoredWithoutWorkflowOption(t *testing.T) {
	in, _, p := g01Fix(t)
	in.Workflow = nil
	in.WorkflowStep = &WorkflowCall{Step: "ignored"}
	if r := Authorize(p, in); !r.Allow || r.Status != 200 {
		t.Fatalf("a step with no workflow option changed the decision: %+v", r)
	}
}

// caveat-lang.ts:530 turns a missing store into a fail-closed "max_uses error"; Go names the cause rather than leaking a nil
// dereference (the engine's TypeError text of the reference is not portable).
func TestW3cReserveMaxUsesNoStore(t *testing.T) {
	bound := []BoundCaveat{{Caveat: map[string]any{"type": CaveatMaxUses, "id": "a", "n": jnum(1), "until": jnum(100)}, CapHash: "c"}}
	r := ReserveMaxUses(nil, bound, 1)
	if r.OK || r.Spent != 0 || !strings.HasPrefix(r.Reason, "max_uses error (fail closed): ") {
		t.Fatalf("%+v", r)
	}
}

// Array.prototype.sort is stable: strings tying in UTF-16 order keep their input order ("\xff" decodes to U+FFFD, one unit).
func TestW3cK3SortStableOnTies(t *testing.T) {
	for _, in := range [][]string{{"\xff", "�"}, {"�", "\xff"}} {
		if got := k3SortedAny(in); !reflect.DeepEqual(got, []any{in[0], in[1]}) {
			t.Errorf("%q: %q", in, got)
		}
	}
	if got := k3SortedAny([]string{"b", "a"}); !reflect.DeepEqual(got, []any{"a", "b"}) {
		t.Errorf("%q", got)
	}
}
