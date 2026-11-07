package pca

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

// The empty string is a legal member name: validate.ts / traits.ts refuse it like any other unknown member, naming it with empty quotes.
func TestW3aUnknownMemberEmptyName(t *testing.T) {
	one := map[string]any{"": jsNumber(1)}
	for _, c := range []struct{ name, got, want string }{
		{"def", validateDef(one), "unknown member ''"},
		{"param", defParamError("p", one, map[string]bool{}), "p: unknown member ''"},
		{"review", defReviewError(one), "review: unknown member ''"},
		{"attestation", defReviewError(map[string]any{"state": "confirmed", "attestation": one}), "review.attestation: unknown member ''"},
		{"profile", profileErrorRaw(one), "profile: unknown member ''"},
	} {
		if c.got != c.want {
			t.Errorf("%s: %q, want %q", c.name, c.got, c.want)
		}
	}
	if k, bad := unknownMember(map[string]any{"kind": 1}, []string{"kind"}); bad || k != "" {
		t.Errorf("no unknown member: %q %v", k, bad)
	}
	// map order is random: repeat so either visiting order of the two keys is exercised
	for i := 0; i < 64; i++ {
		if k, bad := unknownMember(map[string]any{"b": 1, "": 1, "kind": 1}, []string{"kind"}); !bad || k != "" {
			t.Fatalf("the sorted-first unknown member is the empty name: %q %v", k, bad)
		}
	}
}

// TextEncoder writes U+FFFD for a lone surrogate only: U+D000 and U+D7FF (also ED-led) stay as they are beside one.
func TestW3aWellFormedKeepsNonSurrogateEDSequences(t *testing.T) {
	for _, c := range [][2]string{
		{"\xed\xa0\x80\xed\x80\x80", "\xef\xbf\xbd\xed\x80\x80"},
		{"\xed\x9f\xbf\xed\xbf\xbf", "\xed\x9f\xbf\xef\xbf\xbd"},
	} {
		if got := wellFormedUTF8(c[0]); got != c[1] {
			t.Errorf("wellFormedUTF8(%x) = %x, want %x", c[0], got, c[1])
		}
	}
}

// attest-nvidia-rim.ts parseVersion is parseInt(part, radix) behind the pattern: hex parts parse in base 16, and a decimal part
// past float64 is Infinity (parseInt), which then compares above everything, itself included (NaN !== 0, not < 0).
func TestW3aParseVersionIsParseInt(t *testing.T) {
	for _, c := range []struct {
		v     string
		radix int
		want  []float64
	}{
		{"1f.A", 16, []float64{31, 10}},
		{"ffff.0", 16, []float64{65535, 0}},
		{"18446744073709551616.1", 10, []float64{18446744073709551616, 1}},
		{"1" + strings.Repeat("0", 400) + ".1", 10, []float64{math.Inf(1), 1}},
	} {
		if got, ok := parseVersion(c.v, c.radix); !ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("parseVersion(%.24q, %d) = %v %v, want %v", c.v, c.radix, got, ok, c.want)
		}
	}
	if got, ok := parseVersion("1ffff", 16); ok || got != nil {
		t.Errorf("five hex digits: %v %v", got, ok)
	}
	inf := []float64{math.Inf(1)}
	if cmpVersion(inf, inf) != 1 || cmpVersion(inf, []float64{1}) != 1 || cmpVersion([]float64{1}, inf) != -1 {
		t.Errorf("Infinity order: %d %d %d", cmpVersion(inf, inf), cmpVersion(inf, []float64{1}), cmpVersion([]float64{1}, inf))
	}
}

// undo.ts verifyUndoReceipt checks each shape term before the signature: a receipt with one defect stays refused even though it
// is correctly signed over that very content, so every term must refuse alone.
func TestW3aUndoReceiptEachTermRefusesAlone(t *testing.T) {
	key, err := KeyPairFromSeed(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	other, err := KeyPairFromSeed([]byte(strings.Repeat("\x09", 32)))
	if err != nil {
		t.Fatal(err)
	}
	base, err := SignUndoReceipt(UndoReceiptBody{Record: "rec-1", Event: "opened", State: "open", At: 1000, CompensationDigest: "cd"}, key)
	if err != nil {
		t.Fatal(err)
	}
	resign := func(member string, val any) map[string]any {
		body := withoutKeys(base, "sig")
		if member != "" {
			body[member] = val
		}
		r, err := undoSign(UndoReceiptDomain, body, key)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if !VerifyUndoReceipt(resign("", nil), key.Public) {
		t.Fatal("control: the re-signed receipt must verify")
	}
	for _, c := range []struct {
		member string
		val    any
	}{
		{"v", 2}, {"v", "1"}, {"kind", "other"}, {"record", ""}, {"event", "nope"}, {"state", "nope"}, {"at", "1"},
		{"compensation_digest", 1}, {"prev", 1}, {"note", 1}, {"signer", other.Public},
	} {
		if VerifyUndoReceipt(resign(c.member, c.val), key.Public) {
			t.Errorf("%s=%v verified", c.member, c.val)
		}
	}
	noSig := withoutKeys(base, "sig")
	noSig["sig"] = 5
	if VerifyUndoReceipt(noSig, key.Public) {
		t.Error("a non-string sig verified")
	}
}
