package pca

// r5n6: kills for mutants that otherwise end the test binary (an endless loop, an unlocked-forever mutex, a nil dereference or
// an index panic) instead of failing a test. Each call runs on its own goroutine under a deadline with its panic caught, so such a
// mutant becomes an ordinary failure on the first call it spoils. The a0_00 name sorts before every other test file, and the
// suite runs with -failfast: these are the first tests to meet the mutant. None of them runs pathShape or certKids over a valid
// child list: the mutants that grow memory without bound there are decided by the run-error ledger, not here.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// r5n6Run fails the test when f panics, does not finish within the deadline, or returns a message.
func r5n6Run(t *testing.T, what string, f func() string) {
	t.Helper()
	type outcome struct {
		msg string
		pan any
	}
	ch := make(chan outcome, 1)
	go func() {
		var o outcome
		defer func() {
			if p := recover(); p != nil {
				o.pan = p
			}
			ch <- o
		}()
		o.msg = f()
	}()
	select {
	case o := <-ch:
		if o.pan != nil {
			t.Fatalf("%s: panic: %v", what, o.pan)
		}
		if o.msg != "" {
			t.Fatalf("%s: %s", what, o.msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%s: did not finish within 2s", what)
	}
}

// split of 2 would end whatever k starts at; 3 is the first size where k has to double.
func TestR5N6A_SplitTerminates(t *testing.T) {
	r5n6Run(t, "split", func() string {
		for _, c := range []struct{ n, want int }{{3, 2}, {2, 1}, {5, 4}, {9, 8}} {
			if got := split(c.n); got != c.want {
				return fmt.Sprintf("split(%d) = %d, want %d", c.n, got, c.want)
			}
		}
		return ""
	})
}

func TestR5N6A_DecodeB64uStrictReadsInBounds(t *testing.T) {
	r5n6Run(t, "DecodeB64uStrict", func() string {
		if b, ok := DecodeB64uStrict("AAAA", -1); !ok || len(b) != 3 {
			return fmt.Sprintf("AAAA: %v %v", b, ok)
		}
		if _, ok := DecodeB64uStrict("AA=", -1); ok {
			return "AA= accepted"
		}
		return ""
	})
}

func TestR5N6A_CanonicalizeKeys(t *testing.T) {
	r5n6Run(t, "Canonicalize", func() string {
		if got, err := Canonicalize(map[string]any{}); err != nil || got != "{}" {
			return fmt.Sprintf("empty map: %q %v", got, err)
		}
		if got, err := Canonicalize(map[string]any{"b": "x", "a": "y"}); err != nil || got != `{"a":"y","b":"x"}` {
			return fmt.Sprintf("two keys: %q %v", got, err)
		}
		return ""
	})
}

// A normal amount first: a mutant that loses the zero padding never ends, one that flips a bound refuses it. The refusals follow.
func TestR5N6A_MinorToDecimal(t *testing.T) {
	r5n6Run(t, "MinorToDecimal", func() string {
		for _, c := range []struct {
			minor, exp int64
			want       string
		}{{5, 2, "0.05"}, {1234, 2, "12.34"}, {7, 0, "7"}, {100, 2, "1.00"}} {
			if got, err := MinorToDecimal(c.minor, c.exp); err != nil || got != c.want {
				return fmt.Sprintf("MinorToDecimal(%d, %d) = %q %v, want %q", c.minor, c.exp, got, err, c.want)
			}
		}
		for _, c := range []struct{ minor, exp int64 }{{-1, 2}, {maxSafeInt + 1, 2}, {1, 19}, {1, -1}} {
			if got, err := MinorToDecimal(c.minor, c.exp); err == nil || got != "" {
				return fmt.Sprintf("MinorToDecimal(%d, %d) = %q %v, want a refusal", c.minor, c.exp, got, err)
			}
		}
		return ""
	})
}

// readCertElem and certKids over a child that overruns its parent: a refusal, never a zero element whose end sends the
// walk back to the start. The input ends the mutants it targets at a wrong answer, not in a loop.
func TestR5N6A_CertElemOverrun(t *testing.T) {
	if e, err := readCertElem([]byte{0x30, 0x05, 0x00}, 0, 3, 0); err == nil || err.Error() != osslNested || e != (certElem{}) {
		t.Fatalf("overrunning element: %+v %v", e, err)
	}
	b := []byte{0x30, 0x03, 0x02, 0x05, 0x00}
	e, err := readCertElem(b, 0, len(b), 0x30)
	if err != nil {
		t.Fatal(err)
	}
	if kids, err := certKids(b, e); err == nil || err.Error() != osslNested || kids != nil {
		t.Fatalf("kids of an overrunning child: %v %v", kids, err)
	}
}

// Every nil dereference and every missing Unlock of the registry shows on this path: the first Accept builds the lease
// state, the others take the lock again after each kind of call, and the revocation prunes with no ceiling configured.
func TestR5N6A_LeaseRegistryScenario(t *testing.T) {
	k := newKey(t)
	lease := g04SignLease(t, k, g04Lease())
	rev := g04SignRev(t, k, map[string]any{"v": jnum(1), "target": "lease", "value": "L1", "revoked_at": jnum(500)})
	r5n6Run(t, "lease registry", func() string {
		reg := NewLeaseRegistry(LeasePolicy{Authorities: []string{k.id}})
		if r := reg.Accept(lease, nil); !r.Ok || !r.Replaced || r.Seq != 1 {
			return fmt.Sprintf("accept: %+v", r)
		}
		if reg.Get("L1") == nil || reg.Get("never") != nil {
			return "get after accept"
		}
		if d := CheckLease(lease, reg, jnum(150)); d.Decision != "allow" || d.ExpiresAt != 200 || d.LeaseID != "L1" {
			return fmt.Sprintf("check before revocation: %+v", d)
		}
		if reg.Get("L1") == nil {
			return "get after check"
		}
		if code, n := reg.Revoke(rev); code != "" || n != 1 {
			return fmt.Sprintf("revoke: %q %d", code, n)
		}
		if reg.Get("L1") == nil {
			return "get after revoke"
		}
		if d := CheckLease(lease, reg, jnum(150)); d.Decision != "deny" || d.Code != "revoked" {
			return fmt.Sprintf("check after revocation: %+v", d)
		}
		if code, n := reg.Revoke(rev); code != "" || n != 1 {
			return fmt.Sprintf("second revoke: %q %d", code, n)
		}
		if reg.Get("L1") == nil {
			return "get after second revoke"
		}
		return ""
	})
}

// Rows in the order a mutant meets them: one plain value first, then each escape, then the two deep inputs. A parse loop that
// stops advancing hangs on the first row it spoils; the nesting rows pin the depth counter and the early return after a failure.
func TestR5N6A_V8JSONTerminates(t *testing.T) {
	rows := [][2]string{
		{"1", ""},
		{" 1", ""},
		{`"a"`, ""},
		{`"a`, "Unterminated string in JSON at position 2 (line 1 column 3)"},
		{"\"\u0001\"", "Bad control character in string literal in JSON at position 1 (line 1 column 2)"},
		{`"\n"`, ""},
		{`"\""`, ""},
		{`"A"`, ""},
		{`{"a":1}`, ""},
		{`{"a":1,"b":[true,null]}`, ""},
		{"NaN", `"NaN" is not valid JSON`},
		{"undefined", `"undefined" is not valid JSON`},
		{"Infinity", `"Infinity" is not valid JSON`},
		{"[object Object]", `"[object Object]" is not valid JSON`},
		{"[" + strings.Repeat("1,", MaxLenientDepth+5) + "1]", ""},
		{strings.Repeat(`{"a":`, MaxLenientDepth+2), "nesting too deep"},
	}
	r5n6Run(t, "v8JSONError", func() string {
		for _, r := range rows {
			if got := v8JSONError(r[0]); got != r[1] {
				in := r[0]
				if len(in) > 40 {
					in = in[:40] + "..."
				}
				return fmt.Sprintf("v8JSONError(%q) = %q, want %q", in, got, r[1])
			}
		}
		return ""
	})
}
