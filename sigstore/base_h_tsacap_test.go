package pcasigstore

import (
	"encoding/json"
	"strings"
	"testing"
)

// H6: a bundle carries at most 8 RFC 3161 timestamps (each is a full CMS + chain + signature check).
func TestH6_TimestampCap(t *testing.T) {
	f := g07sNewFx(t)
	base := f.bundle(g07sOpt{kind: "hashedrekord"})
	withTimestamps := func(n int) []byte {
		var m map[string]any
		d := json.NewDecoder(strings.NewReader(string(base)))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatal(err)
		}
		tv := g07sSub(m, "verificationMaterial", "timestampVerificationData")
		one := tv["rfc3161Timestamps"].([]any)[0]
		list := make([]any, n)
		for i := range list {
			list[i] = one
		}
		tv["rfc3161Timestamps"] = list
		return g07sMarshal(m)
	}
	if r := VerifySigstoreBundleCore(withTimestamps(8), f.roots); !r.OK {
		t.Fatalf("8 timestamps: %s: %s", r.Code, r.Detail)
	}
	r := VerifySigstoreBundleCore(withTimestamps(9), f.roots)
	if r.OK || r.Code != "tsa" || !strings.Contains(r.Detail, "too many RFC 3161 timestamps (9, at most 8)") {
		t.Errorf("9 timestamps: %+v", r)
	}
	// a hostile count is refused before any of them is verified
	if r := VerifySigstoreBundleCore(withTimestamps(5000), f.roots); r.OK || r.Code != "tsa" || !strings.Contains(r.Detail, "(5000, at most 8)") {
		t.Errorf("5000 timestamps: %+v", r)
	}
}
