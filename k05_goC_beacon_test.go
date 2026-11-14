package pca

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const goCBeaconIat = 1_200_000

func goCBeaconBody(kp *KeyPair, over map[string]any) map[string]any {
	body := map[string]any{"v": 2, "instance": "inst", "scope": "*", "epoch": goCBeaconIat / BeaconEpochMs, "seq": 3,
		"issued_at": goCBeaconIat, "not_after": goCBeaconIat + 300_000, "issuer": kp.Public}
	for k, v := range over {
		if v == nil {
			delete(body, k)
		} else {
			body[k] = v
		}
	}
	return body
}

func goCSignBeacon(t *testing.T, kp *KeyPair, over map[string]any) map[string]any {
	t.Helper()
	b, err := SignArtifact(livenessDomain, goCBeaconBody(kp, over), kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGoCBeaconConstants(t *testing.T) {
	if BeaconEpochMs != 60000 || BeaconMaxValidity != 3600000 || BeaconClockSkewMs != 30000 {
		t.Fatal("beacon constants changed")
	}
}

func TestGoCBeaconIssueBounds(t *testing.T) {
	kp, _ := NewKeyPair()
	const maxSafe = int64(maxSafeBeaconInt)
	for _, c := range []struct {
		name, msg          string
		seq, iat, validity int64
	}{
		{"seq negative", "seq must be a non-negative integer", -1, 0, 0},
		{"seq above safe", "seq must be a non-negative integer", maxSafe + 1, 0, 0},
		{"iat negative", "issuedAt must be an integer", 0, -1, 0},
		{"iat above safe", "issuedAt must be an integer", 0, maxSafe + 1, 0},
		{"validity negative", "validity must be in (0, 3600000] ms", 0, 0, -1},
		{"validity above max", "validity must be in (0, 3600000] ms", 0, 0, BeaconMaxValidity + 1},
	} {
		b, err := IssueLivenessBeacon(kp, "inst", "", c.seq, c.iat, c.validity, nil)
		if err == nil || b != nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: got %v %v", c.name, b, err)
		}
	}
	// accepted boundaries
	if _, err := IssueLivenessBeacon(kp, "inst", "", 0, 0, 1, nil); err != nil {
		t.Errorf("seq 0 / iat 0 / validity 1: %v", err)
	}
	if _, err := IssueLivenessBeacon(kp, "inst", "", maxSafe, 0, BeaconMaxValidity, nil); err != nil {
		t.Errorf("seq max / validity max: %v", err)
	}
	if _, err := IssueLivenessBeacon(kp, "inst", "", 0, maxSafe-BeaconMaxValidity, BeaconMaxValidity, nil); err != nil {
		t.Errorf("iat at the largest representable window: %v", err)
	}
	// issuedAt == max is not refused by the issuedAt guard itself
	if _, err := IssueLivenessBeacon(kp, "inst", "", 0, maxSafe, 1, nil); err != nil && strings.Contains(err.Error(), "issuedAt must be") {
		t.Errorf("iat == max must pass the issuedAt guard: %v", err)
	}
	// defaults: 5 epochs, global scope, epoch = floor(iat / 60000)
	b, err := IssueLivenessBeacon(kp, "inst", "", 7, 120_005, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if b["scope"] != GlobalScope || fmt.Sprint(b["not_after"]) != "420005" || fmt.Sprint(b["epoch"]) != "2" {
		t.Errorf("defaults: %v", b)
	}
}

func TestGoCBeaconVerifyWindows(t *testing.T) {
	kp, _ := NewKeyPair()
	iss := []string{kp.Public}
	const now = goCBeaconIat + 1000
	for _, c := range []struct {
		name string
		over map[string]any
		now  int64
		want string
	}{
		{"v3", map[string]any{"v": 3}, now, "malformed beacon"},
		{"v missing", map[string]any{"v": nil}, now, "malformed beacon"},
		{"epoch type", map[string]any{"epoch": "x"}, now, "malformed window"},
		{"seq type", map[string]any{"seq": "x"}, now, "malformed window"},
		{"iat type", map[string]any{"issued_at": "x"}, now, "malformed window"},
		{"nafter type", map[string]any{"not_after": "x"}, now, "malformed window"},
		{"seq negative", map[string]any{"seq": -1}, now, "malformed window"},
		{"seq zero ok", map[string]any{"seq": 0}, now, ""},
		{"zero validity", map[string]any{"not_after": goCBeaconIat}, now, "validity exceeds the hard maximum"},
		{"one ms validity", map[string]any{"not_after": goCBeaconIat + 1}, now - 999, ""},
		{"max validity", map[string]any{"not_after": goCBeaconIat + 3_600_000}, now, ""},
		{"over max validity", map[string]any{"not_after": goCBeaconIat + 3_600_001}, now, "validity exceeds the hard maximum"},
		{"epoch off", map[string]any{"epoch": 21}, now, "epoch does not match issued_at"},
		{"epoch floor", map[string]any{"issued_at": 1_259_999, "not_after": 1_559_999, "epoch": 20}, 1_260_000, ""},
		{"epoch floor off", map[string]any{"issued_at": 1_259_999, "not_after": 1_559_999, "epoch": 21}, 1_260_000, "epoch does not match issued_at"},
		{"skew exact", nil, goCBeaconIat - 30_000, ""},
		{"skew over", nil, goCBeaconIat - 30_001, "not yet valid"},
		{"expiry exact", nil, goCBeaconIat + 300_000, ""},
		{"expired", nil, goCBeaconIat + 300_001, "expired"},
	} {
		b := goCSignBeacon(t, kp, c.over)
		v := VerifyLivenessBeacon(b, iss, c.now, "inst", "", nil)
		if c.want == "" && !v.OK || c.want != "" && (v.OK || v.Reason != c.want) {
			t.Errorf("%s: %+v want %q", c.name, v, c.want)
		}
	}
	// a body signed without a scope key verifies without a null scope being substituted
	nb := goCSignBeacon(t, kp, map[string]any{"scope": nil})
	if v := VerifyLivenessBeacon(nb, iss, now, "inst", "", nil); !v.OK {
		t.Errorf("absent scope: %+v", v)
	}
	// unknown alg is malformed (before any signature work)
	ub := goCSignBeacon(t, kp, nil)
	ub["alg"] = "bogus"
	if v := VerifyLivenessBeacon(ub, iss, now, "inst", "", nil); v.OK || v.Reason != "malformed beacon" {
		t.Errorf("unknown alg: %+v", v)
	}
	// a PQ suite without pq_pk has no signing message
	pb := goCSignBeacon(t, kp, nil)
	pb["alg"] = "ml-dsa-65"
	if m, ok := beaconMsg(pb); ok || m != nil {
		t.Errorf("beaconMsg without pq_pk: %v %v", m, ok)
	}
	if v := VerifyLivenessBeacon(pb, iss, now, "inst", "", nil); v.OK || v.Reason != "bad signature" {
		t.Errorf("pq without pk: %+v", v)
	}
	// a body that cannot be canonicalized has no signing message
	if m, ok := beaconMsg(map[string]any{"seq": make(chan int)}); ok || m != nil {
		t.Errorf("beaconMsg uncanonical: %v %v", m, ok)
	}
	if _, ok := beaconMsg(map[string]any{"seq": jn("1")}); !ok {
		t.Error("beaconMsg must succeed on a canonical body")
	}
}

func TestGoCAcceptBeaconSeq(t *testing.T) {
	for _, c := range []struct {
		name string
		seq  any
		ok   bool
	}{
		{"zero", jn("0"), true},
		{"one", jn("1"), true},
		{"max", jn("9007199254740991"), true},
		{"above max", jn("9007199254740992"), false},
		{"negative", jn("-1"), false},
		{"string", "3", false},
		{"missing", nil, false},
	} {
		next := map[string]any{}
		if c.seq != nil {
			next["seq"] = c.seq
		}
		v := AcceptBeacon(nil, next)
		if v.OK != c.ok || (!c.ok && v.Reason != "malformed beacon") {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
}

func TestGoCIsFrozenInvalidBeacon(t *testing.T) {
	kp, _ := NewKeyPair()
	other, _ := NewKeyPair()
	iss := []string{kp.Public}
	const now = goCBeaconIat + 1000
	bad := goCSignBeacon(t, other, nil)
	good := goCSignBeacon(t, kp, nil)
	if !IsFrozenLiveness([]map[string]any{bad}, iss, now, "inst", "", nil) {
		t.Error("only an unpinned beacon: must stay frozen")
	}
	if !IsFrozenLiveness([]map[string]any{bad, bad}, iss, now, "inst", "", nil) {
		t.Error("two unpinned beacons: must stay frozen")
	}
	if IsFrozenLiveness([]map[string]any{bad, good}, iss, now, "inst", "", nil) {
		t.Error("a later valid beacon thaws")
	}
}

func TestGoCBeaconSeqKey(t *testing.T) {
	got := beaconSeqKey(map[string]any{"instance": "a<b&c>", "scope": "*", "issuer": "x"})
	if got != `beacon-seq/v1/["a<b&c>","*","x"]` {
		t.Errorf("key: %q", got)
	}
}

func TestGoCNewBeaconAcceptorNeedsKV(t *testing.T) {
	a, err := NewBeaconAcceptor(nil)
	if err == nil || a != nil || err.Error() != "createBeaconAcceptor: a DurableKv is required" {
		t.Errorf("nil kv: %v %v", a, err)
	}
}

type goCBeaconKV struct {
	update func(key string, fn func(prev []byte) []byte) error
}

func (k goCBeaconKV) Get(string) ([]byte, bool, error) { return nil, false, nil }
func (k goCBeaconKV) Update(key string, fn func(prev []byte) []byte) error {
	return k.update(key, fn)
}

func TestGoCBeaconAcceptorBranches(t *testing.T) {
	kp, _ := NewKeyPair()
	other, _ := NewKeyPair()
	iss := []string{kp.Public}
	const now = goCBeaconIat + 1000
	acc := func(kv AtomicKV, b map[string]any) BeaconVerdict {
		a, _ := NewBeaconAcceptor(kv)
		return a.Accept(b, iss, now, "inst", "", nil)
	}
	// an invalid beacon is refused with the verifier's reason and never reaches the store
	touched := false
	spy := goCBeaconKV{func(string, func([]byte) []byte) error { touched = true; return nil }}
	if v := acc(spy, goCSignBeacon(t, other, nil)); v.OK || v.Reason != "issuer not pinned" || touched {
		t.Errorf("invalid: %+v touched=%v", v, touched)
	}
	// store error: refused
	boom := goCBeaconKV{func(string, func([]byte) []byte) error { return errors.New("boom") }}
	if v := acc(boom, goCSignBeacon(t, kp, nil)); v.OK || v.Reason != "beacon state unavailable" {
		t.Errorf("store error: %+v", v)
	}
	// store panic: refused
	pan := goCBeaconKV{func(string, func([]byte) []byte) error { panic("boom") }}
	if v := acc(pan, goCSignBeacon(t, kp, nil)); v.OK || v.Reason != "beacon state unavailable" {
		t.Errorf("store panic: %+v", v)
	}
	// a store that never calls back decides nothing and records nothing
	if v := acc(spy, goCSignBeacon(t, kp, nil)); !v.OK {
		t.Errorf("no callback: %+v", v)
	}
	// stored values: each shape of prev
	for _, c := range []struct {
		name, prev string
		seq        int
		want       string
	}{
		{"canonical lower", "10", 11, ""},
		{"zero", "0", 1, ""},
		{"zero replayed", "0", 0, "replayed beacon: seq 0 <= 0"},
		{"negative", "-1", 5, "beacon state unavailable"},
		{"letters", "abc", 5, "beacon state unavailable"},
		{"leading zeros", "007", 9, "beacon state unavailable"},
		{"range overflow", "99999999999999999999", 5, "beacon state unavailable"},
		{"above safe", "9007199254740992", 5, "beacon state unavailable"},
		{"max replay", "9007199254740991", 9007199254740991, "replayed beacon: seq 9007199254740991 <= 9007199254740991"},
	} {
		kv := NewMemoryAtomicKV()
		b := goCSignBeacon(t, kp, map[string]any{"seq": c.seq})
		_ = kv.Update(beaconSeqKey(b), func([]byte) []byte { return []byte(c.prev) })
		v := acc(kv, b)
		if c.want == "" && !v.OK || c.want != "" && (v.OK || v.Reason != c.want) {
			t.Errorf("%s: %+v", c.name, v)
		}
	}
	// the stored seq is its decimal form
	kv := NewMemoryAtomicKV()
	b := goCSignBeacon(t, kp, map[string]any{"seq": 10})
	if v := acc(kv, b); !v.OK {
		t.Fatalf("seq 10: %+v", v)
	}
	if got, _, _ := kv.Get(beaconSeqKey(b)); string(got) != "10" {
		t.Errorf("stored %q", got)
	}
	// a retried callback starts from a clean slate each time
	retry := func(first []byte) BeaconVerdict {
		return acc(goCBeaconKV{func(_ string, fn func([]byte) []byte) error {
			fn(first)
			fn(nil)
			return nil
		}}, goCSignBeacon(t, kp, nil))
	}
	if v := retry([]byte("5")); !v.OK {
		t.Errorf("replay flag leaked across a retry: %+v", v)
	}
	if v := retry([]byte("abc")); !v.OK {
		t.Errorf("junk flag leaked across a retry: %+v", v)
	}
}
