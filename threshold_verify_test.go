package pca

import (
	"strings"
	"testing"
)

func thSeedKey(t *testing.T, b byte) *KeyPair {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	k, err := KeyPairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestVerifyThresholdCountsDistinctRolesOverTheBoundShareMessage(t *testing.T) {
	a, g, p := thSeedKey(t, 1), thSeedKey(t, 2), thSeedKey(t, 3)
	set := []any{map[string]any{"role": "agent", "publicKey": a.Public}, map[string]any{"role": "guardian", "publicKey": g.Public}, map[string]any{"role": "principal", "publicKey": p.Public}}
	msg := []byte("the threshold message")
	share := func(role string, k *KeyPair, tt int) map[string]any {
		s, err := SignThresholdShare(role, k, msg, set, tt, nil)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	two := map[string]any{"shares": []any{share("agent", a, 2), share("guardian", g, 2)}}
	if v := VerifyThreshold(two, msg, set, jsNumber(2), nil); !v.OK || v.Count != 2 || strings.Join(v.Roles, ",") != "agent,guardian" {
		t.Fatalf("t=2: %+v", v)
	}
	if v := VerifyThreshold(two, msg, set, jsNumber(3), nil); v.OK || v.Reason != "only 0 distinct valid key(s), need 3" && v.Reason != "invalid signature for role agent" {
		t.Fatalf("shares bound to t=2 must not satisfy t=3: %+v", v)
	}
	three := map[string]any{"shares": []any{share("agent", a, 3), share("guardian", g, 3)}}
	if v := VerifyThreshold(three, msg, set, jsNumber(3), nil); v.OK || v.Count != 2 || v.Reason != "only 2 distinct valid key(s), need 3" {
		t.Fatalf("two of three: %+v", v)
	}
	three["shares"] = append(three["shares"].([]any), share("principal", p, 3), share("principal", p, 3)) // a duplicate counts once
	if v := VerifyThreshold(three, msg, set, jsNumber(3), nil); !v.OK || v.Count != 3 {
		t.Fatalf("three of three: %+v", v)
	}
	// a bare agent share (over the message itself) is not a bound share
	bare, err := SignPreparedShare("agent", a, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := VerifyThreshold(map[string]any{"shares": []any{bare}}, msg, set, jsNumber(1), nil); v.OK || v.Reason != "invalid signature for role agent" {
		t.Fatalf("bare agent share: %+v", v)
	}
	if v := VerifyThreshold(two, msg, set, jsNumber(4), nil); v.OK || v.Reason != "invalid threshold t=4 (must be 1, 2 or 3)" {
		t.Fatalf("t=4: %+v", v)
	}
	// a key registered under two roles voids the whole set
	bad := []any{map[string]any{"role": "agent", "publicKey": a.Public}, map[string]any{"role": "guardian", "publicKey": a.Public}}
	if v := VerifyThreshold(two, msg, bad, jsNumber(1), nil); v.OK || v.Reason != "signer set registers one key under two roles" {
		t.Fatalf("one key two roles: %+v", v)
	}
	// a share signed by a key the set does not register for the role
	other := thSeedKey(t, 9)
	forged, err := SignThresholdShare("guardian", other, msg, set, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v := VerifyThreshold(map[string]any{"shares": []any{forged}}, msg, set, jsNumber(2), nil); v.OK || v.Reason != "share for role guardian uses a key not registered for that role" {
		t.Fatalf("unregistered key: %+v", v)
	}
	if v := VerifyThreshold(nil, msg, set, jsNumber(1), nil); v.OK || v.Reason != "only 0 distinct valid key(s), need 1" {
		t.Fatalf("no shares: %+v", v)
	}
}

func TestCreateThresholdVerifierNeedsAServerThreshold(t *testing.T) {
	if _, err := CreateThresholdVerifier(ThresholdVerifierOpts{SignerSet: []any{}}); err == nil || !strings.Contains(err.Error(), "createThresholdVerifier") {
		t.Fatalf("a verifier without a server t: %v", err)
	}
	two := 2
	v, err := CreateThresholdVerifier(ThresholdVerifierOpts{SignerSet: []any{}, T: &two, Scheme: "frost"})
	if err != nil {
		t.Fatal(err)
	}
	if l := v.Assurance(); l.Level != "frost" || !l.AwaitingAudit {
		t.Fatalf("label %+v", l)
	}
	// a PCActn with no usable leaf and no shares is refused, reporting the t it enforced
	if r := v.Verify(map[string]any{}, map[string]any{}); !r.Enforced || r.OK || r.T != 2 {
		t.Fatalf("result %+v", r)
	}
}
