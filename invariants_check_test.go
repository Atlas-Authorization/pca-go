package pca

import "testing"

func TestCheckInvariantsSmoke(t *testing.T) {
	res, err := CheckInvariants(5, InvariantsDefaultSeed, false)
	if err != nil || len(res) != len(InvariantNames) {
		t.Fatalf("err=%v n=%d", err, len(res))
	}
	for i, r := range res {
		if r.Name != InvariantNames[i] || !r.OK {
			t.Errorf("%s: ok=%v %s", r.Name, r.OK, r.Error)
		}
	}
	if _, err := CheckInvariants(-1, 1, false); err == nil {
		t.Error("negative runs accepted")
	}
}
