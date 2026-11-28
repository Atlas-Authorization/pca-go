package pca

import "testing"

// A fault after every core check passed must deny, as the reference's catch turns any throw in the core block into a
// 'malformed' failure: the deferred recover replaces the whole verdict, so allow can never survive it.
func TestCoreLateFaultDenies(t *testing.T) {
	in, pcactn, _ := provGateInput(t)
	if r := Authorize(pcactn, in); !r.Allow {
		t.Fatalf("baseline must allow: %+v", r)
	}
	old := coreFinalFault
	t.Cleanup(func() { coreFinalFault = old })
	coreFinalFault = func() { panic("late fault") }
	in, pcactn, _ = provGateInput(t)
	r := Authorize(pcactn, in)
	if r.Allow || r.Status != 401 || r.Checks["malformed"] != "fail" || r.Checks["wire"] != "fail" || r.Reason != "wire: malformed PCActn: late fault" {
		t.Fatalf("a late core fault: %+v", r)
	}
}

// A revocation hook that panics after the core passed is a revocation failure, never an allow.
func TestRevocationHookFaultDenies(t *testing.T) {
	in, pcactn, _ := provGateInput(t)
	in.IsRevoked = func(_, _ map[string]any) (bool, error) { panic("hook fault") }
	if r := Authorize(pcactn, in); r.Allow || r.Checks["revocation"] != "fail" {
		t.Fatalf("a panicking revocation hook: %+v", r)
	}
}
