package pca

import "testing"

// operations.ts: `r.status !== 403 || failed.length !== 1 || failed[0] !== 'replay'` is a plain denial. A replay with a second failing
// check is never answered from the record. Go's loop leaves whichever failure the map yields last, so a check that lets "more than one
// failure" through reaches the record only on some iterations: run it often enough that every order occurs.
func TestK05Kill4Y2ExecutorReplayWithAnotherFailureIsDenied(t *testing.T) {
	defer func() { authorizeCoreHook = nil }()
	ex, store, p, op, fn := x5Executed(t) // a record exists and the counter is spent
	authorizeCoreHook = func(core *Verdict) {
		core.Checks["y2other"] = false
		core.Allow, core.Reasons = false, []string{"y2other: no"}
	}
	for i := 0; i < 256; i++ {
		o := ex.Run(p, op, fn)
		if o.Status != "denied" || o.Replayed || o.Authorization == nil || o.Authorization.Status != 403 ||
			o.Authorization.Checks["y2other"] != "fail" || o.Authorization.Checks["replay"] != "fail" || store.gets != 0 {
			t.Fatalf("run %d: %+v gets=%d", i, o, store.gets)
		}
	}
}
