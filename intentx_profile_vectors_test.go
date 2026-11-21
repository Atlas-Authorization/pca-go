package pca

// Replays the portable intent profile corpus (shape, signing, verification, succession, scope, standing rules, veto cells).

import "testing"

func TestIntentProfileReferenceVectors(t *testing.T) {
	replayVectorsSeeded(t, "ref-intent-profile.json.gz", map[string]vecFn{
		"signIntentProfile": ixWrap(func(a []any) any { return ixSignIntentProfile(ixM(a[0]), ixS(a[1])) }),
		"intentProfileShapeError": ixWrap(func(a []any) any {
			signed := true
			if o, ok := ixArg(a, 1).(map[string]any); ok && o["signed"] == false {
				signed = false
			}
			if m := ixProfileShapeError(a[0], signed); m != "" {
				return m
			}
			return nil
		}),
		"verifyIntentProfile":     ixWrap(func(a []any) any { return ixVerifyIntentProfile(a[0], ixArg(a, 1)) }),
		"intentProfileDigest":     ixWrap(func(a []any) any { return ixIntentProfileDigest(ixM(a[0])) }),
		"verifyProfileSuccession": ixWrap(func(a []any) any { return ixVerifyProfileSuccession(a[0], a[1]) }),
		"profileApplies":          ixWrap(func(a []any) any { return ixProfileApplies(ixM(a[0]), ixM(a[1])) }),
		"standingAdmits":          ixWrap(func(a []any) any { return ixStandingAdmits(ixM(a[0]), ixM(a[1]), a[2]) }),
		"standingPermits":         ixWrap(func(a []any) any { return ixStandingPermits(ixM(a[0]), ixM(a[1]), a[2]) }),
		"profileVetoCells":        ixWrap(func(a []any) any { return ixProfileVetoCells(ixM(a[0]), ixM(a[1])) }),
		"profileCeiling":          ixWrap(func(a []any) any { return ixProfileCeiling(ixM(a[0]), ixM(a[1]), ixM(a[2]), ixM(a[3])) }),
		"profileUsable": ixWrap(func(a []any) any {
			c := ixM(a[1])
			var pin map[string]string
			if pv, has := c["pin"]; has && pv != nil {
				pin = map[string]string{}
				for k, v := range ixM(ixM(pv)["pqPins"]) {
					pin[k] = ixS(v)
				}
			}
			last, lastP := c["last"]
			return IntentProfileUsable(ixM(a[0]), c["now"], c["maxAgeMs"], c["revocation"], last, lastP, pin)
		}),
	})
}
