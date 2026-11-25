package pca

import (
	"errors"
	"time"
)

// OAGrantVerify is the grant form of a signature-only verifier: the signed Root Intent Grant the proof's capability chain must resolve
// to, plus the core's optional policies (suites, plan roots, freshness, taint, PQ pins). A verifier with neither AuthorizedPlanRoots
// nor InsecureSkipPlanRootCheck refuses every proof (set in Options). Now (epoch ms) is evaluated per call; nil uses the clock.
type OAGrantVerify struct {
	Grant   map[string]any
	Now     func() int64
	Options VerifyOptions
}

// OAGrantVerifier builds the Verify function of OAToolOptions / OAInputGuardrail / OAToolGuard from a grant: each proof is run
// through the core verifier for audience (nil accepts only a proof whose aud is the empty string, i.e. none a real issuer signs).
func OAGrantVerifier(g OAGrantVerify, audience *string) func(map[string]any) (OAVerdict, error) {
	aud := ""
	if audience != nil {
		aud = *audience
	}
	return func(pcactn map[string]any) (OAVerdict, error) {
		if g.Grant == nil {
			reason := "no verifier configured"
			return OAVerdict{Reason: &reason, Checks: map[string]any{}}, nil
		}
		now := time.Now().UnixMilli()
		if g.Now != nil {
			now = g.Now()
		}
		v, err := VerifyPCActnCoreWith(pcactn, g.Grant, now, aud, g.Options)
		if err != nil {
			return OAVerdict{}, errors.New("verify: " + err.Error())
		}
		checks := make(map[string]any, len(v.Checks))
		for k, ok := range v.Checks {
			checks[k] = ok
		}
		out := OAVerdict{Allow: v.Allow, Checks: checks}
		if v.Reason != "" {
			r := v.Reason
			out.Reason = &r
		}
		return out, nil
	}
}
