package pca

import "time"

// CreateRevocationChecker (the reference createRevocationChecker): a revocation hook backed by non-membership proofs. Fails closed: a
// missing root, a missing proof, or a revoked id (which has no valid proof) all refuse. The decision itself is RevocationGate;
// this is the factory a verifier configures once.

// RevocationCheckContext is what one check is made for: the verified PCActn and, when known, the verifier clock (epoch ms).
type RevocationCheckContext struct {
	PCActn   map[string]any
	NowEpoch *int64
}

// RevocationCheckResult is the hook's answer: Enforced is always true; OK false carries the Reason.
type RevocationCheckResult struct {
	Enforced bool
	OK       bool
	Reason   string
}

// RevocationChecker is the revocation hook a verifier calls for every PCActn.
type RevocationChecker func(ctx RevocationCheckContext) RevocationCheckResult

// RevocationCheckerOptions configures CreateRevocationChecker.
type RevocationCheckerOptions struct {
	// Policy is the staleness policy (zero value: none).
	Policy RevocationStalenessPolicy
	// Root is the trusted current revocation root for this verification. With Epoch set it is optional: the signed epoch's root
	// is used (and must equal this one if both are given).
	Root func(ctx RevocationCheckContext) string
	// Epoch returns the guardian-signed revocation epoch for this verification. When set, the checker REQUIRES it to verify
	// (signature, grant binding, now <= not_after, not older than LastAcceptedEpoch, and the PCActn's signed freshness.epoch >=
	// epoch) and checks non-membership against ITS root, closing the circular-freshness gap.
	Epoch          func(ctx RevocationCheckContext) map[string]any
	GuardianPublic string
	// PqPins are the PQ-key pins of the epoch guardian; required for a pure-PQ or hybrid epoch.
	PqPins map[string]string
	// LastAcceptedEpoch is the newest epoch number already accepted for this grant (the verifier-side monotonic pin).
	LastAcceptedEpoch func(ctx RevocationCheckContext) *float64
	// OnEpochAccepted is called with an epoch that passed every check (persist it as the new pin).
	OnEpochAccepted func(ep map[string]any, ctx RevocationCheckContext)
	// ProofFor supplies the non-membership proof for a capability id (nil: none, denied).
	ProofFor func(id string, ctx RevocationCheckContext) any
	// Ids chooses which capability ids to check. Default: every id in the PCActn's cap_chain (a revoked ancestor kills its descendants).
	Ids func(ctx RevocationCheckContext) []string
	// RootIssuedAt is, with a staleness policy and no signed epoch, when your trusted source issued the bare root (nil: unknown, denied).
	RootIssuedAt func(ctx RevocationCheckContext) *float64
	// ReversibilityClass is your authoritative class for the action; the PCActn's signed class can only make it stricter.
	ReversibilityClass func(ctx RevocationCheckContext) string
}

// CreateRevocationChecker validates the staleness policy and returns the hook. The configuration is copied: later edits by the
// caller do not change what this verifier enforces.
func CreateRevocationChecker(opts RevocationCheckerOptions) (RevocationChecker, error) {
	if err := opts.Policy.Validate(); err != nil {
		return nil, err
	}
	return func(ctx RevocationCheckContext) RevocationCheckResult {
		now := float64(time.Now().UnixMilli())
		if ctx.NowEpoch != nil {
			now = float64(*ctx.NowEpoch)
		}
		p := ctx.PCActn
		in := RevocationGateInput{Policy: opts.Policy, GuardianPublic: opts.GuardianPublic, Pins: opts.PqPins, Now: now, EpochSource: opts.Epoch != nil}
		in.GrantRef, _ = p["grant_ref"].(string)
		action, _ := p["action"].(map[string]any)
		in.SignedClass = action["reversibility_class"]
		if fr, ok := p["freshness"].(map[string]any); ok {
			if e, ok := jsNum(fr["epoch"]); ok {
				in.PCActnEpoch = &e
			}
		}
		if opts.Root != nil {
			in.Root = opts.Root(ctx)
		}
		if opts.ReversibilityClass != nil {
			in.ServerClass = opts.ReversibilityClass(ctx)
		}
		var accepted map[string]any
		if opts.Epoch != nil {
			if ep := opts.Epoch(ctx); ep != nil {
				in.Epoch, accepted = ep, ep
			}
			if opts.LastAcceptedEpoch != nil {
				in.LastAcceptedEpoch = opts.LastAcceptedEpoch(ctx)
			}
		} else if opts.RootIssuedAt != nil {
			in.RootIssuedAt = opts.RootIssuedAt(ctx)
		}
		if opts.Ids != nil {
			in.Ids = opts.Ids(ctx)
		} else if chain, ok := p["cap_chain"].([]any); ok {
			for _, c := range chain {
				id, _ := c.(map[string]any)["id"].(string)
				in.Ids = append(in.Ids, id)
			}
		}
		in.Proof = func(id string) any {
			if opts.ProofFor == nil {
				return nil
			}
			return opts.ProofFor(id, ctx)
		}
		r := RevocationGate(in)
		if !r.OK {
			return RevocationCheckResult{Enforced: true, Reason: r.Reason}
		}
		if accepted != nil && opts.OnEpochAccepted != nil {
			opts.OnEpochAccepted(accepted, ctx)
		}
		return RevocationCheckResult{Enforced: true, OK: true}
	}, nil
}

// EnvelopeCaveatEvaluator is the stock caveat evaluator (the reference envelopeCaveatEvaluator): it understands only the envelope
// caveats expires, not_before, rate, max_blast_radius, reversibility_max, delegation_depth, budget_alloc and the intent-session
// binding, and fails closed on anything else (predicates, tool_schema and max_spend need AgentNativeCaveatEvaluator). ctx is the
// caveat context {now, recentActionTimes, blastRadius, reversibilityClass, delegationDepth}. Total.
func EnvelopeCaveatEvaluator(caveat any, ctx any) bool {
	cv, ok := caveat.(map[string]any)
	if !ok {
		return false
	}
	switch cv["type"] {
	case CaveatPredicates, CaveatToolSchema, CaveatMaxSpend:
		return false
	}
	return AgentNativeCaveatEvaluator(caveat, ctx)
}
