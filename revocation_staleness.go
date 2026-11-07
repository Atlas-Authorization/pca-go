package pca

// Revocation staleness (T9): a verifier-side cap on how old the revocation state may be, per reversibility class, the
// guardian-signed revocation epoch (Ed25519 and every suite this build implements, under the pin rules of the ledger
// verifiers), and the gate that combines them. Mirrors the reference revocation module (checkRevocationAge,
// revocationMaxAgeMs, effectiveReversibility, checkRevocationEpoch and the staleness branch of the revocation checker).
// Inputs are parsed JSON values; nothing here panics on a hostile epoch.

import (
	"crypto/ed25519"
	"fmt"
	"math"
)

const (
	// RevocationEpochRefreshMs: the server re-signs the epoch at least this often.
	RevocationEpochRefreshMs = 60_000
	// RevocationEpochValidityMs: how long a signed epoch is acceptable (longer than the refresh period).
	RevocationEpochValidityMs = 5 * 60_000
	// RevocationIrreversibleMaxAgeMs: the default maximum age of revocation state for an irreversible action (two refreshes).
	RevocationIrreversibleMaxAgeMs = 2 * RevocationEpochRefreshMs
	revSkewMs                      = 60_000
)

// StalenessWindows are the per-class maximum ages (ms); nil keeps the default. Each is capped by MaxRevocationAgeMs.
type StalenessWindows struct {
	Irreversible *float64
	Costly       *float64
}

// RevocationStalenessPolicy is the verifier-side staleness policy. It is ON when MaxRevocationAgeMs or Staleness is set
// (see On); the zero value changes nothing. The class is the stricter of the server's authoritative class and the
// PCActn's signed class; a missing or unknown class counts as irreversible.
type RevocationStalenessPolicy struct {
	// MaxRevocationAgeMs: maximum age for any action (nil: RevocationEpochValidityMs).
	MaxRevocationAgeMs *float64
	// Staleness: per-class windows (irreversible default 2 min; costly and rate_limited default MaxRevocationAgeMs).
	Staleness *StalenessWindows
	// AllowUnsignedRootForIrreversible accepts revocation state that is not guardian-signed for an irreversible action.
	AllowUnsignedRootForIrreversible bool
}

// On reports whether the policy turns the staleness check on.
func (p RevocationStalenessPolicy) On() bool {
	return p.MaxRevocationAgeMs != nil || p.Staleness != nil
}

// Validate: every window that is set must be a finite positive number of milliseconds (a configuration error).
func (p RevocationStalenessPolicy) Validate() error {
	chk := func(name string, v *float64) error {
		if v != nil && !(!math.IsNaN(*v) && !math.IsInf(*v, 0) && *v > 0) {
			return fmt.Errorf("%s must be a positive number of milliseconds", name)
		}
		return nil
	}
	if err := chk("maxRevocationAgeMs", p.MaxRevocationAgeMs); err != nil {
		return err
	}
	if p.Staleness != nil {
		if err := chk("staleness.irreversible", p.Staleness.Irreversible); err != nil {
			return err
		}
		return chk("staleness.costly", p.Staleness.Costly)
	}
	return nil
}

// RevocationStalenessPolicyFromJSON reads {maxRevocationAgeMs?, staleness?: {irreversible?, costly?},
// allowUnsignedRootForIrreversible?} from parsed JSON. A set value that is not a number becomes NaN (Validate refuses it).
func RevocationStalenessPolicyFromJSON(v any) RevocationStalenessPolicy {
	m, _ := v.(map[string]any)
	num := func(m map[string]any, k string) *float64 {
		x, has := m[k]
		if !has {
			return nil
		}
		f, ok := jsNum(x)
		if !ok {
			f = math.NaN()
		}
		return &f
	}
	p := RevocationStalenessPolicy{MaxRevocationAgeMs: num(m, "maxRevocationAgeMs")}
	p.AllowUnsignedRootForIrreversible, _ = m["allowUnsignedRootForIrreversible"].(bool)
	if s, has := m["staleness"]; has {
		sm, _ := s.(map[string]any)
		rl := num(sm, "rate_limited") // "costly" is the old name of "rate_limited"
		if rl == nil {
			rl = num(sm, "costly")
		}
		p.Staleness = &StalenessWindows{Irreversible: num(sm, "irreversible"), Costly: rl}
	}
	return p
}

// EffectiveReversibility is the stricter of the server's class ("" = none) and the signed one: "reversible", "rate_limited" or
// "irreversible". Shared class table: reversible 0, rate_limited 1, costly 1, irreversible 2; unknown or missing = 2.
func EffectiveReversibility(serverClass string, signedClass any) string {
	rank := reversibilityRank(signedClass)
	if serverClass != "" {
		if r := reversibilityRank(serverClass); r > rank {
			rank = r
		}
	}
	switch {
	case rank >= 2:
		return "irreversible"
	case rank == 1:
		return "rate_limited"
	}
	return "reversible"
}

// RevocationMaxAgeMs is the maximum age of revocation state the policy allows for an action of class cls.
func RevocationMaxAgeMs(p RevocationStalenessPolicy, cls string) float64 {
	max := float64(RevocationEpochValidityMs)
	if p.MaxRevocationAgeMs != nil {
		max = *p.MaxRevocationAgeMs
	}
	pick := func(w *float64, def float64) float64 {
		if w != nil {
			def = *w
		}
		return math.Min(max, def) // NaN anywhere stays NaN, so the age check then fails closed
	}
	var irr, costly *float64
	if p.Staleness != nil {
		irr, costly = p.Staleness.Irreversible, p.Staleness.Costly
	}
	switch cls {
	case "irreversible":
		return pick(irr, RevocationIrreversibleMaxAgeMs)
	case "costly", "rate_limited":
		return pick(costly, max)
	}
	return max
}

// RevocationAgeResult is the answer of CheckRevocationAge and CheckRevocationEpoch.
type RevocationAgeResult struct {
	OK     bool
	Reason string
}

func revFail(reason string) RevocationAgeResult { return RevocationAgeResult{Reason: reason} }

// CheckRevocationAge checks revocation state issued at issuedAt (nil or non-finite: unknown, denied). `what` names the
// state in the reason ("" = "revocation state"). A time more than 60 s in the future denies.
func CheckRevocationAge(issuedAt *float64, now, maxAgeMs float64, what string) RevocationAgeResult {
	if what == "" {
		what = "revocation state"
	}
	if issuedAt == nil || math.IsNaN(*issuedAt) || math.IsInf(*issuedAt, 0) {
		return revFail(what + " age is unknown (unverifiable revocation state)")
	}
	if !(*issuedAt <= now+revSkewMs) {
		return revFail(what + " issued in the future")
	}
	if !(now-*issuedAt <= maxAgeMs) {
		return revFail(fmt.Sprintf("%s is %s ms old, over the verifier's maximum of %s ms (stale revocation state)",
			what, jsNumberString(now-*issuedAt), jsNumberString(maxAgeMs)))
	}
	return RevocationAgeResult{OK: true}
}

// EpochCheckOptions configures CheckRevocationEpoch.
type EpochCheckOptions struct {
	// GuardianPublic is the pinned Ed25519 identity (b64u) of the guardian.
	GuardianPublic string
	// Pins pins the post-quantum key of a PQ or hybrid guardian: {Ed25519 b64u: ML-DSA public key b64u}. Without a pin for
	// the guardian such an epoch is refused.
	Pins map[string]string
	// Now is the epoch-ms clock (required: no implicit clock).
	Now float64
	// GrantRef, when non-nil, must equal the epoch's grant_ref.
	GrantRef *string
	// LastAcceptedEpoch: the newest epoch number already accepted for the grant; an older one is a rollback.
	LastAcceptedEpoch *float64
	// PCActnEpoch: the PCActn's signed freshness.epoch; it must be >= the epoch (no pre-revocation action).
	PCActnEpoch *float64
	// MaxAgeMs: verifier-side maximum age (now - issued_at); nil: only the signed not_after bounds it.
	MaxAgeMs *float64
}

var epochBodyKeys = []string{"instance_id", "grant_ref", "epoch", "set_size", "root", "issued_at", "not_after"}

// CheckRevocationEpoch verifies a signed revocation epoch (parsed JSON): the guardian, a suite this build implements,
// shape, signature, grant binding, not_after, issue time, the verifier's age cap, rollback and the PCActn's freshness.
func CheckRevocationEpoch(ep any, o EpochCheckOptions) RevocationAgeResult {
	m, ok := ep.(map[string]any)
	if !ok {
		return revFail("revocation epoch not signed by the pinned guardian")
	}
	algV, hasAlg := m["alg"]
	if g, _ := m["guardian"].(string); g != o.GuardianPublic {
		return revFail("revocation epoch not signed by the pinned guardian")
	}
	if _, known := resolveSigAlg(algV, hasAlg); !known {
		return revFail("revocation epoch not signed by the pinned guardian")
	}
	epoch, e1 := extSafeInt(m["epoch"])
	setSize, e2 := extSafeInt(m["set_size"])
	issued, e3 := extSafeInt(m["issued_at"])
	notAfter, e4 := extSafeInt(m["not_after"])
	if !e1 || epoch < 0 || !e2 || setSize < 0 || !e3 || !e4 {
		return revFail("malformed revocation epoch")
	}
	body, have := extPick(m, epochBodyKeys...)
	if !have {
		return revFail("revocation epoch check error")
	}
	if !extSuiteSigned(o.GuardianPublic, revEpochDomain, body, m, extPins{o.Pins, true}) {
		return revFail("revocation epoch signature invalid")
	}
	if o.GrantRef != nil {
		if g, _ := m["grant_ref"].(string); g != *o.GrantRef {
			return revFail("revocation epoch is for a different grant")
		}
	}
	if !(o.Now <= notAfter) {
		return revFail("revocation epoch expired (stale revocation root)")
	}
	if !(issued <= o.Now+revSkewMs) {
		return revFail("revocation epoch issued in the future")
	}
	if o.MaxAgeMs != nil {
		if r := CheckRevocationAge(&issued, o.Now, *o.MaxAgeMs, "revocation epoch"); !r.OK {
			return r
		}
	}
	if o.LastAcceptedEpoch != nil && epoch < *o.LastAcceptedEpoch {
		return revFail(fmt.Sprintf("revocation epoch %s is older than the last accepted %s (rollback)", jsNumberString(epoch), jsNumberString(*o.LastAcceptedEpoch)))
	}
	if o.PCActnEpoch != nil && !(*o.PCActnEpoch >= epoch) {
		return revFail(fmt.Sprintf("PCActn freshness.epoch %s predates the revocation epoch %s", jsNumberString(*o.PCActnEpoch), jsNumberString(epoch)))
	}
	return RevocationAgeResult{OK: true}
}

// RevocationEpochBody is what a guardian signs.
type RevocationEpochBody struct {
	InstanceID string
	GrantRef   string
	Epoch      int64
	SetSize    int64
	Root       string
	IssuedAt   int64
	NotAfter   int64
}

// SignRevocationEpoch signs an Ed25519 revocation epoch with the guardian's 32-byte seed, in the wire form
// CheckRevocationEpoch verifies (a PQ or hybrid guardian signs with its own tooling).
func SignRevocationEpoch(guardianSeed []byte, b RevocationEpochBody) (map[string]any, error) {
	if len(guardianSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("SignRevocationEpoch: the guardian seed must be %d bytes", ed25519.SeedSize)
	}
	n := func(i int64) any { return jsNumber(float64(i)) }
	body := map[string]any{"instance_id": b.InstanceID, "grant_ref": b.GrantRef, "epoch": n(b.Epoch), "set_size": n(b.SetSize),
		"root": b.Root, "issued_at": n(b.IssuedAt), "not_after": n(b.NotAfter)}
	c, err := canonBytes(body)
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(guardianSeed)
	out := make(map[string]any, len(body)+2)
	for k, v := range body {
		out[k] = v
	}
	out["guardian"] = b64.EncodeToString(priv.Public().(ed25519.PublicKey))
	out["sig"] = b64.EncodeToString(ed25519.Sign(priv, append([]byte(revEpochDomain), c...)))
	return out, nil
}

// RevocationGateInput is one decision of the staleness gate.
type RevocationGateInput struct {
	Policy RevocationStalenessPolicy
	// GuardianPublic / Pins: the epoch guardian (Ed25519 identity and optional PQ pins).
	GuardianPublic string
	Pins           map[string]string
	// GrantRef and PCActnEpoch come from the PCActn (grant_ref, freshness.epoch).
	GrantRef    string
	PCActnEpoch *float64
	Now         float64
	// ServerClass is the authoritative reversibility class ("" = none); SignedClass the PCActn's action.reversibility_class.
	ServerClass string
	SignedClass any
	// EpochSource says a signed epoch is the expected source of revocation state. Epoch is the one presented (nil: none),
	// and LastAcceptedEpoch the verifier's rollback pin.
	EpochSource       bool
	Epoch             any
	LastAcceptedEpoch *float64
	// Root is a bare revocation root (with EpochSource it must equal the signed epoch's root); RootIssuedAt the time your
	// trusted source issued it (nil: unknown, denied under a staleness policy).
	Root         string
	RootIssuedAt *float64
	// Ids are the capability ids that must each have a valid non-membership proof against the root (default for Authorize:
	// every id in the PCActn's cap_chain). Proof returns the parsed proof for an id (nil = none supplied: denied). The check
	// runs when Ids is non-empty or Proof is set.
	Ids   []string
	Proof func(id string) any
}

// RevocationGateResult: OK, or the Reason it was refused. Root is the revocation root the state commits to.
type RevocationGateResult struct {
	OK     bool
	Reason string
	Root   string
}

// RevocationGate decides whether the revocation state is fresh enough: the staleness branch of the reference revocation
// checker, then the non-membership proof of every id in Ids. Fail closed: a missing
// signed epoch, an unverifiable one, a mismatching root or no root at all is a refusal.
func RevocationGate(in RevocationGateInput) RevocationGateResult {
	refuse := func(why string) RevocationGateResult { return RevocationGateResult{Reason: why} }
	if err := in.Policy.Validate(); err != nil {
		return refuse("revocation staleness policy invalid: " + err.Error())
	}
	staleness := in.Policy.On()
	root := in.Root
	var maxAge *float64
	cls := ""
	if staleness {
		cls = EffectiveReversibility(in.ServerClass, in.SignedClass)
		v := RevocationMaxAgeMs(in.Policy, cls)
		maxAge = &v
	}
	if in.EpochSource {
		if in.Epoch == nil || in.GuardianPublic == "" {
			return refuse("no signed revocation epoch")
		}
		chk := CheckRevocationEpoch(in.Epoch, EpochCheckOptions{GuardianPublic: in.GuardianPublic, Pins: in.Pins, Now: in.Now,
			GrantRef: &in.GrantRef, LastAcceptedEpoch: in.LastAcceptedEpoch, PCActnEpoch: in.PCActnEpoch, MaxAgeMs: maxAge})
		if !chk.OK {
			return refuse(chk.Reason)
		}
		epRoot, _ := in.Epoch.(map[string]any)["root"].(string)
		if root != "" && root != epRoot {
			return refuse("revocation root does not match the signed epoch")
		}
		root = epRoot
	} else if staleness {
		if cls == "irreversible" && !in.Policy.AllowUnsignedRootForIrreversible {
			return refuse("unsigned revocation root refused for an irreversible action (needs a guardian-signed epoch)")
		}
		if age := CheckRevocationAge(in.RootIssuedAt, in.Now, *maxAge, "revocation root"); !age.OK {
			return refuse(age.Reason)
		}
	}
	if root == "" {
		return refuse("no revocation root")
	}
	for _, id := range in.Ids {
		var proof any
		if in.Proof != nil {
			proof = in.Proof(id)
		}
		if proof == nil {
			return refuse("no non-membership proof for " + id)
		}
		if !VerifyNonMembership(root, proof, id) {
			return refuse("capability " + id + " is revoked or proof invalid")
		}
	}
	return RevocationGateResult{OK: true, Root: root}
}

// RevocationState is the revocation state an Authorize call holds for a grant: a guardian-signed Epoch (parsed JSON), or a
// bare Root with the time RootIssuedAt it was issued. Both zero: no verifiable state.
type RevocationState struct {
	Epoch             map[string]any
	Root              string
	RootIssuedAt      *float64
	LastAcceptedEpoch *float64
}

// revocationFreshness runs the gate for one Authorize decision (policy on). state may be nil (the source had nothing).
func revocationFreshness(in AuthorizeInput, ctx *AuthorizeContext, p map[string]any, state *RevocationState, now int64) string {
	action, _ := p["action"].(map[string]any)
	g := RevocationGateInput{Policy: *in.RevocationStaleness, GuardianPublic: in.GuardianPublic, Pins: in.GuardianPins,
		Now: float64(now), ServerClass: ctx.ReversibilityClass, SignedClass: action["reversibility_class"]}
	g.GrantRef, _ = p["grant_ref"].(string)
	if fr, ok := p["freshness"].(map[string]any); ok {
		if e, ok := jsNum(fr["epoch"]); ok {
			g.PCActnEpoch = &e
		}
	}
	if state == nil || (state.Epoch == nil && state.Root == "") {
		if EffectiveReversibility(g.ServerClass, g.SignedClass) == "irreversible" && !in.RevocationStaleness.AllowUnsignedRootForIrreversible {
			return "no verifiable (guardian-signed) revocation state for an irreversible action"
		}
		return "no signed revocation epoch"
	}
	// ON by default (0.5): every id (default: the cap_chain ids) needs a valid non-membership proof; no proof source denies
	if in.RevocationProof != nil {
		g.Proof = func(id string) any { return in.RevocationProof(id, p) }
	}
	if in.RevocationIds != nil {
		g.Ids = in.RevocationIds(p)
	} else {
		chain, _ := p["cap_chain"].([]any)
		for _, c := range chain {
			cm, _ := c.(map[string]any)
			id, ok := cm["id"].(string)
			if !ok { // an unreadable id can never have a proof
				return "capability chain entry has no readable id (fail closed)"
			}
			g.Ids = append(g.Ids, id)
		}
	}
	g.LastAcceptedEpoch, g.Root, g.RootIssuedAt = state.LastAcceptedEpoch, state.Root, state.RootIssuedAt
	if state.Epoch != nil {
		g.EpochSource, g.Epoch = true, state.Epoch
	}
	if r := RevocationGate(g); !r.OK {
		return r.Reason
	}
	return ""
}
