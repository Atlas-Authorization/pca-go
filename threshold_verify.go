package pca

import (
	"errors"
	"strings"
)

// The t-of-n multi-signature verifier (the reference's verifyThreshold) and the threshold hook built on it (createThresholdVerifier).
// The signer set is validated first and the whole verification fails closed if it is malformed: every role is a known role, each role
// has EXACTLY ONE registered key, no public key is registered under two roles. A share counts iff its role and key are registered and
// its signature verifies over that role's signer-set- and t-bound share message (ShareMessage); the count is of DISTINCT keys, which
// are distinct roles. Deterministic and TOTAL: never panics.

// ThresholdVerdict is the outcome of VerifyThreshold: the number of DISTINCT valid keys (== distinct roles), those roles in
// first-seen order, and, when not ok, the first reason.
type ThresholdVerdict struct {
	OK    bool
	Count int
	Roles []string
	// Reason is "" when OK.
	Reason string
}

// AgentLeafBaseline is the PCActn LEAF signature admitted as the agent's "effective t=1" share: the leaf signature over the BARE
// message verified under the agent's suite. It counts only when Holder equals the signer set's registered 'agent' key and that key is
// not already satisfied by an explicit (bound) share. The leaf's PQ key must be the one the signer set registers for the agent or the
// one the leaf's holder_pq commits to; the unbound-PQ opt-out of the reference is not offered.
type AgentLeafBaseline struct {
	// Holder is the capability-chain leaf holder (b64u Ed25519); a non-string never counts.
	Holder any
	Sig    any
	// Alg is the PCActn's suite; AlgPresent false is Ed25519.
	Alg        any
	AlgPresent bool
	PqPk       any
	PqSig      any
	// HolderPq is the leaf capability's holder_pq commitment; HasHolderPq false is none.
	HolderPq    string
	HasHolderPq bool
}

var thresholdRoleNames = []string{"agent", "guardian", "principal"}

func thresholdAsRole(v any) string {
	if s, ok := v.(string); ok && signerRoles[s] {
		return s
	}
	return ""
}

func thresholdIsPqPkOfSomeSuite(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	b, ok := DecodeB64uStrict(s, -1)
	return ok && pqPkLengths[len(b)]
}

func thresholdSuiteHasPq(alg any, present bool) bool {
	su, ok := resolveSigAlg(alg, present)
	return ok && su.needsPqPk
}

// thresholdShow is the reference's showValue: primitives as String(v), containers by kind only.
func thresholdShow(v any) string {
	switch v.(type) {
	case []any:
		return "<array>"
	case map[string]any:
		return "<object>"
	}
	return jsValueString(v)
}

type thresholdSigner struct {
	role        string // "" == an unknown role
	keyOk, pqOk bool
	key         string
	pq          string
	hasPq       bool
}

// VerifyThreshold verifies a t-of-n multi-signature over message (= ThresholdMessage of the PCActn). sig is {shares: [...]}; a
// value that is not such an object has no shares. t must be exactly 1, 2 or 3. baseline (nil: none) admits the PCActn leaf
// signature as the agent's effective-t=1 share.
func VerifyThreshold(sig any, message []byte, signerSet []any, t any, baseline *AgentLeafBaseline) (v ThresholdVerdict) {
	defer func() {
		if recover() != nil {
			v = ThresholdVerdict{Reason: "threshold verification error (fail closed)", Roles: []string{}}
		}
	}()
	// ---- the signer set: facts per entry
	pqOfRole := map[string]string{}
	hasPqOfRole := map[string]bool{}
	seenPq := map[string]string{}
	seenHasPq := map[string]bool{}
	seenHas := map[string]bool{}
	signers := make([]thresholdSigner, len(signerSet))
	for i, e := range signerSet {
		o, isMap := e.(map[string]any)
		s := thresholdSigner{pqOk: true}
		if !isMap { // no members to read: no role, no key
			signers[i] = s
			continue
		}
		s.role = thresholdAsRole(o["role"])
		pk, pkIsStr := o["publicKey"].(string)
		if _, ok := DecodeB64uStrict(pk, 32); pkIsStr && ok {
			s.keyOk = true
		}
		s.key = pk
		pv, hasPq := o["pq_pk"]
		s.pqOk = !hasPq || thresholdIsPqPkOfSomeSuite(pv)
		if ps, isStr := pv.(string); isStr {
			s.pq, s.hasPq = ps, true
		}
		if s.role != "" && s.keyOk && s.pqOk {
			// a duplicate (role, key) entry is harmless only if it registers the SAME pq_pk (or none on both)
			id := s.role + "\x00" + pk
			if seenHas[id] {
				if seenHasPq[id] != s.hasPq || seenPq[id] != s.pq {
					s.pqOk = false
				}
			} else {
				seenHas[id], seenPq[id], seenHasPq[id] = true, s.pq, s.hasPq
			}
		}
		if s.role != "" && s.keyOk && s.pqOk {
			if _, seenRole := pqOfRole[s.role]; !seenRole { // the first registration of a role fixes its PQ key
				pqOfRole[s.role] = s.pq
				hasPqOfRole[s.role] = s.hasPq
			}
		}
		signers[i] = s
	}
	registeredPq := func(role string) (string, bool) { return pqOfRole[role], hasPqOfRole[role] }

	tValid := false
	tInt := 0
	if f, ok := jsNum(t); ok && jsIsSafeInteger(t) && (f == 1 || f == 2 || f == 3) {
		tValid, tInt = true, int(f)
	}
	fail := func(reason string, count int, roles []string) ThresholdVerdict {
		if roles == nil {
			roles = []string{}
		}
		return ThresholdVerdict{Count: count, Roles: roles, Reason: reason}
	}
	if !tValid {
		return fail("invalid threshold t="+thresholdShow(t)+" (must be 1, 2 or 3)", 0, nil)
	}

	// ---- BuildReg: one key per role, one role per key
	type regEntry struct{ role, key string }
	var reg []regEntry
	lookupKey := func(role string) (string, bool) {
		for _, r := range reg {
			if r.role == role {
				return r.key, true
			}
		}
		return "", false
	}
	lookupRole := func(key string) (string, bool) {
		for _, r := range reg {
			if r.key == key {
				return r.role, true
			}
		}
		return "", false
	}
	for i, s := range signers {
		if s.role == "" || !s.keyOk {
			return fail("malformed signer set", 0, nil)
		}
		if !s.pqOk {
			return fail("malformed signer set (pq_pk)", 0, nil)
		}
		prevKey, hasKey := lookupKey(s.role)
		if hasKey && prevKey != s.key {
			role := thresholdShow(nil)
			if o, ok := signerSet[i].(map[string]any); ok {
				role = thresholdShow(o["role"])
			}
			return fail("signer set registers more than one key for role "+role, 0, nil)
		}
		if prevRole, hasRole := lookupRole(s.key); hasRole && prevRole != s.role {
			return fail("signer set registers one key under two roles", 0, nil)
		}
		if !hasKey {
			reg = append(reg, regEntry{s.role, s.key})
		}
	}

	// ---- the shares
	var rawShares []any
	if sm, ok := sig.(map[string]any); ok {
		rawShares, _ = sm["shares"].([]any)
	}
	var keys, roles []string
	has := func(k string) bool {
		for _, x := range keys {
			if x == k {
				return true
			}
		}
		return false
	}
	reason := ""
	first := func(r string) {
		if reason == "" {
			reason = r
		}
	}
	for _, rs := range rawShares {
		sh, isMap := rs.(map[string]any)
		roleStr, roleIsStr := sh["role"].(string)
		key, keyIsStr := sh["publicKey"].(string)
		if !isMap || !roleIsStr || !keyIsStr {
			first("malformed share")
			continue
		}
		if has(key) {
			continue
		}
		role := thresholdAsRole(roleStr)
		rk, found := "", false
		if role != "" {
			rk, found = lookupKey(role)
		}
		show := thresholdShow(roleStr)
		if !found {
			first("role " + show + " is not in the signer set")
			continue
		}
		if rk != key {
			first("share for role " + show + " uses a key not registered for that role")
			continue
		}
		algV, algPresent := sh["alg"]
		suite, known := resolveSigAlg(algV, algPresent)
		if !known {
			first("share for role " + show + " declares an unknown signature alg")
			continue
		}
		regPq, hasRegPq := registeredPq(role)
		if pv, named := sh["pq_pk"]; named {
			if ps, isStr := pv.(string); !isStr || !hasRegPq || ps != regPq {
				first("share for role " + show + " names a pq_pk that is not the key its role registers")
				continue
			}
		}
		sigOk := func() bool {
			// a role that registers a pq_pk MUST be satisfied by a PQ (pure or hybrid) share
			if hasRegPq && !suite.needsPqPk {
				return false
			}
			pqKey := callerVouchedPqKey(nil)
			algName := "ed25519"
			if suite.alg != "ed25519" {
				if !hasRegPq {
					return false
				}
				pqKey = callerVouchedPqKey(regPq)
				algName = suite.alg
			}
			signed, err := ShareMessage(roleStr, message, signerSet, tInt, algName)
			if err != nil {
				return false
			}
			return verifyLeafSuite(algV, algPresent, key, pqKey, signed, sh["sig"], sh["pq_sig"])
		}
		if !sigOk() {
			first("invalid signature for role " + show)
			continue
		}
		keys = append(keys, key)
		roles = append(roles, role)
	}

	// ---- the agent-leaf baseline (effective t=1)
	if baseline != nil {
		if holder, isStr := baseline.Holder.(string); isStr {
			if agentKey, ok := lookupKey("agent"); ok && holder == agentKey && !has(agentKey) {
				regPq, hasRegPq := registeredPq("agent")
				pqKeyOk := hasRegPq
				if !pqKeyOk {
					var committed *string
					if baseline.HasHolderPq {
						c := baseline.HolderPq
						committed = &c
					}
					pqKeyOk = PqBindingError(baseline.Alg, baseline.AlgPresent, baseline.PqPk, committed, "threshold baseline") == ""
				}
				if pqKeyOk && thresholdBaselineSigOk(baseline, agentKey, regPq, hasRegPq, message) {
					keys = append(keys, agentKey)
					roles = append(roles, "agent")
				}
			}
		}
	}
	if len(keys) >= tInt {
		return ThresholdVerdict{OK: true, Count: len(keys), Roles: append([]string{}, roles...)}
	}
	if reason == "" {
		reason = "only " + jsNumberString(float64(len(keys))) + " distinct valid key(s), need " + thresholdShow(t)
	}
	return fail(reason, len(keys), roles)
}

func thresholdBaselineSigOk(b *AgentLeafBaseline, agentKey, regPq string, hasRegPq bool, message []byte) bool {
	// the same rule for the leaf baseline: an agent with a registered pq_pk needs a PQ / hybrid leaf
	if hasRegPq && !thresholdSuiteHasPq(b.Alg, b.AlgPresent) {
		return false
	}
	var key pqVerifyKey
	if hasRegPq {
		key = callerVouchedPqKey(regPq)
	} else {
		var bound bool
		hq := any(nil)
		if b.HasHolderPq {
			hq = b.HolderPq
		}
		key, bound = resolvePqVerifyKey(b.Alg, b.AlgPresent, b.PqPk, pqAuthority{holderPq: hq, hasHolderPq: b.HasHolderPq})
		if !bound {
			return false
		}
	}
	return verifyLeafSuite(b.Alg, b.AlgPresent, agentKey, key, message, b.Sig, b.PqSig)
}

// ThresholdVerifierResult is what the threshold hook reports: always enforced, whether it passed, why not, and the t it enforced.
type ThresholdVerifierResult struct {
	Enforced bool
	OK       bool
	Reason   string
	T        int
}

// ThresholdVerifierOpts configures CreateThresholdVerifier.
type ThresholdVerifierOpts struct {
	// SignerSet is the roles and public keys permitted to co-sign ({role, publicKey, pq_pk?} objects). It MUST register the agent
	// role's key = the leaf.
	SignerSet []any
	// T is the fixed required threshold, decided by the SERVER (nil: RequiredT must be given). There is deliberately NO default
	// derived from the PCActn's risk_claim.r: that value is the AGENT's own claim.
	T *int
	// RequiredT derives the required t from SERVER-HELD data only (it takes precedence over T). It must never read
	// pcactn["risk_claim"]; the guard also refuses a hook whose enforced t is below the server's own decision.
	RequiredT func(pcactn, grant map[string]any) int
	// Scheme labels how the co-signers' keys are held (assurance): "multisig" (default), or "frost", "frost_dkg", "mpc" when a
	// signer-set key is a FROST group key or an MPC key. Those schemes are reported as awaiting audit.
	Scheme string
}

// ThresholdVerifier is the threshold hook: it recomputes the canonical signed message, verifies the explicit shares carried in the
// PCActn's `threshold` member and admits the PCActn's own leaf signature as the agent's effective-t=1 baseline, resolves the required
// t and reports the t it enforced. It implements AssuranceLabeler (the scheme).
type ThresholdVerifier struct {
	signerSet []any
	t         *int
	requiredT func(pcactn, grant map[string]any) int
	scheme    string
}

// CreateThresholdVerifier builds the threshold hook. The configuration is copied: later edits by the caller change nothing.
func CreateThresholdVerifier(opts ThresholdVerifierOpts) (*ThresholdVerifier, error) {
	if opts.RequiredT == nil && opts.T == nil {
		return nil, errors.New("createThresholdVerifier: supply `t` or `requiredT` derived from SERVER-held data. The risk_claim.r-derived default was removed (F-1): it is the agent's own claim.")
	}
	set, err := normList(opts.SignerSet)
	if err != nil {
		return nil, err
	}
	v := &ThresholdVerifier{signerSet: set, requiredT: opts.RequiredT, scheme: opts.Scheme}
	if opts.T != nil {
		t := *opts.T
		v.t = &t
	}
	if v.scheme == "" {
		v.scheme = "multisig"
	}
	return v, nil
}

// Assurance is the label of the threshold scheme.
func (v *ThresholdVerifier) Assurance() AssuranceLabel {
	return AssuranceLabel{Level: v.scheme, AwaitingAudit: isAwaitingAuditScheme(v.scheme)}
}

// Verify is the hook body over a PCActn and the verifier's own grant.
func (v *ThresholdVerifier) Verify(pcactn, grant map[string]any) (res ThresholdVerifierResult) {
	t := 0
	if v.requiredT != nil {
		t = v.requiredT(pcactn, grant)
	} else {
		t = *v.t
	}
	defer func() {
		if recover() != nil {
			res = ThresholdVerifierResult{Enforced: true, Reason: "threshold verification error (fail closed)", T: t}
		}
	}()
	message, err := ThresholdMessage(pcactn)
	if err != nil {
		return ThresholdVerifierResult{Enforced: true, Reason: "threshold message error: " + err.Error(), T: t}
	}
	var explicit []any
	if tm, ok := pcactn["threshold"].(map[string]any); ok {
		explicit, _ = tm["shares"].([]any)
	}
	chain, _ := pcactn["cap_chain"].([]any)
	var baseline *AgentLeafBaseline
	if len(chain) > 0 {
		leaf, _ := chain[len(chain)-1].(map[string]any)
		_, holderIsStr := leaf["holder"].(string)
		_, sigIsStr := pcactn["sig"].(string)
		if holderIsStr && sigIsStr {
			baseline = &AgentLeafBaseline{Holder: leaf["holder"], Sig: pcactn["sig"], PqPk: pcactn["pq_pk"], PqSig: pcactn["pq_sig"]}
			baseline.Alg, baseline.AlgPresent = pcactn["alg"]
			if hq, ok := leaf["holder_pq"].(string); ok {
				baseline.HolderPq, baseline.HasHolderPq = hq, true
			}
		}
	}
	verdict := VerifyThreshold(map[string]any{"shares": explicit}, message, v.signerSet, jsNumber(float64(t)), baseline)
	if verdict.OK {
		return ThresholdVerifierResult{Enforced: true, OK: true, T: t}
	}
	reason := verdict.Reason
	if strings.TrimSpace(reason) == "" {
		reason = "threshold not met"
	}
	return ThresholdVerifierResult{Enforced: true, Reason: reason, T: t}
}

// Hook is Verify as the guard's ThresholdHook (the reason is not carried by that type).
func (v *ThresholdVerifier) Hook() ThresholdHook {
	return func(pcactn, grant map[string]any) ThresholdResult {
		r := v.Verify(pcactn, grant)
		return ThresholdResult{OK: r.OK, Enforced: r.Enforced, T: r.T}
	}
}
