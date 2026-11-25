package pca

// The mesh surface beside the verifier and the domain / witness machinery: the public effective authority, the proof size and
// revocation latency models, and the federation primitives (cross-domain capability translation, the federated budget tree,
// cross-reference commitments). Values are JSON shapes (objects as map[string]any, numbers as json.Number), as elsewhere in the
// mesh files. Verifiers never fail with an error: a refusal is {ok: false, reason}. Signers and digests return an error.

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
)

const (
	// MeshDefaultMaxHeadAgeMs is the default bound on the age of a cosigned head a verifier accepts (5 minutes).
	MeshDefaultMaxHeadAgeMs = meshDefaultMaxHeadAgeMs
	// MeshDefaultMaxClockSkewMs is the default clock-skew allowance (1 minute).
	MeshDefaultMaxClockSkewMs = meshDefaultMaxSkewMs
	// MeshDefaultMaxChainLength is the default bound on the length of a delegation chain, and the depth bound of a federated budget tree.
	MeshDefaultMaxChainLength = meshDefaultMaxChain

	meshXcapVersion        = "atlas-pca/mesh-xcap/v1"
	meshXcapDomain         = meshXcapVersion + "\x00"
	meshXanchorDomain      = "atlas-pca/mesh-xanchor/v1\x00"
	meshActionDigestDomain = "atlas-pca/mesh-action-digest/v1\x00"
	meshXrefVersion        = "atlas-pca/mesh-xref/v1"

	meshMalformedTranslated = "malformed translated capability"
)

// KeyRevocationID is the id a domain's revocation set carries to revoke an agent KEY (it kills every capability the key issues).
func KeyRevocationID(agentPublic string) string { return "key:" + agentPublic }

// meshEffectiveRef is the effective authority of a caveat list as the reference computes it on any value: throws reports what
// the reference throws on (a value that is not a list, a null entry); an entry that is not an object has no type and is
// reported as an unknown caveat type.
func meshEffectiveRef(caveats any) (e meshAuthority, msg string, throws bool) {
	arr, ok := caveats.([]any)
	if !ok {
		return e, "", true
	}
	list := make([]any, len(arr))
	for i, c := range arr {
		switch c.(type) {
		case nil:
			return e, "", true
		case map[string]any:
			list[i] = c
		default:
			list[i] = map[string]any{}
		}
	}
	e, msg = meshEffective(list)
	return e, msg, false
}

func meshStringsJSON(l []string) []any {
	out := make([]any, len(l))
	for i, s := range l {
		out[i] = s
	}
	return out
}

func meshAuthorityJSON(e meshAuthority) map[string]any {
	out := map[string]any{"prefixes": meshStringsJSON(e.prefixes)}
	if e.hasAct {
		out["actions"] = meshStringsJSON(e.actions)
	}
	if e.hasAmount {
		out["maxAmount"] = jsNumber(e.maxAmount)
	}
	if e.hasExp {
		out["expiresAt"] = jsNumber(e.expiresAt)
	}
	if e.hasAud {
		out["audience"] = meshStringsJSON(e.audience)
	}
	if e.hasHops {
		out["maxHops"] = jsNumber(e.maxHops)
	}
	return out
}

// EffectiveAuthority is the conjunction of a list of caveats as one authority: {prefixes, actions?, maxAmount?, expiresAt?,
// audience?, maxHops?} (an absent member is unconstrained). An unknown or malformed caveat fails closed as {error}. A value that
// is not a list, or a null entry, is an error.
func EffectiveAuthority(caveats any) (map[string]any, error) {
	e, msg, throws := meshEffectiveRef(caveats)
	if throws {
		return nil, errors.New("effectiveAuthority: the caveats are not a list of caveats")
	}
	if msg != "" {
		return map[string]any{"error": msg}, nil
	}
	return meshAuthorityJSON(e), nil
}

// meshMember is the reference's member access container[key] on decoded JSON: an element of a list by an index (a number, or its
// decimal text), a member of an object by name. ok is false for what the reference reads as undefined.
func meshMember(container, key any) (any, bool) {
	name, isName := key.(string)
	if !isName {
		f, isNum := jsNum(key)
		if !isNum {
			return nil, false
		}
		name = jsNumberString(f)
	}
	switch c := container.(type) {
	case []any:
		i, isIndex := jsArrayIndex(name)
		if !isIndex || i >= uint64(len(c)) {
			return nil, false
		}
		return c[i], true
	case map[string]any:
		v, has := c[name]
		return v, has
	}
	return nil, false
}

// MeshProofSize is the size accounting of a mesh proof, in bytes of canonical JSON: {total_bytes, chain_bytes, heads_bytes,
// rev_leaves_bytes, hops_bytes, uncompacted_bytes}; uncompacted_bytes is what the proof would weigh with every hop carrying its
// own head and revocation leaves. A value that is not a proof (a missing part, a hop naming no head, a hop without its revocation
// proofs) is an error.
func MeshProofSize(proof any) (map[string]any, error) {
	bad := errors.New("meshProofSize: not a mesh proof")
	p, ok := mRec(proof)
	if !ok {
		return nil, bad
	}
	size := func(x any) (float64, bool) {
		b, ok := strictBytes(x)
		return float64(len(b)), ok
	}
	part := func(name string) (float64, bool) {
		v, has := p[name]
		if !has {
			return 0, false
		}
		return size(v)
	}
	total, ok0 := size(p)
	chain, ok1 := part("chain")
	action, ok2 := part("action")
	actionSig, ok3 := part("action_sig")
	heads, ok4 := part("heads")
	leaves, ok5 := part("rev_leaves")
	hopsBytes, ok6 := part("hops")
	hops, isList := p["hops"].([]any)
	if !(ok0 && ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && isList) {
		return nil, bad
	}
	expand := func(cv any) (map[string]any, bool) {
		c, isObj := mRec(cv)
		sz, hasSize := c["size"]
		if !isObj || !hasSize {
			return nil, false
		}
		out := map[string]any{"size": sz}
		for _, side := range []string{"lo", "hi"} {
			if ref, has := c[side]; has {
				if leaf, found := meshMember(p["rev_leaves"], ref); found && meshTruthy(leaf) {
					out[side] = leaf
				}
			}
		}
		return out, true
	}
	uncompacted := chain + action + actionSig
	for _, hv := range hops {
		h, isObj := mRec(hv)
		rev, hasRev := mRec(h["revocation"])
		if !isObj || !hasRev {
			return nil, bad
		}
		head, found := meshMember(p["heads"], h["head"])
		capNM, okCap := expand(rev["cap"])
		keyNM, okKey := expand(rev["issuer_key"])
		if !found || !okCap || !okKey {
			return nil, bad
		}
		full := copyMap(h)
		full["head"] = head
		full["revocation"] = map[string]any{"cap": capNM, "issuer_key": keyNM}
		n, okN := size(full)
		if !okN {
			return nil, bad
		}
		uncompacted += n
	}
	return map[string]any{"total_bytes": jsNumber(total), "chain_bytes": jsNumber(chain), "heads_bytes": jsNumber(heads),
		"rev_leaves_bytes": jsNumber(leaves), "hops_bytes": jsNumber(hopsBytes), "uncompacted_bytes": jsNumber(uncompacted)}, nil
}

// LatencyParams are the freshness parameters of a mesh deployment, in milliseconds: the verifier's bound on the age of a head, how
// often domains publish, and optionally the clock skew the verifier tolerates and how often a pinning verifier refreshes its pins.
type LatencyParams struct {
	MaxHeadAgeMs, HeadIntervalMs float64
	MaxClockSkewMs, PinRefreshMs *float64
}

// LatencyBound is the worst-case time until a revocation takes effect: once published, for a verifier without pins, for a pinning
// verifier; and whether an honest prover can still present a fresh head.
type LatencyBound struct {
	PublishedMs, UnpinnedMs, PinnedMs float64
	HonestProversViable               bool
}

// RevocationLatencyBound is the revocation latency model. A parameter that is not a finite number >= 0 gives the infinite bound
// (no guarantee) and no viable prover.
func RevocationLatencyBound(p LatencyParams) LatencyBound {
	ok := func(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) && x >= 0 }
	if !ok(p.MaxHeadAgeMs) || !ok(p.HeadIntervalMs) || (p.MaxClockSkewMs != nil && !ok(*p.MaxClockSkewMs)) || (p.PinRefreshMs != nil && !ok(*p.PinRefreshMs)) {
		inf := math.Inf(1)
		return LatencyBound{PublishedMs: inf, UnpinnedMs: inf, PinnedMs: inf}
	}
	skew := 0.0
	if p.MaxClockSkewMs != nil {
		skew = *p.MaxClockSkewMs
	}
	unpinned := p.MaxHeadAgeMs + skew
	pinned := unpinned
	if p.PinRefreshMs != nil {
		pinned = math.Min(unpinned, *p.PinRefreshMs)
	}
	return LatencyBound{PublishedMs: p.HeadIntervalMs, UnpinnedMs: unpinned, PinnedMs: pinned, HonestProversViable: p.HeadIntervalMs+skew < p.MaxHeadAgeMs}
}

// ---- cross-domain capability translation --------------------------------------------------------------------------------------

func meshIsCaveatArray(x any) ([]any, bool) {
	arr, ok := x.([]any)
	if !ok {
		return nil, false
	}
	for _, c := range arr {
		m, isObj := mRec(c)
		if _, isStr := m["type"].(string); !isObj || !isStr {
			return nil, false
		}
	}
	return arr, true
}

// meshCloneCaveats deep-copies a caveat list through its strict canonical form (which refuses what cannot be hashed).
func meshCloneCaveats(cs []any) ([]any, error) {
	b, err := canonBytes(cs)
	if err != nil {
		return nil, err
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		return nil, err
	}
	out, _ := v.([]any)
	return out, nil
}

func meshXcapBody(from, to, sourceTip string, caveats []any, issuedAt any) map[string]any {
	return map[string]any{"v": meshXcapVersion, "from": from, "to": to, "source_tip": sourceTip, "caveats": caveats, "issued_at": issuedAt}
}

// TranslateArgs are the arguments of TranslateCapability: the two Guardians, the bridge's narrowing caveats (nil: none), the
// bridge key, the issue time (epoch ms), and the verifier-side PQ pins by Ed25519 identity for a post-quantum or hybrid root.
type TranslateArgs struct {
	FromGuardian, ToGuardian string
	AdditionalCaveats        []any
	Bridge                   *KeyPair
	IssuedAt                 float64
	PqPins                   map[string]string
}

// TranslateCapability translates a capability chain rooted in one Guardian's grant into a capability for another domain: the
// source chain, the two Guardians, the bridge key, the source tip's hash, the caveats (the tip's, then the bridge's: append only,
// so the bridge can only narrow) and the bridge's signature. It fails on an invalid source chain or caveats that are not caveats.
func TranslateCapability(chain []any, args TranslateArgs) (map[string]any, error) {
	if why, ok := VerifyChainPolicy(chain, "", false, nil, args.PqPins, nil); !ok {
		return nil, errors.New("translateCapability: invalid source chain: " + why)
	}
	added := []any{}
	if args.AdditionalCaveats != nil {
		a, ok := meshIsCaveatArray(args.AdditionalCaveats)
		if !ok {
			return nil, errors.New("translateCapability: additionalCaveats must be an array of caveats")
		}
		added = a
	}
	if args.Bridge == nil {
		return nil, errors.New("translateCapability: a bridge key is required")
	}
	tip, _ := mRec(chain[len(chain)-1])
	tipCaveats, _ := tip["caveats"].([]any)
	own, err := meshCloneCaveats(tipCaveats)
	if err != nil {
		return nil, err
	}
	extra, err := meshCloneCaveats(added)
	if err != nil {
		return nil, err
	}
	caveats := append(own, extra...)
	sourceTip, err := CapHash(tip)
	if err != nil {
		return nil, err
	}
	issuedAt := jsNumber(args.IssuedAt)
	msg, ok := meshMsg(meshXcapDomain, meshXcapBody(args.FromGuardian, args.ToGuardian, sourceTip, caveats, issuedAt))
	if !ok {
		return nil, errors.New("translateCapability: the translation is not canonical JSON")
	}
	return map[string]any{"source": chain, "fromGuardian": args.FromGuardian, "toGuardian": args.ToGuardian, "bridge": args.Bridge.Public,
		"source_tip": sourceTip, "caveats": caveats, "issued_at": issuedAt, "sig": b64.EncodeToString(args.Bridge.Sign(msg))}, nil
}

// TranslatedEffectiveAuthority is the effective authority of a translated capability's caveats ({error} when it is malformed or a
// caveat fails closed).
func TranslatedEffectiveAuthority(tc any) map[string]any {
	m, ok := mRec(tc)
	caveats, isCaveats := meshIsCaveatArray(m["caveats"])
	if !ok || !isCaveats {
		return map[string]any{"error": meshMalformedTranslated}
	}
	e, msg := meshEffective(caveats)
	if msg != "" {
		return map[string]any{"error": msg}
	}
	return meshAuthorityJSON(e)
}

// meshNowWithin is Number.isFinite(now) && now <= expiresAt: a null, boolean or string clock is not a finite number, so it is not within.
func meshNowWithin(now any, expiresAt float64) bool {
	f, ok := jsNum(now)
	return ok && !math.IsNaN(f) && !math.IsInf(f, 0) && f <= expiresAt
}

// VerifyTranslatedCapability verifies a translated capability: the source chain, the pinned Guardians and bridge, the binding to
// the source tip, the append-only caveats, the bridge signature, and that the translated authority narrows the source's. The
// result is {ok: true, from, to, bridge, effective} or {ok: false, reason}; it never fails otherwise. opts is at most one value,
// the verifier's expectations as an object with the optional members fromGuardian, toGuardian, bridge, rootIssuer (pins), now
// (epoch ms: an expired translation is refused) and pqPins (the PQ pins by Ed25519 identity for a post-quantum or hybrid root).
// Given as nil it is refused as malformed; a value that is not an object carries no expectation.
func VerifyTranslatedCapability(tcv any, opts ...any) (res map[string]any) {
	fail := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	defer func() {
		if recover() != nil {
			res = fail(meshMalformedTranslated)
		}
	}()
	tc, isObj := mRec(tcv)
	source, isArr := tc["source"].([]any)
	from, okFrom := mStr(tc["fromGuardian"])
	to, okTo := mStr(tc["toGuardian"])
	bridge, okBridge := mStr(tc["bridge"])
	sourceTip, okTip := mStr(tc["source_tip"])
	sig, okSig := mStr(tc["sig"])
	caveats, okCaveats := meshIsCaveatArray(tc["caveats"])
	if !isObj || !isArr || !okFrom || !okTo || !okBridge || !okTip || !okSig || !mNum(tc["issued_at"]) || !okCaveats {
		return fail(meshMalformedTranslated)
	}
	o := map[string]any{}
	if len(opts) > 0 {
		if opts[0] == nil {
			return fail(meshMalformedTranslated)
		}
		if m, isOpts := mRec(opts[0]); isOpts {
			o = m
		}
	}
	// (1) the source chain; a pinned root issuer that is not a string equals no issuer
	root, haveRoot := "", false
	if v, has := o["rootIssuer"]; has {
		haveRoot = true
		if s, isStr := v.(string); isStr {
			root = s
		} else {
			root = "\x00"
		}
	}
	var pins map[string]string
	if pm, has := mRec(o["pqPins"]); has {
		pins = map[string]string{}
		for k, v := range pm {
			if s, isStr := v.(string); isStr {
				pins[k] = s
			}
		}
	}
	if why, ok := VerifyChainPolicy(source, root, haveRoot, nil, pins, nil); !ok {
		return fail("source chain: " + why)
	}
	// (2) the Guardian and bridge pins
	if v, has := o["fromGuardian"]; has && v != any(from) {
		return fail("source guardian mismatch")
	}
	if v, has := o["toGuardian"]; has && v != any(to) {
		return fail("target guardian mismatch")
	}
	if v, has := o["bridge"]; has && v != any(bridge) {
		return fail("bridge key mismatch")
	}
	if from == to {
		return fail("translation does not cross a domain boundary")
	}
	// (3) the binding to the source tip
	tip, _ := mRec(source[len(source)-1])
	tipHash, err := CapHash(tip)
	if err != nil {
		return fail(meshMalformedTranslated)
	}
	if sourceTip != tipHash {
		return fail("source_tip does not match the source chain tip")
	}
	// (4) append only over the source tip's caveats
	tipCaveats, isList := tip["caveats"].([]any)
	if !isList {
		return fail(meshMalformedTranslated)
	}
	if len(caveats) < len(tipCaveats) {
		return fail("translation drops a source caveat (widening)")
	}
	for j := range tipCaveats {
		a, okA := hashCanonicalV(caveats[j])
		b, okB := hashCanonicalV(tipCaveats[j])
		if !okA || !okB {
			return fail(meshMalformedTranslated)
		}
		if a != b {
			return fail(fmt.Sprintf("translation altered or reordered source caveat %d (widening)", j))
		}
	}
	// (5) the bridge signature
	msg, ok := meshMsg(meshXcapDomain, meshXcapBody(from, to, sourceTip, caveats, tc["issued_at"]))
	if !ok {
		return fail(meshMalformedTranslated)
	}
	if !verifyB64u(bridge, msg, sig) {
		return fail("translation not signed by the declared bridge key")
	}
	// (6) the translated authority narrows the source's (an unknown caveat on either side fails closed)
	effS, why, throws := meshEffectiveRef(tipCaveats)
	if throws {
		return fail(meshMalformedTranslated)
	}
	if why != "" {
		return fail("source caveats: " + why)
	}
	effT, why := meshEffective(caveats)
	if why != "" {
		return fail(why)
	}
	if !meshNarrows(effT, effS) {
		return fail("translated authority widens the source authority")
	}
	// (7) expiry, when the verifier gives its time
	if now, has := o["now"]; has && effT.hasExp && !meshNowWithin(now, effT.expiresAt) {
		return fail("translated capability expired")
	}
	return map[string]any{"ok": true, "from": from, "to": to, "bridge": bridge, "effective": meshAuthorityJSON(effT)}
}

// ---- the federated budget tree --------------------------------------------------------------------------------------------------

func meshBudgetFail(reason string) map[string]any {
	return map[string]any{"ok": false, "reason": reason}
}

// CreateFederatedBudget creates the budget tree of a cross-domain delegation from {rootId, rootDomain, B0, kappa, bMax}: {ok:
// true, state} with state = {nodes: {<id>: {domain, parent?, B}}, root, kappa, bMax}, or {ok: false, reason}.
func CreateFederatedBudget(args any) map[string]any {
	a, ok := mRec(args)
	rootID, okID := mStr(a["rootId"])
	rootDomain, okDomain := mStr(a["rootDomain"])
	if !ok || !okID || !okDomain {
		return meshBudgetFail("malformed root")
	}
	if !mNum(a["kappa"]) || jsF(a["kappa"]) <= 0 {
		return meshBudgetFail("kappa must be finite and > 0")
	}
	if !mNum(a["bMax"]) || jsF(a["bMax"]) < 0 {
		return meshBudgetFail("bMax must be finite and >= 0")
	}
	if !mNum(a["B0"]) || jsF(a["B0"]) < 0 {
		return meshBudgetFail("B0 must be finite and >= 0")
	}
	if jsF(a["B0"]) > jsF(a["bMax"]) {
		return meshBudgetFail("B0 exceeds bMax")
	}
	return map[string]any{"ok": true, "state": map[string]any{"nodes": map[string]any{rootID: map[string]any{"domain": rootDomain, "B": a["B0"]}},
		"root": rootID, "kappa": a["kappa"], "bMax": a["bMax"]}}
}

func meshValidBudgetState(sv any) (map[string]any, map[string]any, bool) {
	s, ok := mRec(sv)
	nodes, okNodes := mRec(s["nodes"])
	root, okRoot := mStr(s["root"])
	if !ok || !okNodes || !okRoot || !mNum(s["kappa"]) || !mNum(s["bMax"]) || jsF(s["kappa"]) <= 0 || jsF(s["bMax"]) < 0 {
		return nil, nil, false
	}
	if _, has := nodes[root]; !has {
		return nil, nil, false
	}
	for _, nv := range nodes {
		n, isObj := mRec(nv)
		if _, isStr := n["domain"].(string); !isObj || !isStr || !mNum(n["B"]) || jsF(n["B"]) < 0 {
			return nil, nil, false
		}
		if p, has := n["parent"]; has {
			if _, isStr := p.(string); !isStr {
				return nil, nil, false
			}
		}
	}
	return s, nodes, true
}

// AllocateSub adds a sub-agent to a budget tree from {id, domain, parent, alloc}: a ceiling of alloc, at most the parent's
// CURRENT remaining budget (the parent is not reduced). The input state is not modified.
func AllocateSub(state, args any) map[string]any {
	s, nodes, ok := meshValidBudgetState(state)
	if !ok {
		return meshBudgetFail("malformed budget state")
	}
	a, isObj := mRec(args)
	id, okID := mStr(a["id"])
	domain, okDomain := mStr(a["domain"])
	parent, okParent := mStr(a["parent"])
	if !isObj || !okID || !okDomain || !okParent {
		return meshBudgetFail("malformed allocation")
	}
	if _, has := nodes[id]; has {
		return meshBudgetFail("node id already exists")
	}
	pn, has := mRec(nodes[parent])
	if !has {
		return meshBudgetFail("unknown parent")
	}
	alloc, isNum := jsNum(a["alloc"])
	if !isNum {
		alloc = math.NaN()
	}
	sub, err := SubBudget(TrustBudget{B: jsF(pn["B"])}, alloc)
	if err != nil {
		return meshBudgetFail(err.Error())
	}
	next := copyMap(nodes)
	next[id] = map[string]any{"domain": domain, "parent": parent, "B": jsNumber(sub.B)}
	out := copyMap(s)
	out["nodes"] = next
	return map[string]any{"ok": true, "state": out}
}

// meshBudgetPath is the path from a node up to and including the root; it guards against cycles, stray nodes and depth.
func meshBudgetPath(nodes map[string]any, root, nodeID string) ([]string, string) {
	var path []string
	seen := map[string]bool{}
	cur, more := nodeID, true
	for more {
		n, has := mRec(nodes[cur])
		switch {
		case !has:
			return nil, "unknown node"
		case seen[cur]:
			return nil, "cycle in budget tree"
		case len(path) >= meshDefaultMaxChain:
			return nil, "budget tree too deep"
		}
		seen[cur] = true
		path = append(path, cur)
		cur, more = n["parent"].(string)
	}
	if path[len(path)-1] != root {
		return nil, "node is not rooted at the budget root"
	}
	return path, ""
}

// SpendFederated debits a spend of c by a node from the whole tree, atomically: every ancestor between the spender and the root
// must cover c, and the root and the spender are debited together. The input state is not modified.
func SpendFederated(state any, nodeID any, c any) map[string]any {
	s, nodes, ok := meshValidBudgetState(state)
	if !ok {
		return meshBudgetFail("malformed budget state")
	}
	id, isStr := nodeID.(string)
	if !isStr {
		return meshBudgetFail("malformed node id")
	}
	if !mNum(c) || jsF(c) < 0 {
		return meshBudgetFail("spend must be finite and >= 0")
	}
	cost := jsF(c)
	root := s["root"].(string)
	path, why := meshBudgetPath(nodes, root, id)
	if why != "" {
		return meshBudgetFail(why)
	}
	next := copyMap(nodes)
	b := func(k string) float64 { return jsF(nodes[k].(map[string]any)["B"]) }
	set := func(k string, v float64) {
		n := copyMap(nodes[k].(map[string]any))
		n["B"] = jsNumber(v)
		next[k] = n
	}
	done := func() map[string]any {
		out := copyMap(s)
		out["nodes"] = next
		return map[string]any{"ok": true, "state": out}
	}
	if id == root {
		if !(finite(b(root)) && b(root) >= cost) {
			return meshBudgetFail("root budget insufficient")
		}
		set(root, TrustBudget{B: b(root)}.Debit(cost).B)
		return done()
	}
	interior := path[1 : len(path)-1]
	for _, k := range interior {
		if !(finite(b(k)) && b(k) >= cost) {
			return meshBudgetFail(fmt.Sprintf("ancestor \"%s\" budget insufficient", k))
		}
	}
	newRoot, newSub, err := DebitConsolidated(TrustBudget{B: b(root)}, TrustBudget{B: b(id)}, cost)
	if err != nil {
		return meshBudgetFail(err.Error())
	}
	set(id, newSub.B)
	set(root, newRoot.B)
	for _, k := range interior {
		set(k, TrustBudget{B: b(k)}.Debit(cost).B)
	}
	return done()
}

// FederatedSafetyBound is the bound on the total risk the whole delegation tree can spend between two human recharges: bMax /
// kappa of {bMax, kappa}; 0 for anything else.
func FederatedSafetyBound(p any) float64 {
	m, ok := mRec(p)
	if !ok || !mNum(m["bMax"]) || !mNum(m["kappa"]) {
		return 0
	}
	return SafetyBound(jsF(m["bMax"]), jsF(m["kappa"]))
}

// ---- the cross-reference commitment ------------------------------------------------------------------------------------------------

// MeshActionDigest is the digest of a mesh action for anchoring (domain separated, strict canonical).
func MeshActionDigest(action any) (string, error) {
	return HashCanonical(map[string]any{"v": meshActionDigestDomain, "action": action})
}

// CrossReferenceCommit is the commitment both Guardians anchor for a cross-domain action {action_digest, fromGuardian,
// toGuardian, nonce, at}. A missing member, or one the canonical hash refuses, is an error.
func CrossReferenceCommit(x map[string]any) (string, error) {
	body := map[string]any{"v": meshXrefVersion}
	for name, member := range map[string]string{"action_digest": "action_digest", "from": "fromGuardian", "to": "toGuardian", "nonce": "nonce", "at": "at"} {
		v, has := x[member]
		if !has {
			return "", errors.New("crossReferenceCommit: missing " + member)
		}
		body[name] = v
	}
	return HashCanonical(body)
}

// AnchorCrossReference is a Guardian's signed anchor of a commitment at position seq of its own log: {domain, commit, seq, sig}.
// commit is the commitment (a string) and seq the position (a number); like the reference it signs whatever canonical JSON
// values it is given (only VerifyCrossReference requires a string and a natural number) and fails on one the canonical form
// refuses.
func AnchorCrossReference(domain *KeyPair, commit, seq any) (map[string]any, error) {
	if domain == nil {
		return nil, errors.New("anchorCrossReference: a domain key is required")
	}
	switch n := seq.(type) {
	case float64:
		seq = jsNumber(n)
	case int:
		seq = json.Number(strconv.Itoa(n))
	case int64:
		seq = json.Number(strconv.FormatInt(n, 10))
	}
	msg, ok := meshMsg(meshXanchorDomain, map[string]any{"commit": commit, "seq": seq})
	if !ok {
		return nil, errors.New("anchorCrossReference: the anchor is not canonical JSON")
	}
	return map[string]any{"domain": domain.Public, "commit": commit, "seq": seq, "sig": b64.EncodeToString(domain.Sign(msg))}, nil
}

func meshValidAnchor(av any) (domain, commit, sig string, seq any, ok bool) {
	a, isObj := mRec(av)
	domain, ok1 := mStr(a["domain"])
	commit, ok2 := mStr(a["commit"])
	sig, ok3 := mStr(a["sig"])
	return domain, commit, sig, a["seq"], isObj && ok1 && ok2 && ok3 && mNat(a["seq"])
}

// VerifyCrossReference verifies that both Guardians anchored the same cross-domain action: {ok: true, commit} or {ok: false,
// reason}. anchors is {from, to}, each a signed anchor. It never fails otherwise.
func VerifyCrossReference(xv, anchors any) (res map[string]any) {
	fail := func(reason string) map[string]any { return map[string]any{"ok": false, "reason": reason} }
	defer func() {
		if recover() != nil {
			res = fail("malformed cross-reference")
		}
	}()
	x, isObj := mRec(xv)
	_, ok1 := mStr(x["action_digest"])
	from, ok2 := mStr(x["fromGuardian"])
	to, ok3 := mStr(x["toGuardian"])
	_, ok4 := mStr(x["nonce"])
	if !isObj || !ok1 || !ok2 || !ok3 || !ok4 || !mNum(x["at"]) {
		return fail("malformed cross-reference")
	}
	am, isAnchors := mRec(anchors)
	fd, fc, fs, fseq, okF := meshValidAnchor(am["from"])
	td, tc, ts, tseq, okT := meshValidAnchor(am["to"])
	if !isAnchors || !okF || !okT {
		return fail("malformed anchors")
	}
	if from == to {
		return fail("cross-reference must span two distinct domains")
	}
	expected, err := CrossReferenceCommit(x)
	if err != nil {
		return fail("malformed cross-reference")
	}
	switch {
	case fd != from:
		return fail("source anchor domain does not match the cross-reference")
	case td != to:
		return fail("target anchor domain does not match the cross-reference")
	case fc != expected:
		return fail("source anchor commits a different action")
	case tc != expected:
		return fail("target anchor commits a different action")
	}
	signed := func(domain, commit, sig string, seq any) bool {
		msg, ok := meshMsg(meshXanchorDomain, map[string]any{"commit": commit, "seq": seq})
		return ok && verifyB64u(domain, msg, sig)
	}
	if !signed(fd, fc, fs, fseq) {
		return fail("source anchor signature invalid")
	}
	if !signed(td, tc, ts, tseq) {
		return fail("target anchor signature invalid")
	}
	return map[string]any{"ok": true, "commit": expected}
}

// ---- the worked example ----------------------------------------------------------------------------------------------------------

// meshExampleKey is a key of the worked example: its seed is the first 32 bytes of the TEXT of a canonical hash, so the example
// is the same everywhere.
func meshExampleKey(label string) (*KeyPair, error) {
	h, err := HashCanonical(map[string]any{"seed": "atlas-pca/mesh-example/" + label})
	if err != nil {
		return nil, err
	}
	return KeyPairFromSeed([]byte(h)[:32])
}

// MeshExample is the worked example human -> orchestrator (org A) -> tool agent (org B) -> service (org C), with its parts, so a
// caller can build variants (a revocation, a widening, a fork). Keys are named human, orchestrator, tool, service and leaf; Heads
// A0, A, B and C; Bindings orchestrator, tool and service.
type MeshExample struct {
	Trust, Proof              map[string]any
	Evidence, Chain           []map[string]any
	DomainA, DomainB, DomainC *MeshDomain
	Witnesses                 []*MeshWitness
	Keys                      map[string]*KeyPair
	Heads, Bindings           map[string]map[string]any
}

// BuildMeshExample builds the worked example at time now (epoch ms): three domains, three witnesses, a four-hop chain and a
// compacted proof that VerifyMeshProof accepts under Trust.
func BuildMeshExample(now float64) (ex *MeshExample, err error) {
	keys := map[string]*KeyPair{}
	key := func(label string) *KeyPair {
		k, e := meshExampleKey(label)
		if e != nil && err == nil {
			err = e
		}
		return k
	}
	for _, name := range []string{"human", "orchestrator", "tool", "service", "leaf"} {
		keys[name] = key(name)
	}
	dA, dB, dC := key("domain-A"), key("domain-B"), key("domain-C")
	w1, w2, w3 := key("witness-1"), key("witness-2"), key("witness-3")
	if err != nil {
		return nil, err
	}
	a, b, c := NewMeshDomain("org-A", dA), NewMeshDomain("org-B", dB), NewMeshDomain("org-C", dC)
	var witnesses []*MeshWitness
	for _, k := range []*KeyPair{w1, w2, w3} {
		w, e := NewMeshWitness(k, MeshWitnessOptions{})
		if e != nil {
			return nil, e
		}
		witnesses = append(witnesses, w)
	}
	scope := func(actions ...any) map[string]any { return map[string]any{"type": "scope", "actions": actions} }
	amount := func(max float64) map[string]any { return map[string]any{"type": "max_amount", "max": jsNumber(max)} }
	prefix := func(p string) map[string]any { return map[string]any{"type": "resource", "prefix": p} }
	root, err := MintRoot(keys["human"], keys["orchestrator"].Public, []any{scope("payments.refund", "payments.read", "orders.read"), prefix("/orders/"),
		amount(500), map[string]any{"type": "expires", "at": jsNumber(now + 3_600_000)}, map[string]any{"type": "audience", "domains": []any{c.ID}}}, "", nil)
	if err != nil {
		return nil, err
	}
	c1, err := Delegate(root, keys["orchestrator"], keys["tool"].Public, []any{scope("payments.refund", "payments.read"), amount(100)}, "", nil)
	if err != nil {
		return nil, err
	}
	c2, err := Delegate(c1, keys["tool"], keys["service"].Public, []any{prefix("/orders/42"), map[string]any{"type": "max_hops", "n": jsNumber(4)}}, "", nil)
	if err != nil {
		return nil, err
	}
	c3, err := Delegate(c2, keys["service"], keys["leaf"].Public, []any{scope("payments.refund"), amount(50)}, "", nil)
	if err != nil {
		return nil, err
	}
	record := func(d *MeshDomain, cap map[string]any) {
		if _, e := d.Record(cap); e != nil && err == nil {
			err = e
		}
	}
	publish := func(d *MeshDomain, at float64) map[string]any {
		h, e := d.PublishHead(witnesses, at, nil)
		if e != nil && err == nil {
			err = e
		}
		return h
	}
	record(a, root)
	hA0 := publish(a, now-2_000)
	record(a, c1)
	hA := publish(a, now-1_000) // size 1 -> 2: every witness is shown the consistency proof
	record(b, c2)
	record(c, c3)
	hB, hC := publish(b, now-1_000), publish(c, now-1_000)
	if err != nil {
		return nil, err
	}
	enroll := func(d *MeshDomain, agent, role string) map[string]any {
		bd, e := d.Enroll(agent, role)
		if e != nil && err == nil {
			err = e
		}
		return bd
	}
	bOrch := enroll(a, keys["orchestrator"].Public, "orchestrator")
	bTool := enroll(b, keys["tool"].Public, "tool-agent")
	bSvc := enroll(c, keys["service"].Public, "service-agent")
	evidence := func(d *MeshDomain, cap, head, binding map[string]any) map[string]any {
		ev, e := d.Evidence(cap, head, binding)
		if e != nil && err == nil {
			err = e
		}
		return ev
	}
	hops := []map[string]any{evidence(a, root, hA, nil), evidence(a, c1, hA, bOrch), evidence(b, c2, hB, bTool), evidence(c, c3, hC, bSvc)}
	if err != nil {
		return nil, err
	}
	chain := []map[string]any{root, c1, c2, c3}
	action := map[string]any{"type": "payments.refund", "resource": "/orders/42/line/1", "amount": jsNumber(25), "service_domain": c.ID, "nonce": "n-0001",
		"at": jsNumber(now)}
	proof, err := AssembleMeshProof(chain, hops, action, keys["leaf"], nil)
	if err != nil {
		return nil, err
	}
	trust := map[string]any{"humanPrincipal": keys["human"].Public, "witnesses": []any{witnesses[0].ID, witnesses[1].ID, witnesses[2].ID},
		"threshold": jsNumber(2), "now": jsNumber(now), "allowedDomains": []any{a.ID, b.ID, c.ID}, "rootDomain": a.ID}
	return &MeshExample{Trust: trust, Proof: proof, Evidence: hops, Chain: chain, DomainA: a, DomainB: b, DomainC: c, Witnesses: witnesses, Keys: keys,
		Heads:    map[string]map[string]any{"A0": hA0, "A": hA, "B": hB, "C": hC},
		Bindings: map[string]map[string]any{"orchestrator": bOrch, "tool": bTool, "service": bSvc}}, nil
}

// ForkDemo is the outcome of DemonstrateForkRejection.
type ForkDemo struct {
	// HonestExtensionCosigned: the witness cosigned an honest, larger head of the domain.
	HonestExtensionCosigned bool
	// ForkLargerThanPrior and SizeOnlyCheckWouldAccept: the fork is larger than the head the witness saw, so a check of sizes
	// alone would have accepted it.
	ForkLargerThanPrior, SizeOnlyCheckWouldAccept bool
	// ForkRejected with ForkReason: the witness refused the fork, for want of a consistency proof.
	ForkRejected bool
	ForkReason   string
}

// DemonstrateForkRejection shows why a witness asks for a consistency proof and not only a larger size: a domain key that
// rewrites its history and grows the log past the last head a witness cosigned is refused.
func DemonstrateForkRejection() (ForkDemo, error) {
	var demo ForkDemo
	k, err := meshExampleKey("fork-domain")
	if err != nil {
		return demo, err
	}
	hk, err := meshExampleKey("fork-human")
	if err != nil {
		return demo, err
	}
	wk, err := meshExampleKey("fork-witness")
	if err != nil {
		return demo, err
	}
	w, err := NewMeshWitness(wk, MeshWitnessOptions{})
	if err != nil {
		return demo, err
	}
	record := func(d *MeshDomain, n int) error {
		cap, e := MintRoot(hk, hk.Public, []any{map[string]any{"type": "scope", "actions": []any{"a" + strconv.Itoa(n)}}}, "", nil)
		if e != nil {
			return e
		}
		_, e = d.Record(cap)
		return e
	}
	honest := NewMeshDomain("X", k)
	for _, n := range []int{0, 1} {
		if err := record(honest, n); err != nil {
			return demo, err
		}
	}
	if _, err := honest.PublishHead([]*MeshWitness{w}, 100, nil); err != nil {
		return demo, err
	}
	if err := record(honest, 2); err != nil {
		return demo, err
	}
	_, err = honest.PublishHead([]*MeshWitness{w}, 200, nil)
	demo.HonestExtensionCosigned = err == nil
	prior, _ := safeInt(w.LastSeen(honest.ID)["size"])
	fork := NewMeshDomain("X", k) // the same key, a rewritten history (entry 0 differs), grown past the prior size
	for _, n := range []int{100, 1, 2, 3} {
		if err := record(fork, n); err != nil {
			return demo, err
		}
	}
	if _, err := fork.PublishHead([]*MeshWitness{w}, 300, nil); err != nil {
		demo.ForkRejected, demo.ForkReason = true, err.Error()
	}
	demo.ForkLargerThanPrior, demo.SizeOnlyCheckWouldAccept = 4 > prior, 4 >= prior
	return demo, nil
}

// LogSize is the number of delegations the domain has recorded (the newSize of ConsistencyProof for the current log).
func (d *MeshDomain) LogSize() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.log.Size()
}
