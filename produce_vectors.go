package pca

// ProduceVector runs one case of the shared producer vectors (producer-vectors.json, producer-pq-vectors.json) through this
// package's producers: the conformance drivers and the tests call it, so both run exactly the same code.

import (
	"errors"
	"fmt"
)

type vecArgs struct {
	m     map[string]any
	keys  map[string]any
	pq    map[string]any
	err   error
	cache map[string]*KeyPair
}

func (v *vecArgs) fail(format string, a ...any) {
	if v.err == nil {
		v.err = fmt.Errorf("produce: "+format, a...)
	}
}

func (v *vecArgs) str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func (v *vecArgs) num(m map[string]any, k string) int64 {
	n, ok := safeInt(m[k])
	if !ok {
		v.fail("%s must be an integer", k)
	}
	return n
}

func (v *vecArgs) obj(m map[string]any, k string) map[string]any {
	o, ok := m[k].(map[string]any)
	if !ok {
		v.fail("%s must be an object", k)
	}
	return o
}

func (v *vecArgs) list(m map[string]any, k string) []any {
	l, ok := m[k].([]any)
	if !ok {
		v.fail("%s must be an array", k)
	}
	return l
}

func (v *vecArgs) strs(m map[string]any, k string) []string {
	out := []string{}
	for _, x := range v.list(m, k) {
		s, ok := x.(string)
		if !ok {
			v.fail("%s must be an array of strings", k)
		}
		out = append(out, s)
	}
	return out
}

func (v *vecArgs) objs(m map[string]any, k string) []map[string]any {
	out := []map[string]any{}
	for _, x := range v.list(m, k) {
		o, ok := x.(map[string]any)
		if !ok {
			v.fail("%s must be an array of objects", k)
		}
		out = append(out, o)
	}
	return out
}

// ed is the Ed25519 key named by args[k] ("" when args[k] is absent and optional).
func (v *vecArgs) ed(m map[string]any, k string) *KeyPair {
	name := v.str(m, k)
	if kp, ok := v.cache[name]; ok {
		return kp
	}
	ent, _ := v.keys[name].(map[string]any)
	kp, err := KeyPairFromSeedB64u(v.str(ent, "seed"))
	if err != nil {
		v.fail("no Ed25519 key %q", name)
		return &KeyPair{}
	}
	v.cache[name] = kp
	return kp
}

// pqKey is the PQ key named by args[k] (nil for null / absent).
func (v *vecArgs) pqKey(m map[string]any, k string) *PqKeyPair {
	name := v.str(m, k)
	if name == "" {
		return nil
	}
	ent, _ := v.pq[name].(map[string]any)
	fam, ok := pqVectorFamilies[v.str(ent, "family")]
	if !ok {
		v.fail("%s: %s", UnsupportedSuite, v.str(ent, "family"))
		return nil
	}
	seed, _ := DecodeB64uStrict(v.str(ent, "seed"), -1)
	kp, err := GeneratePqKeyPairFromSeed(fam, seed)
	if err != nil {
		v.fail("%v", err)
	}
	return kp
}

var pqVectorFamilies = map[string]string{"ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87", "slh-dsa-sha2-128f": "SLH-DSA-SHA2-128f", "slh-dsa-sha2-256s": "SLH-DSA-SHA2-256s"}

// ProduceVector runs op over args (keys: the vector file's Ed25519 keys {name: {seed, public}}; pqKeys: its PQ keys, nil for
// the Ed25519 file). The result is the vector's `expect` shape; a refusal is an error. An op this package does not produce
// is refused with "unsupported_op: <op>"; a suite it cannot sign with "unsupported_suite: <alg>".
func ProduceVector(op string, args, keys, pqKeys map[string]any) (out any, err error) {
	v := &vecArgs{m: args, keys: keys, pq: pqKeys, cache: map[string]*KeyPair{}}
	defer func() {
		if r := recover(); r != nil { // a malformed vector is refused, never a crash
			out, err = nil, fmt.Errorf("produce: malformed %s vector: %v", op, r)
		}
		if err == nil && v.err != nil {
			out, err = nil, v.err
		}
	}()
	a := args
	b, _ := a["body"].(map[string]any)
	sig := func(s string, err error) (any, error) { return map[string]any{"sig": s}, err }
	epoch := func(b map[string]any) RevocationEpochBody {
		return RevocationEpochBody{InstanceID: v.str(b, "instance_id"), GrantRef: v.str(b, "grant_ref"), Epoch: v.num(b, "epoch"), SetSize: v.num(b, "set_size"),
			Root: v.str(b, "root"), IssuedAt: v.num(b, "issued_at"), NotAfter: v.num(b, "not_after")}
	}
	var suite *SuiteOpts
	if alg := v.str(a, "alg"); alg != "" {
		suite = &SuiteOpts{Alg: alg, Pq: v.pqKey(a, "pq")}
	}
	holderPq := ""
	if k := v.pqKey(a, "holder_pq"); k != nil {
		holderPq = k.Public
	}
	if v.err != nil {
		return nil, v.err
	}
	switch op {
	// ---- the grant / action core
	case "ed25519_sign":
		k, err := KeyPairFromSeedB64u(v.str(a, "seed"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"public": k.Public, "sig": b64.EncodeToString(k.Sign([]byte(v.str(a, "message_utf8"))))}, nil
	case "goal_commit":
		c, err := GoalCommitOf(v.str(a, "goal"), v.str(a, "salt"))
		return map[string]any{"commit": c}, err
	case "params_digest":
		c, err := ParamsDigest(a["params"])
		return map[string]any{"digest": c}, err
	case "plan_commit":
		nodes := v.objs(a, "nodes")
		pc, err := CommitPlan(nodes)
		if err != nil {
			return nil, err
		}
		proofs := map[string]any{}
		for _, n := range nodes {
			p, err := pc.ProofFor(v.str(n, "id"))
			if err != nil {
				return nil, err
			}
			proofs[v.str(n, "id")] = p
		}
		return map[string]any{"root": pc.Root, "proofs": proofs}, nil
	case "mint_grant":
		r, err := MintGrant(v.ed(a, "principal"), v.ed(a, "holder").Public, v.obj(a, "envelope"), v.str(a, "goal"), v.str(a, "salt"), "", nil)
		if err != nil {
			return nil, err
		}
		return map[string]any{"grant": r.Grant, "goal_commit": r.GoalCommit, "goal_salt": r.GoalSalt}, nil
	case "delegate":
		to := ""
		if v.str(a, "to_holder") != "" {
			to = v.ed(a, "to_holder").Public
		}
		return Delegate(v.obj(a, "parent"), v.ed(a, "signer"), to, v.list(a, "added_caveats"), "", nil)
	case "act":
		in := PCActnInput{Grant: v.obj(a, "grant"), Chain: v.objs(a, "chain"), Plan: v.objs(a, "plan"), NodeID: v.str(a, "node_id"), Params: a["params"],
			Counter: v.num(a, "counter"), Signer: v.ed(a, "signer"), Aud: v.str(a, "aud"), Iat: v.num(a, "iat"), Exp: v.num(a, "exp"), Extra: map[string]any{}}
		for _, k := range []string{"nonce", "caution", "rationale_commitment", "tool_binding", "fresh_at"} {
			if x, ok := a[k]; ok {
				in.Extra[k] = x
			}
		}
		if v.err != nil {
			return nil, v.err
		}
		p, err := BuildPCActn(in)
		if err != nil {
			return nil, err
		}
		h, err := PCAHeaders(p, nil, nil, nil)
		if err != nil {
			return nil, err
		}
		return map[string]any{"pcactn": p, "header": h[PCAHeader]}, nil
	case "fresh_at":
		return SignFreshAt(v.ed(a, "signer"), v.str(a, "scope"), v.obj(a, "state"), v.num(a, "issued_at"))
	case "escalation_digests":
		var last *int64
		if a["last_counter"] != nil {
			n := v.num(a, "last_counter")
			last = &n
		}
		pd, err := EscalationPolicyDigest(v.obj(a, "grant"))
		if err != nil {
			return nil, err
		}
		ad, err := EscalationActionDigest(v.obj(a, "pcactn"))
		if err != nil {
			return nil, err
		}
		hh, err := EscalationHistoryHead(last)
		return map[string]any{"policy_digest": pd, "action_digest": ad, "history_head": hh}, err
	case "sign_escalation_answer":
		return SignEscalationAnswer(v.ed(a, "signer"), b, v.str(b, "decision"), v.num(b, "iat"), v.num(b, "expires_at"), v.str(b, "nonce"), nil)
	case "sign_discharge":
		return SignDischarge(v.ed(a, "signer"), DischargeInput{CaveatID: v.str(b, "caveat_id"), IssuerLabel: v.str(b, "issuer"), CapHash: v.str(b, "cap_hash"),
			Bind: v.str(b, "bind"), ActionDigest: v.str(b, "action_digest"), Claims: v.obj(b, "claims"), Iat: v.num(b, "iat"), NotAfter: v.num(b, "not_after"), Nonce: v.str(b, "nonce")}, nil)
	case "discharge_digest":
		x, err := DischargeDigest(a["discharge"])
		return map[string]any{"digest": x}, err
	case "sign_narrow":
		return SignNarrow(v.ed(a, "signer"), v.str(b, "cap_hash"), v.list(b, "caveats"), v.num(b, "iat"), v.num(b, "not_after"), v.str(b, "action_digest"), v.str(b, "nonce"), nil)
	case "sign_passport":
		pp, err := IssuePassport(v.obj(a, "identity"))
		if err != nil {
			return nil, err
		}
		sp, err := SignPassport(pp, v.ed(a, "issuer"), v.ed(a, "subject").Public, 0, 0, v.num(a, "exp"), nil, nil)
		return map[string]any{"passport": pp, "signed": sp}, err
	case "sign_workflow":
		return SignWorkflow(v.ed(a, "signer"), b)
	case "sign_step_receipt":
		prev, _ := a["prev"].(map[string]any)
		return SignStepReceipt(v.ed(a, "signer"), v.obj(a, "workflow"), v.str(a, "step"), v.str(a, "outcome"), v.str(a, "params_digest"), v.obj(a, "outputs"),
			v.num(a, "issued_at"), prev)
	case "sign_read_grant":
		return SignReadGrant(v.ed(a, "signer"), b)
	case "sign_aggregate_grant":
		return SignAggregateGrant(v.ed(a, "signer"), b)

	// ---- the deterministic post-quantum file
	case "pq_keygen":
		fam, ok := pqVectorFamilies[v.str(a, "family")]
		if !ok {
			return nil, fmt.Errorf("%s: %s", UnsupportedSuite, v.str(a, "family"))
		}
		seed, _ := DecodeB64uStrict(v.str(a, "seed"), -1)
		k, err := GeneratePqKeyPairFromSeed(fam, seed)
		if err != nil {
			return nil, err
		}
		return map[string]any{"public": k.Public}, nil
	case "suite_sign":
		var ed *KeyPair // null for a pure post-quantum suite
		if a["ed"] != nil {
			ed = v.ed(a, "ed")
		}
		s, p, err := SignWithSuite(suite, ed, []byte(v.str(a, "message_utf8")))
		r := map[string]any{"sig": s}
		if p != "" {
			r["pq_sig"] = p
		}
		return r, err
	case "mint_root_suite":
		return MintRoot(v.ed(a, "principal"), v.ed(a, "holder").Public, v.list(a, "caveats"), holderPq, suite)
	case "delegate_suite":
		to := ""
		if v.str(a, "to_holder") != "" {
			to = v.ed(a, "to_holder").Public
		}
		added, _ := a["added_caveats"].([]any)
		return Delegate(v.obj(a, "parent"), v.ed(a, "signer"), to, added, holderPq, suite)
	case "sign_pcactn_suite":
		p, err := SignPCActn(b, v.ed(a, "signer"), suite)
		return map[string]any{"pcactn": p}, err
	case "sign_artifact_suite":
		if v.str(a, "kind") == "revocation_epoch" {
			return SignRevocationEpoch(v.ed(a, "signer").Seed(), epoch(b), suite)
		}
		return SignEscalationAnswer(v.ed(a, "signer"), b, v.str(b, "decision"), v.num(b, "iat"), v.num(b, "expires_at"), v.str(b, "nonce"), suite)

	// ---- signers beyond the grant / action core
	case "sign_revocation_epoch":
		return SignRevocationEpoch(v.ed(a, "signer").Seed(), epoch(b))
	case "sign_undo_token":
		r := v.obj(a, "record")
		return SignUndoToken(UndoTokenRecord{ID: v.str(r, "id"), Aud: v.str(r, "aud"), Principal: v.str(r, "principal"),
			CompensationDigest: v.str(r, "compensation_digest"), RenderDigest: v.str(r, "render_digest"), WindowEnd: v.num(r, "window_end")}, v.ed(a, "signer"))
	case "sign_undo_receipt":
		return SignUndoReceipt(UndoReceiptBody{Record: v.str(b, "record"), Event: v.str(b, "event"), State: v.str(b, "state"), At: v.num(b, "at"),
			CompensationDigest: v.str(b, "compensation_digest"), Prev: v.str(b, "prev"), Note: v.str(b, "note")}, v.ed(a, "signer"))
	case "sign_contract":
		return SignContract(a["contract"], v.ed(a, "signer").Seed())
	case "sign_contract_reset":
		return sig(SignContractReset(v.ed(a, "signer").Seed(), v.str(a, "contract_id"), v.num(a, "seq")))
	case "sign_constitution":
		return SignConstitution(a["constitution"], v.ed(a, "signer").Seed())
	case "sign_safety_evidence":
		k := v.ed(a, "signer")
		return SignSafetyEvidence(a["evidence"], k.Seed(), k.Public)
	case "sign_threshold_share":
		m, _ := DecodeB64uStrict(v.str(a, "message"), -1)
		return SignThresholdShare(v.str(a, "role"), v.ed(a, "signer"), m, v.list(a, "signer_set"), int(v.num(a, "t")), nil)
	case "sign_prepared_share":
		m, _ := DecodeB64uStrict(v.str(a, "prepared"), -1)
		return SignPreparedShare(v.str(a, "role"), v.ed(a, "signer"), m, nil)
	case "sign_pq_binding":
		return SignPqBinding(v.ed(a, "signer"), v.str(a, "pq_pk"), v.num(a, "epoch"), v.str(a, "aud"))
	case "sign_caution":
		return SignCaution(v.ed(a, "signer"), b)
	case "sign_heartbeat":
		return SignHeartbeat(v.ed(a, "signer"), b)
	case "prov_recorder":
		return produceRecorder(v, a)
	case "sign_mesh_action":
		return sig(SignMeshAction(v.objs(a, "chain"), v.obj(a, "action"), v.ed(a, "signer")))
	case "sign_session_root":
		return SignSessionRoot(v.ed(a, "signer"), b, nil)
	case "mint_session_grant":
		cav, _ := a["caveats"].([]any)
		g, salt, err := MintSessionGrant(SessionGrantInput{Principal: v.ed(a, "principal"), Holder: v.ed(a, "holder").Public, Session: v.str(a, "session"),
			Seq: v.num(a, "seq"), Prev: v.str(a, "prev"), Root: v.str(a, "root"), MapDigest: v.str(a, "map_digest"), MapForm: v.str(a, "map_form"),
			Predicates: v.list(a, "predicates"), Caveats: cav, Salt: v.str(a, "salt")})
		return map[string]any{"grant": g, "goal_salt": salt}, err
	case "sign_action_schema":
		return SignActionSchema(v.obj(a, "doc"), v.str(a, "kid"), v.ed(a, "signer"), nil)
	case "sign_intent_required":
		return SignIntentRequired(b, v.str(a, "kid"), v.ed(a, "signer"), nil)
	case "sign_progress_step":
		return SignProgressStep(v.obj(a, "step"), v.ed(a, "signer"))
	case "sign_labels":
		return SignLabels(b, v.ed(a, "signer"), nil)
	case "sign_fact":
		return SignFact(b, v.ed(a, "signer"), nil)
	case "sign_offer_set":
		return SignOfferSet(b, v.ed(a, "signer"), nil)
	case "sign_read_receipt":
		prev, _ := a["prev"].(map[string]any)
		return SignReadReceipt(v.ed(a, "signer"), v.obj(a, "grant"), v.str(a, "verb"), v.str(a, "resource"), v.str(a, "purpose"), v.obj(a, "fields"),
			v.strs(a, "labels"), v.num(a, "issued_at"), prev)
	case "sign_template":
		return SignTemplate(v.obj(a, "def"), v.ed(a, "signer"))
	case "sign_tighten":
		return SignTighten(v.obj(a, "overlay"), v.ed(a, "signer"))

	// ---- the facade
	case "parse_limit":
		l, err := ParseLimit(v.str(a, "limit"))
		if err != nil {
			return nil, err
		}
		return ParsedLimitJSON(l), nil
	case "compile_policy":
		p, err := CompilePolicy(PolicyOptions{Permissions: a["permissions"], Limits: vecLimits(a["limits"]), BudgetModel: v.str(a, "budget_model"), Now: v.num(a, "now")})
		if err != nil {
			return nil, err
		}
		return p.JSON(), nil
	case "facade_act":
		return produceFacadeAct(v, a)
	}
	return nil, errors.New("unsupported_op: " + op)
}

func vecLimits(x any) map[string]string {
	m, _ := x.(map[string]any)
	if m == nil {
		return nil
	}
	out := map[string]string{}
	for k, s := range m {
		out[k], _ = s.(string)
	}
	return out
}

func produceRecorder(v *vecArgs, a map[string]any) (any, error) {
	clock := v.list(a, "clock")
	i := 0
	now := func() int64 {
		if len(clock) == 0 {
			v.fail("clock must not be empty")
			return 0
		}
		n, _ := safeInt(clock[min(i, len(clock)-1)])
		i++
		return n
	}
	r, err := NewProvenanceRecorder(ProvenanceRecorderOptions{Mediator: v.str(a, "mediator"), Kid: v.str(a, "kid"), Key: v.ed(a, "key"), Session: v.str(a, "session"), Now: now})
	if err != nil {
		return nil, err
	}
	outs := []any{}
	for _, sv := range v.list(a, "steps") {
		s, _ := sv.(map[string]any)
		var o map[string]any
		switch s["kind"] {
		case "principal":
			o, err = r.Principal(v.str(s, "text"))
		case "tool":
			o, err = r.Tool(v.str(s, "name"), s["output"])
		case "retrieval":
			o, err = r.Retrieval(v.str(s, "source"), s["content"])
		case "web":
			o, err = r.Web(v.str(s, "url"), s["content"])
		default:
			op := v.obj(s, "op")
			params, _ := op["params"].(map[string]any)
			o, err = r.ForAction(Operation{Verb: v.str(op, "verb"), Resource: v.str(op, "resource"), Params: params})
		}
		if err != nil {
			return nil, err
		}
		outs = append(outs, o)
	}
	if len(outs) == 0 {
		return nil, errors.New("produce: no recorder steps")
	}
	return map[string]any{"pin": r.Pin.JSON(), "receipts": outs[:len(outs)-1], "bundle": outs[len(outs)-1]}, nil
}

func produceFacadeAct(v *vecArgs, a map[string]any) (any, error) {
	now := v.num(a, "now")
	ag, err := CreateAgent(AgentOptions{Principal: v.ed(a, "principal"), Holder: v.ed(a, "holder"), Goal: v.str(a, "goal"), GoalSalt: v.str(a, "goal_salt"),
		Permissions: a["permissions"], Limits: vecLimits(a["limits"]), Aud: v.str(a, "aud"), Now: now,
		Provenance: &ProvenanceRecorderOptions{Key: v.ed(a, "recorder_key"), Session: v.str(a, "session"), Now: func() int64 { return now }}})
	if err != nil {
		return nil, err
	}
	if _, has := a["principal_messages"]; has {
		for _, m := range v.strs(a, "principal_messages") {
			if _, err := ag.Provenance.Principal(m); err != nil {
				return nil, err
			}
		}
	}
	if sa, ok := a["sub_agent"].(map[string]any); ok {
		cav, _ := sa["added_caveats"].([]any)
		if ag, err = ag.SubAgent(SubAgentOptions{Holder: v.ed(sa, "holder"), AddedCaveats: cav}); err != nil {
			return nil, err
		}
	}
	act := v.obj(a, "act")
	counter := v.num(act, "counter")
	params, _ := act["params"].(map[string]any)
	r, err := ag.Act(v.str(act, "verb"), v.str(act, "resource"), params, &ActOptions{Counter: &counter, Now: v.num(act, "now"), Nonce: v.str(act, "nonce")})
	if err != nil {
		return nil, err
	}
	chain := make([]any, len(ag.Chain))
	for i, c := range ag.Chain {
		chain[i] = c
	}
	env, _ := ag.Grant["caveats"].([]any)[0].(map[string]any)
	return map[string]any{"grant": ag.Grant, "goal_commit": env["goal_commit"], "chain": chain, "pcactn": r.PCActn, "encoded": r.Encoded, "provenance": r.Provenance}, nil
}

// ParsedLimitJSON is the reference's ParsedLimit object: {amount, unit, periodMs?}.
func ParsedLimitJSON(l ParsedLimit) map[string]any {
	m := map[string]any{"amount": l.Amount, "unit": l.Unit}
	if l.PeriodMs != 0 {
		m["periodMs"] = l.PeriodMs
	}
	return m
}

// JSON is the reference's CompiledPolicy object without its action specs and raw inputs: {predicates, caveats, riskPolicy,
// budgetModel, limits, approximations}.
func (p *CompiledPolicy) JSON() map[string]any {
	lim := map[string]any{}
	for verb, l := range p.Limits {
		lim[verb] = ParsedLimitJSON(l)
	}
	ap := make([]any, len(p.Approximations))
	for i, s := range p.Approximations {
		ap[i] = s
	}
	return map[string]any{"predicates": p.Predicates, "caveats": p.Caveats, "riskPolicy": p.RiskPolicy, "budgetModel": p.BudgetModel, "limits": lim, "approximations": ap}
}
