package pca

// Replays the grants reference corpus: signing, bundles, the decision log and replay tooling, consistency tokens, shadow rollout,
// list-authorized, the grant management service and its HTTP binding, lease renewal and the lease HTTP routes, blueprint group kill
// and attestation-gated admission. Secret keys cross as LABELS: the key is derived from SHA-256 of "atlas-pca-conformance/" + label.
// Scenario fns replay the reference's scripted operations over the native API; a step the reference throws on yields {"$err": ...}.

import (
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// scenario input, not the generator clock: the reference oracle injects this fixed T0 into its own clock and bakes it into the case data (token iat/exp, budget tau, grant times), so it must not follow the header clockMs (the Date.now default 1.7e12).
const grantsT0 = 1_800_000_000_000

func grantsKP(label string) *KeyPair {
	d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	k, err := KeyPairFromSeed(d[:])
	if err != nil {
		panic(err)
	}
	return k
}

func grantsInt(v any) int64              { f, _ := jsNum(v); return int64(f) }
func grantsF(v any) float64              { return jsF(v) }
func grantsStr(v any) string             { s, _ := v.(string); return s }
func grantsArgStr(a []any, i int) string { return grantsStr(vecArg(a, i)) }

func grantsStrs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, grantsStr(x))
	}
	return out
}

func grantsErr(flag any) any { return map[string]any{"$err": flag} }

func grantsErrCode(err error) any {
	var ge *GrantError
	if errors.As(err, &ge) {
		return grantsErr(ge.Code)
	}
	return grantsErr("x")
}

type grantsTypeError struct{}

func (grantsTypeError) Error() string { return "boom" }
func (grantsTypeError) Name() string  { return "TypeError" }

// grantsResolve replaces "$key:LABEL" strings and {"$sign": {kind, label, fields}} objects, recursively.
func grantsResolve(v any) (any, error) {
	switch t := v.(type) {
	case string:
		if strings.HasPrefix(t, "$key:") {
			return grantsKP(t[5:]).Public, nil
		}
		return t, nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			r, err := grantsResolve(x)
			if err != nil {
				return nil, err
			}
			out[i] = r
		}
		return out, nil
	case map[string]any:
		if s, ok := t["$sign"]; ok {
			sm := vecObj(s)
			fields, err := grantsResolve(sm["fields"])
			if err != nil {
				return nil, err
			}
			kp := grantsKP(vecStr(sm, "label"))
			var rec map[string]any
			switch vecStr(sm, "kind") {
			case "lease":
				rec, err = SignLease(kp, fields)
			case "leaseOver":
				rec, err = SignLeaseUnsafeOverCap(kp, fields)
			case "revocation":
				rec, err = SignLeaseRevocation(kp, fields)
			case "blueprint":
				rec, err = SignBlueprint(kp, fields)
			case "breakglass":
				rec, err = SignBreakGlass(kp, fields)
			case "review":
				rec, err = SignBreakGlassReview(kp, fields)
			default:
				err = errors.New("bad kind")
			}
			if err != nil {
				return nil, err
			}
			return rec, nil
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			r, err := grantsResolve(x)
			if err != nil {
				return nil, err
			}
			out[k] = r
		}
		return out, nil
	}
	return v, nil
}

func grantsSigner(f func(*KeyPair, any) (map[string]any, error)) vecFn {
	return func(a []any) (any, error) {
		m, err := f(grantsKP(grantsArgStr(a, 0)), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		return m, nil
	}
}

func grantsBatchVerdict(v BatchVerdict) any {
	if v.OK {
		return map[string]any{"ok": true, "next": jsNumber(float64(v.Next)), "lastCommit": v.LastCommit}
	}
	return map[string]any{"ok": false, "reason": v.Reason}
}

func grantsCopy(m map[string]any, kv ...any) map[string]any {
	out := make(map[string]any, len(m)+len(kv)/2)
	for k, v := range m {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

// ---- decision log ---------------------------------------------------------------------------------------------------------

func grantsLogScenario(spec map[string]any) (any, error) {
	kp := grantsKP(vecStr(spec, "label"))
	log := NewDecisionLog(kp, vecStrs(spec, "mask"))
	in, _ := spec["records"].([]any)
	recs := []any{}
	for _, r := range in {
		m, _ := r.(map[string]any)
		rec, err := log.Append(m)
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
	}
	now := spec["now"]
	head, err := log.Head(now)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"recs": recs, "head": head, "size": jsNumber(float64(log.Size()))}
	proofs, incl := []any{}, []any{}
	pi, _ := spec["proofs"].([]any)
	for _, x := range pi {
		i := int(grantsInt(x))
		p, perr := log.Proof(i)
		if perr != nil {
			proofs, incl = append(proofs, grantsErr(true)), append(incl, grantsErr(true))
			continue
		}
		proofs = append(proofs, p)
		incl = append(incl, VerifyRecordInclusion(recs[i], p, head, kp.Public))
	}
	out["proofs"], out["incl"] = proofs, incl
	batches := []any{}
	bi, _ := spec["batches"].([]any)
	for _, x := range bi {
		b := vecObj(x)
		from, max := grantsInt(b["from"]), grantsInt(b["max"])
		bt, berr := NextBatch(log, from, max, now)
		last := ""
		if berr == nil && from != 0 {
			if from-1 >= int64(len(recs)) {
				berr = errors.New("no such record")
			} else if c, ok := RecordCommit(recs[from-1]); ok {
				last = c
			} else {
				berr = errors.New("not canonicalizable")
			}
		}
		if berr != nil {
			batches = append(batches, grantsErr(true))
			continue
		}
		tam := bt
		if rl, _ := bt["records"].([]any); len(rl) > 0 {
			first := grantsCopy(rl[0].(map[string]any), "at", jsNumber(1))
			tam = grantsCopy(bt, "records", append([]any{first}, rl[1:]...))
		}
		batches = append(batches, map[string]any{
			"bt":       bt,
			"verdict":  grantsBatchVerdict(VerifyDecisionBatch(bt, from, last, kp.Public)),
			"tampered": grantsBatchVerdict(VerifyDecisionBatch(tam, from, last, kp.Public)),
			"wrong":    grantsBatchVerdict(VerifyDecisionBatch(bt, from, last, grantsKP("zz").Public)),
		})
	}
	out["batches"] = batches
	return out, nil
}

func grantsReplayScenario(spec map[string]any) (any, error) {
	dec := func(t any) func(any) any {
		tm, _ := t.(map[string]any)
		return func(i any) any {
			s, _ := i.(string)
			return tm[s]
		}
	}
	toMaps := func(v any) []map[string]any {
		l, _ := v.([]any)
		out := make([]map[string]any, 0, len(l))
		for _, x := range l {
			m, _ := x.(map[string]any)
			out = append(out, m)
		}
		return out
	}
	revT, _ := spec["revT"].(map[string]any)
	return map[string]any{
		"diff": SemanticDiff(toMaps(spec["cases"]), dec(spec["oldT"]), dec(spec["newT"])),
		"audit": AuditReplay(toMaps(spec["records"]), toMaps(spec["cases"]), func(i any, rev any) any {
			return revT[jsValueString(i)+"@"+jsValueString(rev)]
		}),
	}, nil
}

// ---- consistency tokens ---------------------------------------------------------------------------------------------------

func grantsFreshScenario(spec map[string]any) (any, error) {
	iss := NewFreshAtIssuer(grantsKP(vecStr(spec, "label")), vecStr(spec, "scope"), vecObj(spec["init"]))
	out := []any{}
	var last map[string]any
	steps, _ := spec["steps"].([]any)
	for _, x := range steps {
		s := vecObj(x)
		switch vecStr(s, "op") {
		case "advance":
			tok, err := iss.Advance(vecObj(s["patch"]), s["now"])
			if err != nil {
				out = append(out, grantsErr(true))
				continue
			}
			last = tok
			out = append(out, tok)
		case "check":
			var token any = s["token"]
			if s["token"] == "last" {
				token = nil
				if last != nil {
					token = last
				}
			}
			out = append(out, iss.Check(token, s["now"], s["maxAge"]))
		case "current":
			out = append(out, iss.Current())
		case "tamper":
			if last == nil {
				out = append(out, grantsErr(true))
				continue
			}
			out = append(out, iss.Check(grantsCopy(last, "policy_revision", jsNumber(grantsF(last["policy_revision"])+1)), s["now"], nil))
		}
	}
	return out, nil
}

// ---- shadow ---------------------------------------------------------------------------------------------------------------

func grantsShadowScenario(spec map[string]any) (any, error) {
	log := NewShadowLog(grantsKP(vecStr(spec, "label")))
	table := func(t any) func(any) (any, error) {
		tm, _ := t.(map[string]any)
		return func(in any) (any, error) {
			key, _ := in.(string)
			switch d := tm[key]; d {
			case "throw":
				return nil, errors.New("boom")
			case "junk":
				return "weird", nil
			default:
				return d, nil
			}
		}
	}
	cands := []ShadowCandidate{}
	cl, _ := spec["cands"].([]any)
	for _, c := range cl {
		cm := vecObj(c)
		cands = append(cands, ShadowCandidate{Digest: vecStr(cm, "digest"), Decide: table(cm["T"])})
	}
	out := map[string]any{}
	runs := []any{}
	enforcedDigest := vecStr(spec, "enforcedDigest")
	obs, _ := spec["obs"].([]any)
	for _, o := range obs {
		ob := vecObj(o)
		decision, shadow, err := RunShadow(ob["input"], table(spec["enforcedT"]), cands)
		if err != nil {
			return nil, err
		}
		runs = append(runs, map[string]any{"decision": decision, "shadow": shadow})
		for _, oc := range shadow {
			if _, err := log.Observe(enforcedDigest, vecStr(ob, "action_digest"), decision, oc, ob["at"]); err != nil {
				return nil, err
			}
		}
	}
	stats, diffs := map[string]any{}, map[string]any{}
	order := []string{}
	for _, c := range cands {
		stats[c.Digest] = log.Stats(c.Digest)
		if _, dup := diffs[c.Digest]; !dup {
			order = append(order, c.Digest)
		}
		diffs[c.Digest] = log.Diffs(c.Digest)
	}
	verify := []any{}
	zz := grantsKP("zz").Public
	for _, dg := range order {
		for _, d := range diffs[dg].([]map[string]any) {
			sig, _ := d["sig"].(string)
			bad := sig
			if len(sig) > 0 {
				bad = sig[1:] + "A"
			}
			verify = append(verify, []any{
				VerifyShadowDiff(d, log.Signer()), VerifyShadowDiff(d), VerifyShadowDiff(d, zz),
				VerifyShadowDiff(grantsCopy(d, "sig", bad), log.Signer()),
				VerifyShadowDiff(grantsCopy(d, "at", jsNumber(grantsF(d["at"])+1))),
			})
		}
	}
	out["runs"], out["stats"], out["diffs"], out["verify"], out["signer"] = runs, stats, diffs, verify, log.Signer()
	g := vecObj(spec["gate"])
	if g == nil {
		return out, nil
	}
	principals := []any{}
	for _, p := range grantsStrs(g["principals"]) {
		principals = append(principals, grantsKP(p).Public)
	}
	explanations := []any{}
	el, _ := g["explain"].([]any)
	for _, x := range el {
		e := vecObj(x)
		sx, err := SignWideningExplanation(grantsKP(vecStr(e, "label")), map[string]any{"shadow_digest": e["shadow_digest"], "action_digest": e["action_digest"], "reason_digest": e["reason_digest"]})
		if err != nil {
			return nil, err
		}
		explanations = append(explanations, sx)
	}
	var approval any
	if ap := vecObj(g["approval"]); ap != nil {
		sa, err := SignPromotionApproval(grantsKP(vecStr(ap, "label")), map[string]any{"shadow_digest": ap["shadow_digest"], "enforced_digest": ap["enforced_digest"], "at": ap["at"]})
		if err != nil {
			return nil, err
		}
		approval = sa
	}
	out["explanations"], out["approval"] = explanations, approval
	opts := grantsCopy(vecObj(g["options"]))
	if opts["principals"] == nil {
		opts["principals"] = principals
	}
	if opts["explanations"] == nil {
		opts["explanations"] = explanations
	}
	if approval != nil {
		opts["approval"] = approval
	}
	gate := PromotionGate(log, opts)
	out["gate"] = gate
	if pr := vecObj(spec["promote"]); pr != nil {
		use := gate
		if pr["useGate"] == false {
			use = map[string]any{"ok": false, "code": "bad_input", "reason": "x"}
		}
		p, err := PromoteShadow(vecObj(pr["enforced"]), vecObj(pr["candidate"]), use, pr["now"])
		if err != nil {
			out["promoted"] = grantsErr(true)
		} else {
			out["promoted"] = p
		}
	}
	return out, nil
}

// ---- list-authorized ------------------------------------------------------------------------------------------------------

func grantsListScenario(spec map[string]any) (any, error) {
	acc := NewWindowReadAccumulator(grantsF(spec["cap"]), grantsF(spec["windowMs"]))
	universe := grantsStrs(spec["universe"])
	overfetch, emptyNext := jsTruthy(spec["overfetch"]), jsTruthy(spec["emptyNext"])
	pageOf := func(list []string, q ListPageQuery) ListCandidatePage {
		idx := 0
		if q.Cursor != nil {
			idx, _ = strconv.Atoi(*q.Cursor)
		}
		more := idx+q.Limit < len(list)
		end := idx + q.Limit
		if overfetch {
			end += 3
		}
		if idx > len(list) {
			idx = len(list)
		}
		if end > len(list) {
			end = len(list)
		}
		pg := ListCandidatePage{Objects: append([]string{}, list[idx:end]...)}
		if more {
			s := strconv.Itoa(q.Limit + idx)
			pg.Next = &s
		} else if emptyNext {
			s := ""
			pg.Next = &s
		}
		return pg
	}
	relSpec := vecObj(spec["relation"])
	var relBase *ListRelation
	if relSpec != nil {
		allowed := map[string]bool{}
		for _, o := range grantsStrs(relSpec["allowed"]) {
			allowed[o] = true
		}
		relBase = &ListRelation{Name: vecStr(relSpec, "name"), Check: func(_, _, object string) (bool, error) { return allowed[object], nil }}
		if jsTruthy(relSpec["useList"]) {
			listed := universe
			if _, has := relSpec["listed"]; has && relSpec["listed"] != nil {
				listed = grantsStrs(relSpec["listed"])
			}
			relBase.ListObjects = func(q ListPageQuery) (ListCandidatePage, error) { return pageOf(listed, q), nil }
		}
	}
	var permitted map[string]bool
	if spec["permitted"] != nil {
		permitted = map[string]bool{}
		for _, o := range grantsStrs(spec["permitted"]) {
			permitted[o] = true
		}
	}
	out := []any{}
	var cursor *string
	pages := int(grantsInt(spec["pages"]))
	for p := 0; p < pages; p++ {
		var tm map[string]any
		if t := vecObj(spec["tamper"]); t != nil && int(grantsInt(t["page"])) == p {
			tm = t
		}
		step := 1.0
		if spec["nowStep"] != nil {
			step = grantsF(spec["nowStep"])
		}
		pick := func(k string, def any) any {
			if tm != nil && tm[k] != nil {
				return tm[k]
			}
			return def
		}
		a := ListAuthorizedArgs{
			Subject: grantsStr(pick("subject", spec["subject"])), ResourceType: vecStr(spec, "type"),
			Permits:  func(o string) bool { return permitted == nil || permitted[o] },
			FilterID: grantsStr(pick("filterId", spec["filterId"])), PolicyDigest: vecStr(spec, "policyDigest"), FreshAtDigest: vecStr(spec, "freshAt"),
			Limit: grantsInt(pick("limit", spec["limit"])), Reads: acc, Now: jsNumber(float64(grantsT0) + float64(p)*step),
			Signing: grantsKP(grantsStr(pick("label", spec["label"]))),
		}
		if spec["maxScan"] != nil {
			ms := grantsInt(spec["maxScan"])
			a.MaxScan = &ms
		}
		if !(tm != nil && jsTruthy(tm["dropCursor"])) && cursor != nil {
			c := *cursor
			if tm != nil && tm["cursor"] != nil {
				c = grantsStr(tm["cursor"])
			}
			a.Cursor = &c
		}
		var err error
		if relBase != nil {
			rel := *relBase
			rel.Name = grantsStr(pick("relation", relBase.Name))
			a.Relation = &rel
			if jsTruthy(relSpec["asCandidates"]) {
				a.Candidates, err = CandidatesFromRelation(relBase, grantsStr(spec["subject"]), relBase.Name)
			}
		}
		if err == nil && a.Candidates == nil {
			a.Candidates = func(q ListPageQuery) (ListCandidatePage, error) { return pageOf(universe, q), nil }
		}
		var res *ListAuthorizedResult
		if err == nil {
			res, err = ListAuthorized(a)
		}
		if err != nil {
			code := "x"
			var le *ListError
			if errors.As(err, &le) {
				code = le.Code
			}
			out = append(out, grantsErr(code))
			if tm == nil {
				break
			}
			continue
		}
		out = append(out, res)
		cursor = nil
		if res.NextCursor != "" {
			c := res.NextCursor
			cursor = &c
		}
	}
	return out, nil
}

// ---- grant management -----------------------------------------------------------------------------------------------------

func grantsHTTPReq(s map[string]any) *GrantsHTTPRequest {
	q := map[string]string{}
	for k, v := range vecObj(s["query"]) {
		q[k] = grantsStr(v)
	}
	return &GrantsHTTPRequest{Method: vecStr(s, "method"), Path: vecStr(s, "path"), Query: q, Body: s["body"], Who: s["who"]}
}

func grantsAuthWho(r *GrantsHTTPRequest) map[string]any { m, _ := r.Who.(map[string]any); return m }

func grantsGrantScenario(spec map[string]any) (any, error) {
	store := NewMemoryGrantStore()
	events := []any{}
	gc, nc := 0, 0
	o := GrantServiceOptions{
		Store: store, Now: func() int64 { return grantsT0 },
		NewID: func(kind string) string {
			if kind == "grant" {
				gc++
				return "g_" + strconv.Itoa(gc)
			}
			nc++
			return "n_" + strconv.Itoa(nc)
		},
		OnRevoke: func(ids []string, scope string, root map[string]any) {
			l := make([]any, len(ids))
			for i, s := range ids {
				l[i] = s
			}
			events = append(events, map[string]any{"revoked": l, "scope": scope, "root": root["id"]})
		},
		OnChange: func(kind string, g map[string]any) {
			events = append(events, map[string]any{"change": kind, "id": g["id"], "rev": g["rev"]})
		},
	}
	if jsTruthy(spec["providers"]) {
		o.Providers = &GrantProviders{
			Usage:           func(g map[string]any) any { return map[string]any{"rev": g["rev"]} },
			RemainingBudget: func(map[string]any) any { return map[string]any{"left": jsNumber(5)} },
			Residual:        func(g map[string]any) any { return map[string]any{"id": g["id"]} },
		}
	}
	if jsTruthy(spec["stepUp"]) {
		o.VerifyStepUp = func(ref any, _ map[string]any) bool { return ref == "ok-step" }
	}
	if jsTruthy(spec["validateNeed"]) {
		o.ValidateNeed = func(n map[string]any) string {
			if n["verb"] == "forbidden" {
				return "verb not allowed"
			}
			return ""
		}
	}
	svc := NewGrantService(o)
	handler := GrantResourceHandler(svc, GrantsHTTPOptions{Authenticate: grantsAuthWho})
	sec := func(by string) *KeyPair {
		return grantsKP(map[string]string{"principal": "$P", "holder": "$A", "wrongkey": "$X"}[by])
	}
	out := []any{}
	steps, _ := spec["steps"].([]any)
	for _, raw := range steps {
		rs, err := grantsResolve(raw)
		if err != nil {
			out = append(out, grantsErrCode(err))
			continue
		}
		s := vecObj(rs)
		r, err := func() (any, error) {
			switch vecStr(s, "op") {
			case "register":
				return svc.Register(vecObj(s["grant"]))
			case "list":
				f := GrantListFilter{}
				fm := vecObj(s["filter"])
				if v, ok := fm["principal"]; ok {
					f.Principal = v
				}
				if v, ok := fm["agent"].(string); ok {
					f.Agent = &v
				}
				if v, ok := fm["status"].(string); ok {
					f.Status = &v
				}
				if v, ok := jsNum(fm["limit"]); ok {
					f.Limit = &v
				}
				if v, ok := fm["cursor"].(string); ok {
					f.Cursor = &v
				}
				return svc.List(f)
			case "inspect":
				return svc.Inspect(vecStr(s, "id"))
			case "amend":
				g, err := svc.Inspect(vecStr(s, "id"))
				if err != nil {
					return nil, err
				}
				req := map[string]any{"action": s["action"], "authority": s["authority"]}
				if by := vecStr(s, "by"); by != "none" {
					signedBy := "principal"
					if by == "holder" {
						signedBy = "holder"
					}
					if v, ok := s["signed_by"]; ok && v != nil {
						signedBy = grantsStr(v)
					}
					req["signed_by"] = signedBy
					msg, err := GrantAmendMessage(g["id"], g["rev"], s["action"], s["authority"])
					if err != nil {
						return nil, err
					}
					if req["sig"], err = GrantsSignBody(grantAmendDomain, msg, sec(by)); err != nil {
						return nil, err
					}
				}
				if jsTruthy(s["stepUp"]) {
					req["step_up_ref"] = s["stepUp"]
				}
				r, err := svc.Amend(vecStr(s, "id"), req)
				if err != nil {
					return nil, err
				}
				return map[string]any{"grant": r.Grant, "created": r.Created}, nil
			case "revoke":
				g, err := svc.Inspect(vecStr(s, "id"))
				if err != nil {
					return nil, err
				}
				var auth map[string]any
				switch by := vecStr(s, "by"); by {
				case "admin":
					auth = map[string]any{"admin": true}
				case "noauth":
					auth = map[string]any{}
				default:
					sig, err := GrantsSignBody(grantRevokeDomain, GrantRevokeMessage(g["id"], s["scope"]), sec(by))
					if err != nil {
						return nil, err
					}
					auth = map[string]any{"sig": sig}
				}
				return svc.Revoke(vecStr(s, "id"), s["scope"], auth)
			case "needs":
				return svc.RequestNeeds(vecStr(s, "id"), s["needs"])
			case "approve":
				nid, err := svc.NeedGrantID(vecStr(s, "needId"))
				if err != nil {
					return nil, err
				}
				g, err := svc.Inspect(nid)
				if err != nil {
					return nil, err
				}
				sig, err := GrantsSignBody(needApproveDomain, NeedApproveMessage(s["needId"], nid, g["rev"], s["approved"]), sec(vecStr(s, "by")))
				if err != nil {
					return nil, err
				}
				r, err := svc.ApproveNeeds(vecStr(s, "needId"), s["approved"], sig, s["stepUp"])
				if err != nil {
					return nil, err
				}
				return map[string]any{"grant": r.Grant, "created": r.Created}, nil
			case "deny":
				return nil, svc.DenyNeeds(vecStr(s, "needId"))
			case "http":
				res := handler(grantsHTTPReq(s))
				return map[string]any{"status": jsNumber(float64(res.Status)), "body": res.Body}, nil
			}
			return nil, errors.New("bad op")
		}()
		if err != nil {
			out = append(out, grantsErrCode(err))
			continue
		}
		out = append(out, r)
	}
	all, _ := store.List()
	grantsSortByID(all)
	return map[string]any{"steps": out, "events": events, "grants": all}, nil
}

// ---- leases ---------------------------------------------------------------------------------------------------------------

func grantsAcceptJSON(r LeaseAcceptResult) any {
	if r.Ok {
		return map[string]any{"ok": true, "replaced": r.Replaced, "seq": jsNumber(float64(r.Seq))}
	}
	out := map[string]any{"ok": false, "code": r.Code}
	if r.Reason != "" {
		out["reason"] = r.Reason
	}
	return out
}

func grantsDecisionJSON(d LeaseDecision) any {
	m := map[string]any{"decision": d.Decision}
	if d.Decision == "allow" {
		m["lease_id"], m["expires_at"] = d.LeaseID, jsNumber(float64(d.ExpiresAt))
		return m
	}
	m["code"] = d.Code
	if d.LeaseID != "" {
		m["lease_id"] = d.LeaseID
	}
	return m
}

func grantsLeaseScenario(spec map[string]any) (any, error) {
	pol := LeasePolicy{Authorities: []string{grantsKP("auth").Public}}
	if p := vecObj(spec["policy"]); p != nil {
		if v, ok := jsNum(p["minApprovals"]); ok {
			n := int64(v)
			pol.MinApprovals = &n
		}
		if _, ok := p["eligibleApprovers"]; ok {
			pol.Eligible = grantsStrs(p["eligibleApprovers"])
		}
		if v, ok := jsNum(p["maxTtlCeiling"]); ok {
			n := int64(v)
			pol.MaxTtlCeiling = &n
		}
	}
	shards := 4
	if spec["shards"] != nil {
		shards = int(grantsInt(spec["shards"]))
	}
	reg := NewLeaseRegistryShards(pol, MemoryLeaseKv(), shards)
	reg.clock = func() int64 { return grantsT0 }
	handler := LeaseResourceHandler(reg, LeaseHTTPOptions{Authenticate: grantsAuthWho, Now: func() int64 { return grantsT0 }})
	out := []any{}
	steps, _ := spec["steps"].([]any)
	for _, raw := range steps {
		rs, err := grantsResolve(raw)
		if err != nil {
			out = append(out, grantsErrCode(err))
			continue
		}
		s := vecObj(rs)
		r, err := func() (any, error) {
			switch vecStr(s, "op") {
			case "accept":
				chain := []string{}
				cl, _ := s["chain"].([]any)
				for _, c := range cl {
					if cs, ok := c.(string); ok {
						chain = append(chain, cs)
					} else {
						chain = append(chain, "\x00non-string")
					}
				}
				return grantsAcceptJSON(reg.Accept(s["lease"], chain)), nil
			case "revoke":
				code, n := reg.Revoke(s["rev"])
				if code != "" {
					return map[string]any{"ok": false, "code": code}, nil
				}
				return map[string]any{"ok": true, "revoked": jsNumber(float64(n))}, nil
			case "get":
				return reg.Get(vecStr(s, "id")), nil
			case "history":
				h, err := reg.History(vecStr(s, "id"))
				if err != nil {
					return nil, err
				}
				return GrantsLeaseHistoryJSON(h), nil
			case "shardRevs":
				return reg.ShardRevocations(int(grantsInt(s["i"])))
			case "renew":
				label := "auth"
				if s["label"] != nil {
					label = grantsStr(s["label"])
				}
				ro := LeaseRenewOptions{Now: s["now"], Increment: s["increment"], JustificationDigest: grantsStr(s["just"])}
				if _, has := s["approvers"]; has {
					ro.Approvers = s["approvers"]
				}
				if vs, has := s["vetoSeq"]; has && vs != nil {
					at := grantsF(vs)
					ro.Veto = func(c map[string]any) bool { return grantsF(c["seq"]) >= at }
				}
				if cl, ok := s["chain"].([]any); ok {
					ro.Chain = grantsStrs(cl)
				}
				return RenewLease(grantsKP(label), reg, vecStr(s, "id"), ro), nil
			case "check":
				return grantsDecisionJSON(CheckLease(s["lease"], reg, s["now"])), nil
			case "http":
				res := handler(grantsHTTPReq(s))
				return map[string]any{"status": jsNumber(float64(res.Status)), "body": res.Body}, nil
			}
			return nil, errors.New("bad op")
		}()
		if err != nil {
			out = append(out, grantsErrCode(err))
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// ---- blueprints -----------------------------------------------------------------------------------------------------------

func grantsBlueprintScenario(spec map[string]any) (any, error) {
	reg := NewBlueprintRegistry([]string{grantsKP("op").Public}, MemoryBlueprintKv())
	adm := NewAdmissionRegistry()
	revoked := []any{}
	fresh := NewFreshAtIssuer(grantsKP("iss"), "scope", map[string]any{
		"revocation_epoch": jsNumber(0), "ledger_tree_size": jsNumber(0), "budget_version": jsNumber(0), "policy_revision": jsNumber(0), "policy_digest": "pd"})
	out := []any{}
	steps, _ := spec["steps"].([]any)
	for _, raw := range steps {
		rs, err := grantsResolve(raw)
		if err != nil {
			out = append(out, grantsErrCode(err))
			continue
		}
		s := vecObj(rs)
		r, err := func() (any, error) {
			switch vecStr(s, "op") {
			case "accept":
				code, replaced := reg.Accept(s["bp"])
				if code != "" {
					return map[string]any{"ok": false, "code": code}, nil
				}
				return map[string]any{"ok": true, "replaced": replaced}, nil
			case "epoch":
				return jsNumber(float64(reg.Epoch())), nil
			case "kill":
				label := "op"
				if s["label"] != nil {
					label = grantsStr(s["label"])
				}
				o := GroupKillOptions{Now: s["now"], Reason: grantsStr(s["reason"])}
				if jsTruthy(s["revoker"]) {
					o.Revoke = func(in map[string]any) error { revoked = append(revoked, in); return nil }
				}
				if jsTruthy(s["fresh"]) {
					o.FreshAt = fresh
				}
				return GroupKill(grantsKP(label), reg, vecStr(s, "key"), o)
			case "revoked":
				return revoked, nil
			case "admit", "admitCheck":
				bp, err := reg.Get(vecStr(s, "key"))
				if err != nil {
					return nil, err
				}
				if bp == nil {
					return nil, errors.New("Cannot read properties of undefined")
				}
				if vecStr(s, "op") == "admit" {
					return true, adm.Admit(vecStr(s, "instance"), bp, s["until"])
				}
				return adm.Checker(s["now"])(vecStr(s, "instance"), bp), nil
			case "admitRevoke":
				return adm.Revoke(vecStr(s, "instance"), vecStr(s, "key")), nil
			}
			return nil, errors.New("bad op")
		}()
		if err != nil {
			out = append(out, grantsErrCode(err))
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

func TestGrantsVectors(t *testing.T) {
	fns := map[string]vecFn{
		"signerOf": func(a []any) (any, error) { return grantsKP(grantsArgStr(a, 0)).Public, nil },
		"signBody": func(a []any) (any, error) {
			return GrantsSignBody(grantsArgStr(a, 0), vecArg(a, 1), grantsKP(grantsArgStr(a, 2)))
		},
		"verifyBody": func(a []any) (any, error) {
			return GrantsVerifyBody(grantsArgStr(a, 0), vecArg(a, 1), grantsArgStr(a, 2), vecArg(a, 3)), nil
		},
		"signLease":              grantsSigner(SignLease),
		"signLeaseUnsafeOverCap": grantsSigner(SignLeaseUnsafeOverCap),
		"signLeaseRevocation":    grantsSigner(SignLeaseRevocation),
		"signBlueprint":          grantsSigner(SignBlueprint),
		"signBreakGlass":         grantsSigner(SignBreakGlass),
		"signBreakGlassReview":   grantsSigner(SignBreakGlassReview),
		"signBundle": func(a []any) (any, error) {
			m, err := SignBundle(vecArg(a, 0), grantsKP(grantsArgStr(a, 1)))
			if err != nil {
				return nil, err
			}
			return m, nil
		},
		"assembleBundle": func(a []any) (any, error) { return AssembleBundle(vecArg(a, 0), vecArg(a, 1)), nil },
		"maskRecord": func(a []any) (any, error) {
			m, err := MaskRecord(vecObj(vecArg(a, 0)), vecStrs(map[string]any{"c": vecArg(a, 1)}, "c"))
			if err != nil {
				return nil, err
			}
			return m, nil
		},
		"logScenario":    func(a []any) (any, error) { return grantsLogScenario(vecObj(vecArg(a, 0))) },
		"replayScenario": func(a []any) (any, error) { return grantsReplayScenario(vecObj(vecArg(a, 0))) },
		"mergeFreshAt": func(a []any) (any, error) {
			return MergeFreshAt(vecObj(vecArg(a, 0)), vecObj(vecArg(a, 1))), nil
		},
		"gateDecision": func(a []any) (any, error) {
			return GateDecision(grantsArgStr(a, 0), vecObj(vecArg(a, 1))), nil
		},
		"freshScenario":     func(a []any) (any, error) { return grantsFreshScenario(vecObj(vecArg(a, 0))) },
		"shadowScenario":    func(a []any) (any, error) { return grantsShadowScenario(vecObj(vecArg(a, 0))) },
		"listScenario":      func(a []any) (any, error) { return grantsListScenario(vecObj(vecArg(a, 0))) },
		"grantScenario":     func(a []any) (any, error) { return grantsGrantScenario(vecObj(vecArg(a, 0))) },
		"leaseScenario":     func(a []any) (any, error) { return grantsLeaseScenario(vecObj(vecArg(a, 0))) },
		"blueprintScenario": func(a []any) (any, error) { return grantsBlueprintScenario(vecObj(vecArg(a, 0))) },
		"windowAcc": func(a []any) (any, error) {
			acc := NewWindowReadAccumulator(grantsF(vecArg(a, 0)), grantsF(vecArg(a, 1)))
			out := []any{}
			ops, _ := vecArg(a, 2).([]any)
			for _, x := range ops {
				op := vecObj(x)
				out = append(out, acc.Charge(vecStr(op, "key"), grantsF(op["units"]), grantsF(op["now"])))
			}
			return out, nil
		},
		"admitWithEvidence": func(a []any) (any, error) {
			e := vecArg(a, 1)
			return AdmitWithEvidence(vecObj(vecArg(a, 0)), func() (any, error) {
				if m, ok := e.(map[string]any); ok && jsTruthy(m["$throw"]) {
					return nil, grantsTypeError{}
				}
				return e, nil
			}), nil
		},
	}
	replayVectors(t, "ref-grants.json.gz", fns)
}
