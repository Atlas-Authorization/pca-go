package pca

import (
	"errors"
	"math"
	"strconv"
	"testing"
)

// Replay of bond settlement against the reference (ref-core-bond-settlement-java): the money arithmetic, the slash split, bond
// sizing, evidence digests, record checks and commitments, the claim / fraud-proof / dispute judgments and scripted store-ledger
// sequences. Plus the bondStore section of ref-core-stores-java.

const bondSettlementCorpusCases = 1451

func bvSplitPolicy(v any) SlashSplitPolicy {
	m := vecObj(v)
	return SlashSplitPolicy{ChallengerBps: jsF(m["challengerBps"]), VictimBps: jsF(m["victimBps"])}
}

func bvStrPtr(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

func bvBondPolicy(v any) BondPolicy {
	m := vecObj(v)
	p := BondPolicy{Floor: jsF(m["floor"]), K: jsF(m["k"]), MaxOpenClaims: 100, MaxOpenAmount: math.Inf(1)}
	if f, ok := jsNum(m["maxOpenClaims"]); ok {
		p.MaxOpenClaims = f
	}
	if f, ok := jsNum(m["maxOpenAmount"]); ok {
		p.MaxOpenAmount = f
	}
	switch c := m["curve"].(type) {
	case map[string]any:
		kind, _ := c["kind"].(string)
		p.Curve = &BondCurve{Kind: kind, Gamma: jsF(c["gamma"])}
		if tiers, ok := c["tiers"].([]any); ok {
			for _, t := range tiers {
				tm := vecObj(t)
				p.Curve.Tiers = append(p.Curve.Tiers, BondTier{UpTo: jsF(tm["upTo"]), MarginalK: jsF(tm["marginalK"])})
			}
		}
	case string:
		if c != "" {
			p.Curve = &BondCurve{}
		}
	}
	return p
}

func bvWindowPolicy(v any) *ChallengeWindowPolicy {
	m := vecObj(v)
	if m == nil {
		return nil
	}
	return &ChallengeWindowPolicy{MinWindowMs: jsF(m["minWindowMs"]), MaxWindowMs: jsF(m["maxWindowMs"]), MaxSkewMs: jsF(m["maxSkewMs"])}
}

func bvOracle(table any) ObjectiveOracle {
	t := vecObj(table)
	if t == nil {
		return nil
	}
	return func(input string, _ map[string]any) map[string]any { return vecObj(t[input]) }
}

func bvOptNum(v any) *float64 {
	if f, ok := jsNum(v); ok {
		return &f
	}
	return nil
}

func bvPins(v any) []map[string]string {
	// the reference takes a pin policy {pqPins: {guardian key -> pinned post-quantum key}}; the native takes the inner table
	if o, ok := v.(map[string]any); ok {
		if inner, has := o["pqPins"]; has {
			v = inner
		}
	}
	if m := rsStrMap(v); m != nil {
		return []map[string]string{m}
	}
	return nil
}

// bvResolve replaces every "@name" string by the fixture of that name (an unknown name is an absent value).
func bvResolve(fx map[string]any, v any) any {
	switch t := v.(type) {
	case string:
		if len(t) > 0 && t[0] == '@' {
			return normalizeJSON(fx[t[1:]])
		}
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = bvResolve(fx, x)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = bvResolve(fx, x)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	}
	return v
}

func bvSlashParams(fx map[string]any, raw any, idKey string) SlashParams {
	q := vecObj(bvResolve(fx, raw))
	id, _ := q[idKey].(string)
	treasury, _ := q["treasury"].(string)
	comp, _ := q["compensationAccount"].(string)
	revoked, _ := q["revokedCapId"].(string)
	p := SlashParams{ClaimID: id, Claim: vecObj(q["claim"]), Treasury: treasury, ChallengerAccount: bvStrPtr(q["challengerAccount"]),
		CompensationAccount: comp, FraudProof: q["fraudProof"], Grant: vecObj(q["grant"]), OpenSnapshot: q["openSnapshot"],
		Dispute: q["dispute"], Oracle: bvOracle(q["oracleTable"]), RMargin: bvOptNum(q["rMargin"]), RevokedCapID: revoked}
	if sp, ok := q["splitPolicy"]; ok && sp != nil {
		pol := bvSplitPolicy(sp)
		p.SplitPolicy = &pol
	}
	return p
}

func bvLedger(t *testing.T, a []any) (any, error) {
	fx, cfg := vecObj(a[0]), vecObj(a[1])
	kv := NewMemoryAtomicKV()
	store, err := NewKvBondStore(kv)
	if err != nil {
		return nil, err
	}
	clock := 1_800_000_000_000.0
	o := StoreBondLedgerOptions{Store: store, Clock: func() float64 { return clock }}
	o.Guardian = mwKey(t, "bond/guardian")
	if f, ok := jsNum(cfg["epoch"]); ok {
		e := int64(f)
		o.GuardianEpoch = &e
	}
	if s, ok := cfg["escrow"].(string); ok {
		o.EscrowAccount = s
	}
	if v, ok := cfg["bondPolicy"]; ok {
		p := bvBondPolicy(v)
		o.BondPolicy = &p
	}
	if v, ok := cfg["splitPolicy"]; ok {
		p := bvSplitPolicy(v)
		o.SlashSplitPolicy = &p
	}
	if w := vecObj(cfg["windowMs"]); w != nil {
		o.WindowPolicy = &ChallengeWindowPolicy{MinWindowMs: jsF(w["min"]), MaxWindowMs: jsF(w["max"]), MaxSkewMs: jsF(w["skew"])}
	}
	ledger, err := NewStoreBondLedger(o)
	if err != nil {
		return nil, err
	}
	return stScript(a[2], func(op []any) (any, error) {
		str := func(i int) string { s, _ := vecArg(op, i).(string); return s }
		switch op[0] {
		case "clock":
			clock = jsF(op[1])
			return nil, nil
		case "deposit":
			return ledger.Deposit(str(1), jsF(op[2]))
		case "balance":
			return ledger.BalanceOf(str(1))
		case "status":
			return ledger.BondStatus(str(1))
		case "bond":
			b, err := ledger.GetBond(str(1))
			if b == nil {
				return nil, err
			}
			return b, err
		case "challenge":
			return ledger.ChallengeStatus(str(1))
		case "pub":
			return ledger.GuardianPublicKey(), nil
		case "openClaim":
			p := vecObj(bvResolve(fx, op[1]))
			signer, _ := p["signerPublic"].(string)
			dep, _ := p["depositor"].(string)
			return ledger.OpenClaim(vecObj(p["claim"]), vecObj(p["pcactn"]), signer, jsF(p["amount"]), dep, bvOptNum(p["exposure"]))
		case "openBond":
			p := vecObj(bvResolve(fx, op[1]))
			id, _ := p["claimId"].(string)
			dep, _ := p["depositor"].(string)
			return ledger.OpenBond(id, jsF(p["amount"]), dep, bvOptNum(p["exposure"]))
		case "release":
			return ledger.Release(str(1))
		case "releaseUnreg":
			return ledger.ReleaseUnregistered(str(1))
		case "slash":
			return ledger.SlashBond(bvSlashParams(fx, op[1], "claimId"))
		case "slashDispute":
			return ledger.SlashBondOnDispute(bvSlashParams(fx, op[1], "claimId"))
		case "slashRevoke":
			return ledger.SlashBondOnRevocation(bvSlashParams(fx, op[1], "claimId"))
		case "slashCounter":
			return ledger.SlashCounterBond(bvSlashParams(fx, op[1], "counterBondId"))
		case "kvSet":
			return nil, stKvSet(kv, BondDocKey, op[1])
		case "kvGet":
			return stKvGet(kv, BondDocKey)
		}
		return nil, errors.New("op")
	}), nil
}

func TestBondSettlementMatchesTheReference(t *testing.T) {
	count := 0
	counted := func(f vecFn) vecFn {
		return func(a []any) (any, error) { count++; return f(a) }
	}
	str := func(v any) string { s, _ := v.(string); return s }
	fns := map[string]vecFn{
		"computeSlashSplit": func(a []any) (any, error) {
			dest := vecObj(a[2])
			ca := bvStrPtr(dest["challengerAccount"])
			cv, has := dest["challengerAccount"]
			absent := ca == nil && (!has || cv != nil) // JS: only an explicit null is anonymous; undefined is an account that serialises to nothing
			if absent {
				empty := ""
				ca = &empty
			}
			r, err := ComputeSlashSplit(jsF(a[0]), bvSplitPolicy(a[1]), ca, str(dest["victimAccount"]), str(dest["treasuryAccount"]))
			if absent && r != nil {
				delete(r, "challengerAccount")
			}
			return r, err
		},
		"quantizeUp": func(a []any) (any, error) { return QuantizeUp(jsF(a[0])), nil },
		"toMicros": func(a []any) (any, error) {
			m, ok := ToMicros(jsF(a[0]))
			if !ok {
				return nil, nil
			}
			return map[string]any{"$bigint": strconv.FormatInt(m, 10)}, nil
		},
		"exactAdd": func(a []any) (any, error) { return ExactAdd(jsF(a[0]), jsF(a[1]), int(jsF(a[2]))), nil },
		"applyBondMoves": func(a []any) (any, error) {
			bal := vecObj(a[0])
			return ApplyBondMoves(func(acct string) float64 {
				if f, ok := jsNum(bal[acct]); ok {
					return f
				}
				return 0
			}, bsMovesOf(a[1]))
		},
		"bondAmount":               func(a []any) (any, error) { return BondAmount(bvBondPolicy(a[0]), jsF(a[1])) },
		"settlementEvidenceDigest": func(a []any) (any, error) { return SettlementEvidenceDigest(vecObj(a[0]), vecObj(a[1])) },
		"revocationEvidenceDigest": func(a []any) (any, error) { return RevocationEvidenceDigest(vecObj(a[0]), str(a[1])) },
		"disputeEvidenceDigest":    func(a []any) (any, error) { return DisputeEvidenceDigest(vecObj(a[0]), vecObj(a[1])) },
		"verifySettlement":         func(a []any) (any, error) { return VerifySettlement(a[0], str(a[1]), bvPins(vecArg(a, 2))...), nil },
		"settlementRecordDigest":   func(a []any) (any, error) { return SettlementRecordDigest(vecObj(a[0])) },
		"settlementCommit":         func(a []any) (any, error) { return SettlementCommit(str(a[0]), vecObj(a[1])) },
		"verifySettlementCommit":   func(a []any) (any, error) { return VerifySettlementCommit(str(a[0]), str(a[1]), vecObj(a[2])), nil },
		"verifyClaim": func(a []any) (any, error) {
			return VerifyClaim(a[0], vecObj(a[1]), str(a[2]), jsF(a[3]), bvWindowPolicy(vecArg(a, 4))), nil
		},
		"verifyFraudProof": func(a []any) (any, error) {
			return VerifyFraudProof(vecObj(a[0]), a[1], vecObj(a[2]), a[3]), nil
		},
		"adjudicateDispute": func(a []any) (any, error) {
			return AdjudicateDispute(vecObj(a[0]), a[1], vecObj(a[2]), a[3], bvOracle(vecArg(a, 4)), bvOptNum(vecArg(a, 5))), nil
		},
		"ledger": func(a []any) (any, error) { return bvLedger(t, a) },
	}
	for k, f := range fns {
		fns[k] = counted(f)
	}
	replayVectors(t, "ref-core-bond-settlement-java.json.gz", fns)
	if count != bondSettlementCorpusCases {
		t.Fatalf("replayed %d cases, the corpus has %d", count, bondSettlementCorpusCases)
	}
}

func TestBondStoreMatchesTheReference(t *testing.T) {
	rsReplaySubset(t, "ref-core-stores-java.json.gz", map[string]vecFn{"bondStore": func(a []any) (any, error) {
		kv := NewMemoryAtomicKV()
		s, err := NewKvBondStore(kv)
		if err != nil {
			return nil, err
		}
		return stScript(a[0], func(op []any) (any, error) {
			switch op[0] {
			case "read":
				q := map[string]any{"claimId": op[1]}
				if dep, ok := vecArg(op, 2).(string); ok {
					q["depositor"] = dep
				}
				return s.Read(q)
			case "commit":
				return s.Commit(vecObj(op[1]), jsF(vecArg(op, 2)))
			case "deposit":
				acct, _ := op[1].(string)
				return s.Deposit(acct, jsF(vecArg(op, 2)))
			case "kvSet":
				return nil, stKvSet(kv, BondDocKey, op[1])
			case "kvGet":
				return stKvGet(kv, BondDocKey)
			}
			return nil, errors.New("op")
		}), nil
	}})
}

func TestDisputeGameAndCapitalPool(t *testing.T) {
	claim := map[string]any{"pcactn_digest": "d", "bond_ref": "b", "claimed_r": jsNumber(0.1)}
	oracle := func(input string, _ map[string]any) map[string]any {
		return map[string]any{"input": input, "value": jsNumber(0.9), "valid": true}
	}
	for name, game := range map[string]any{
		"malformed":     nil,
		"another claim": map[string]any{"pcactn_digest": "x", "bond_ref": "b"},
		"no steps":      map[string]any{"pcactn_digest": "d", "bond_ref": "b", "steps": []any{}},
		"unknown input": map[string]any{"pcactn_digest": "d", "bond_ref": "b", "steps": []any{"nonsense"}},
		"short traces":  map[string]any{"pcactn_digest": "d", "bond_ref": "b", "steps": []any{"blastRadius"}, "defender": []any{}, "challenger": []any{}},
	} {
		r := AdjudicateDisputeGame(claim, game, map[string]any{}, map[string]any{}, oracle, nil)
		v := vecObj(r["verdict"])
		if r["converged"] != false || v["outcome"] != "indeterminate" || v["fraudulent"] != false || v["slashCounterBond"] != false {
			t.Fatalf("%s: a game that cannot be judged must slash nobody: %v", name, r)
		}
	}
	snap := map[string]any{"now": 5, "nested": map[string]any{"a": []any{1, "x"}}}
	frozen, err := FreezeOpenSnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	snap["nested"].(map[string]any)["a"].([]any)[1] = "changed"
	if got := vecObj(frozen["nested"])["a"].([]any)[1]; got != "x" {
		t.Fatalf("the frozen snapshot follows the live one: %v", got)
	}

	if _, err := NewInsuranceCapitalPool(-1); err == nil {
		t.Fatal("negative capital must be refused")
	}
	pool, _ := NewInsuranceCapitalPool(100)
	score := 1.0
	out, err := pool.CollectPremium(&score, 1000, nil)
	if err != nil || pool.PremiumsIn() != 10 || pool.Balance() != 110 || vecObj(out["pricing"])["declined"] != false {
		t.Fatalf("premium: %v %v", out, err)
	}
	if _, err := pool.CollectPremium(nil, 1000, nil); err != nil || pool.PremiumsIn() != 10 {
		t.Fatal("a declined quote must collect nothing")
	}
	if _, err := pool.PayClaim(500); err == nil || pool.CanCover(500) {
		t.Fatal("a claim above the capital must be refused")
	}
	if st, err := pool.PayClaim(60); err != nil || pool.Balance() != 50 || pool.PayoutsOut() != 60 || jsF(st["balance"]) != 50 {
		t.Fatalf("payout: %v %v", st, err)
	}
	log, _ := MerkleLogOf(nil)
	rec := map[string]any{"claimId": "c", "action": "open", "amount": jsNumber(1), "from": "a", "to": "escrow", "at": jsNumber(1), "evidenceDigest": "", "sig": "s"}
	anchor, err := AppendSettlement(log, rec, "")
	if err != nil || anchor.Index != 0 || anchor.Salt == "" || !VerifySettlementCommit(anchor.Commit, anchor.Salt, rec) || log.Size() != 1 {
		t.Fatalf("anchor: %+v %v", anchor, err)
	}
}
