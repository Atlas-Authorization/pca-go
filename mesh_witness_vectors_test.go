package pca

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
)

// Replay of the mesh issuing and witnessing side against the reference: the domain ops (ref-core-mesh-domain-java) and the witness
// scripts with their stores (the meshWitness section of ref-core-stores-java).

func mwKey(t *testing.T, label string) *KeyPair {
	t.Helper()
	h := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	k, err := KeyPairFromSeed(h[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mwCap(label string, full bool) map[string]any {
	c := map[string]any{"id": label, "caveats": []any{map[string]any{"type": "scope", "actions": []any{label}}}}
	if full {
		c["issuer"], c["holder"] = "iss-"+label, "h"
	}
	return c
}

func mwStrs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func mwThreshold(v any) *int {
	if f, ok := jsNum(v); ok {
		n := int(f)
		return &n
	}
	return nil
}

func mwNum(i int) any { return jsNumber(float64(i)) }

func TestMeshDomainMatchesTheReference(t *testing.T) {
	rsReplaySubset(t, "ref-core-mesh-domain-java.json.gz", map[string]vecFn{"meshDomain": func(a []any) (any, error) {
		doms := map[string]*MeshDomain{}
		ws := map[string]*MeshWitness{}
		heads, binds := map[string]map[string]any{}, map[string]map[string]any{}
		out := []any{}
		for _, oo := range a[0].([]any) {
			op := oo.([]any)
			v, err := func() (v any, err error) {
				defer func() {
					if r := recover(); r != nil {
						err = errors.New("panic")
					}
				}()
				switch op[0] {
				case "domain":
					d := NewMeshDomain(op[1].(string), mwKey(t, "mesh-domain/"+op[2].(string)))
					doms[op[1].(string)] = d
					return d.ID, nil
				case "witness":
					w, e := NewMeshWitness(mwKey(t, "mesh-domain/"+op[2].(string)), MeshWitnessOptions{})
					if e != nil {
						return nil, e
					}
					ws[op[1].(string)] = w
					return w.ID, nil
				case "record":
					i, e := doms[op[1].(string)].Record(mwCap(op[2].(string), true))
					return mwNum(i), e
				case "revoke":
					doms[op[1].(string)].Revoke(op[2].(string))
					return nil, nil
				case "publish":
					var list []*MeshWitness
					for _, w := range mwStrs(op[4]) {
						list = append(list, ws[w])
					}
					ts, _ := jsNum(op[3])
					h, e := doms[op[1].(string)].PublishHead(list, ts, mwThreshold(op[5]))
					if e == nil {
						heads[op[2].(string)] = h
					}
					return h, e
				case "fork":
					h := map[string]any{}
					for k, x := range heads[op[2].(string)] {
						h[k] = x
					}
					h[op[3].(string)] = op[4]
					heads[op[1].(string)] = h
					return nil, nil
				case "enroll":
					b, e := doms[op[1].(string)].Enroll(op[3].(string), op[4].(string))
					binds[op[2].(string)] = b
					return b, e
				case "evidence":
					var b map[string]any
					if op[4] != nil {
						b = binds[op[4].(string)]
					}
					return doms[op[1].(string)].Evidence(mwCap(op[2].(string), true), heads[op[3].(string)], b)
				case "pinProof":
					var pin map[string]any
					if s, ok := op[2].(string); ok {
						pin = heads[s]["head"].(map[string]any)
					} else {
						pin = vecObj(op[2])
					}
					return doms[op[1].(string)].PinProof(pin, heads[op[3].(string)])
				case "nonMembership":
					id, ok := op[2].(string)
					if !ok {
						return nil, errors.New("not a string")
					}
					return doms[op[1].(string)].RevocationSetCopy().NonMembershipProof(id)
				}
				return nil, errors.New("op")
			}()
			if err != nil {
				out = append(out, map[string]any{"$err": "Error"})
			} else {
				out = append(out, v)
			}
		}
		return out, nil
	}})
}

func TestMeshWitnessScriptsMatchTheReference(t *testing.T) {
	rsReplaySubset(t, "ref-core-stores-java.json.gz", map[string]vecFn{"meshWitness": func(a []any) (any, error) {
		stores := map[string]*MemoryMeshWitnessStore{}
		witnesses := map[string]*MeshWitness{}
		domains := map[string]*MeshDomain{}
		out := []any{}
		for _, oo := range a[0].([]any) {
			op := oo.([]any)
			v, err := func() (v any, err error) {
				defer func() {
					if r := recover(); r != nil {
						err = errors.New("panic")
					}
				}()
				switch op[0] {
				case "store":
					stores[op[1].(string)] = &MemoryMeshWitnessStore{}
					return true, nil
				case "witness":
					var o MeshWitnessOptions
					if op[2] != nil {
						o.Store = stores[op[2].(string)]
					}
					w, e := NewMeshWitness(mwKey(t, op[3].(string)), o)
					if e != nil {
						return nil, e
					}
					witnesses[op[1].(string)] = w
					return w.ID, nil
				case "witnessClock":
					now, _ := jsNum(op[3])
					o := MeshWitnessOptions{Clock: func() float64 { return now }}
					if f, ok := jsNum(op[4]); ok {
						o.MaxClockSkewMs = &f
					}
					w, e := NewMeshWitness(mwKey(t, op[2].(string)), o)
					if e != nil {
						return nil, e
					}
					witnesses[op[1].(string)] = w
					return true, nil
				case "restart":
					w, e := NewMeshWitness(mwKey(t, op[3].(string)), MeshWitnessOptions{Store: stores[op[2].(string)]})
					if e != nil {
						return nil, e
					}
					witnesses[op[1].(string)] = w
					return w.ExportState(), nil
				case "domain":
					d := NewMeshDomain(op[1].(string), mwKey(t, op[2].(string)))
					domains[op[1].(string)] = d
					return d.ID, nil
				case "record":
					i, e := domains[op[1].(string)].Record(mwCap(op[2].(string), false))
					return mwNum(i), e
				case "revoke":
					domains[op[1].(string)].Revoke(op[2].(string))
					return nil, nil
				case "publish":
					var list []*MeshWitness
					for _, w := range mwStrs(op[3]) {
						list = append(list, witnesses[w])
					}
					ts, _ := jsNum(op[2])
					return domains[op[1].(string)].PublishHead(list, ts, mwThreshold(op[4]))
				case "lastSeen":
					if h := witnesses[op[1].(string)].LastSeen(op[2].(string)); h != nil {
						return h, nil
					}
					return nil, nil
				case "export":
					return witnesses[op[1].(string)].ExportState(), nil
				case "import":
					return nil, witnesses[op[1].(string)].ImportState(vecObj(op[2]))
				case "load":
					st, e := stores[op[1].(string)].Load()
					if st == nil {
						return nil, e
					}
					return st, e
				case "save":
					return nil, stores[op[1].(string)].Save(vecObj(op[2]))
				case "domainId":
					return domains[op[1].(string)].ID, nil
				}
				return nil, errors.New("op")
			}()
			if err != nil {
				out = append(out, map[string]any{"$err": err.Error()})
			} else {
				out = append(out, v)
			}
		}
		return out, nil
	}})
}

func TestRevocationSetNonMembershipProofsVerify(t *testing.T) {
	set := NewRevocationSet("b", "d", "f", "h", "j")
	for _, id := range []string{"a", "c", "e", "g", "i", "k", "", "key:x"} {
		p, err := set.NonMembershipProof(id)
		if err != nil || !VerifyNonMembership(set.Root(), p, id) {
			t.Fatalf("non-membership of %q: %v", id, err)
		}
	}
	for _, id := range []string{"b", "d", "j"} {
		if _, err := set.NonMembershipProof(id); err == nil {
			t.Fatalf("a revoked id %q has no non-membership proof", id)
		}
	}
	if p, _ := NewRevocationSet().NonMembershipProof("a"); p["size"] != jsNumber(0) {
		t.Fatalf("empty set size %v", p["size"])
	}
}

// bgCodeOf is the reference script's error name: the typed code of a ledger error, RangeError for a refused argument, else Error.
func bgCodeOf(err error) string {
	var le *BudgetLedgerError
	var re *BudgetRangeError
	switch {
	case errors.As(err, &le):
		return le.Code
	case errors.As(err, &re):
		return "RangeError"
	}
	return "Error"
}

// TestBudgetLedgerMatchesTheReference replays the budgetLedger section of the stores corpus, the scoped admission helpers and the
// log anchor included.
func TestBudgetLedgerMatchesTheReference(t *testing.T) {
	rsReplaySubset(t, "ref-core-stores-java.json.gz", map[string]vecFn{"budgetLedger": func(a []any) (any, error) {
		ops := a[0].([]any)
		kv := NewMemoryAtomicKV()
		log, _ := NewKvLedgerStore(NewMemoryAtomicKV())
		reservations := func(v any) []AggregateReservation {
			out := []AggregateReservation{}
			for _, x := range v.([]any) {
				m := vecObj(x)
				out = append(out, AggregateReservation{Key: vecStr(m, "key"), ID: vecStr(m, "id")})
			}
			return out
		}
		var ledger *KvBudgetLedger
		rkey := mwKey(t, "release-signer")
		out := []any{}
		for _, o := range ops {
			op := o.([]any)
			v, err := func() (v any, err error) {
				defer func() {
					if r := recover(); r != nil {
						err = errors.New("panic")
					}
				}()
				switch op[0] {
				case "new":
					ledger, err = NewKvBudgetLedger(kv, op[1] == true)
					return ledger.Durable(), err
				case "snapshot":
					return ledger.Snapshot(op[1].(string))
				case "reserve":
					return ledger.Reserve(op[1].(string), vecObj(op[2]))
				case "start":
					return ledger.Start(op[1].(string), op[2].(string))
				case "commit":
					return ledger.Commit(op[1].(string), op[2].(string))
				case "release":
					return ledger.Release(op[1].(string), op[2].(string), vecObj(op[3]))
				case "expire":
					if !jsIsInt(op[2]) {
						return nil, budRange("not a safe integer")
					}
					now, _ := jsNum(op[2])
					return ledger.Expire(op[1].(string), now)
				case "signRelease":
					if !jsIsInt(op[4]) {
						return nil, budRange("not a safe integer")
					}
					at, _ := jsNum(op[4])
					return SignBudgetRelease(op[1].(string), op[2].(string), op[3].(string), int64(at), rkey)
				case "verifyRelease":
					signer, _ := op[2].(string)
					if signer == "signer" {
						signer = rkey.Public
					}
					return VerifyBudgetRelease(op[1], signer), nil
				case "releaseCommit":
					r := vecObj(op[1])
					d, e1 := BudgetReleaseDigest(r)
					c, e2 := BudgetReleaseCommit(r)
					if e1 != nil || e2 != nil {
						return nil, errors.New("digest")
					}
					return []any{d, c}, nil
				case "scopeKey":
					return BudgetScopeKey(op[1].(string), op[2].(string))
				case "kvSet":
					b, e := json.Marshal(op[2])
					if e != nil {
						return nil, e
					}
					return nil, kv.Update(op[1].(string), func([]byte) []byte { return b })
				case "anchor":
					i, e := AnchorBudgetRelease(log, vecObj(op[1]))
					if e != nil {
						return nil, e
					}
					n, e := log.Size()
					return []any{i, n}, e
				case "admit":
					ad := vecObj(op[1])
					accs, _ := ad["accumulators"].([]any)
					args := AggregateAdmitArgs{IDs: rsStrMap(ad["ids"]), Accumulators: accs, Event: vecObj(ad["event"]),
						Verify: func(state map[string]any) (map[string]any, error) {
							return map[string]any{"allow": ad["allow"], "state": state}, nil
						}}
					if _, has := ad["expiresAt"]; has {
						if !jsIsInt(ad["expiresAt"]) {
							return nil, budRange("not a safe integer")
						}
						at := int64(jsF(ad["expiresAt"]))
						args.ExpiresAt = &at
					}
					if _, has := ad["maxAttempts"]; has {
						if !jsIsInt(ad["maxAttempts"]) {
							return nil, budRange("not a safe integer")
						}
						args.MaxAttempts = int(jsF(ad["maxAttempts"]))
					}
					r, e := AdmitAggregateAction(ledger, args)
					if e != nil {
						return nil, e
					}
					res := map[string]any{"admitted": r.Admitted}
					if r.Reason != "" {
						res["reason"] = r.Reason
					}
					if r.Verdict != nil {
						res["verdict"] = r.Verdict
					}
					if r.Admitted {
						rs := []any{}
						for _, x := range r.Reservations {
							rs = append(rs, map[string]any{"key": x.Key, "id": x.ID})
						}
						res["reservations"], res["state"] = rs, r.State
					}
					return res, nil
				case "startAgg":
					return StartAggregate(ledger, reservations(op[1]))
				case "settleAgg":
					return SettleAggregate(ledger, reservations(op[1]), op[2].(string), nil)
				}
				return nil, errors.New("op")
			}()
			if err != nil {
				out = append(out, map[string]any{"$err": bgCodeOf(err)})
			} else {
				out = append(out, v)
			}
		}
		return out, nil
	}})
}
