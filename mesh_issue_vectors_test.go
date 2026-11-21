package pca

import (
	"errors"
	"math"
	"testing"
)

// Replay of the mesh issuing side and the federation primitives against the reference (ref-mesh-issue), every case: the constants,
// the public effective authority, the size and latency models, the worked example and the fork demonstration, scripted domain and
// witness lifecycles (stores, clocks, forks, restarts), capability translation with its verifier, the federated budget tree and
// the cross-reference commitments. Results compare as JSON values, refusal reasons and script errors included; a reference throw
// requires a refusal. Keys derive from the seed labels, so heads, cosignatures and proofs compare byte for byte.

// mivFailStore is a witness store whose Save fails once a number of saves have succeeded.
type mivFailStore struct {
	inner MemoryMeshWitnessStore
	saves int
	after int
}

func (s *mivFailStore) Load() (map[string]any, error) { return s.inner.Load() }

func (s *mivFailStore) Save(state map[string]any) error {
	s.saves++
	if s.saves > s.after {
		return errors.New("disk")
	}
	return s.inner.Save(state)
}

func mivNum(v any) float64 {
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

func mivOptNum(m map[string]any, k string) *float64 {
	v, has := m[k]
	if !has {
		return nil
	}
	f := mivNum(v)
	return &f
}

func mivMaps(l []map[string]any) []any {
	out := make([]any, len(l))
	for i, m := range l {
		out[i] = m
	}
	return out
}

func mivHeadMaps(m map[string]map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// mivScript runs one scripted lifecycle: one result per op, a refusal as {$err: message}.
func mivScript(t *testing.T, ops []any) []any {
	doms, ws := map[string]*MeshDomain{}, map[string]*MeshWitness{}
	heads, binds := map[string]map[string]any{}, map[string]map[string]any{}
	stores := map[string]MeshWitnessStore{}
	unknown := func(name any) error { return errors.New("unknown name " + jsValueString(name)) }
	dom := func(name any) (*MeshDomain, error) {
		s, _ := name.(string)
		if d, ok := doms[s]; ok {
			return d, nil
		}
		return nil, unknown(name)
	}
	wit := func(name any) (*MeshWitness, error) {
		s, _ := name.(string)
		if w, ok := ws[s]; ok {
			return w, nil
		}
		return nil, unknown(name)
	}
	head := func(name any) (map[string]any, error) {
		s, _ := name.(string)
		if h, ok := heads[s]; ok {
			return h, nil
		}
		return nil, unknown(name)
	}
	store := func(name any) (MeshWitnessStore, error) {
		s, _ := name.(string)
		if st, ok := stores[s]; ok {
			return st, nil
		}
		return nil, unknown(name)
	}
	size := func(v any) (int, error) {
		f, ok := jsNum(v)
		if !ok || f != math.Trunc(f) || math.Abs(f) > 1e9 {
			return 0, errors.New("consistencyProof: invalid sizes")
		}
		return int(f), nil
	}
	str := func(v any) string { s, _ := v.(string); return s }
	run := func(op []any) (any, error) {
		switch op[0] {
		case "domain":
			d := NewMeshDomain(str(op[1]), mwKey(t, "mesh-issue/d/"+str(op[2])))
			doms[str(op[1])] = d
			return d.ID, nil
		case "witness":
			w, err := NewMeshWitness(mwKey(t, "mesh-issue/w/"+str(op[2])), MeshWitnessOptions{})
			if err != nil {
				return nil, err
			}
			ws[str(op[1])] = w
			return w.ID, nil
		case "witnessOpts":
			x := vecObj(vecArg(op, 3))
			var o MeshWitnessOptions
			if name := str(x["store"]); name != "" {
				st, err := store(name)
				if err != nil {
					return nil, err
				}
				o.Store = st
			}
			if x["clock"] != nil {
				clock := mivNum(x["clock"])
				o.Clock = func() float64 { return clock }
			}
			if x["skew"] != nil {
				skew := mivNum(x["skew"])
				o.MaxClockSkewMs = &skew
			}
			w, err := NewMeshWitness(mwKey(t, "mesh-issue/w/"+str(op[2])), o)
			if err != nil {
				return nil, err
			}
			ws[str(op[1])] = w
			return w.ID, nil
		case "store":
			stores[str(op[1])] = &MemoryMeshWitnessStore{}
			return true, nil
		case "failStore":
			stores[str(op[1])] = &mivFailStore{after: int(mivNum(op[2]))}
			return true, nil
		case "storeLoad":
			st, err := store(op[1])
			if err != nil {
				return nil, err
			}
			state, err := st.Load()
			if err != nil || state == nil {
				return nil, err
			}
			return state, nil
		case "record":
			d, err := dom(op[1])
			if err != nil {
				return nil, err
			}
			i, err := d.Record(mwCap(str(op[2]), true))
			return mwNum(i), err
		case "revoke":
			d, err := dom(op[1])
			if err != nil {
				return nil, err
			}
			d.Revoke(str(op[2]))
			return nil, nil
		case "publish":
			d, err := dom(op[1])
			if err != nil {
				return nil, err
			}
			var list []*MeshWitness
			for _, name := range op[4].([]any) {
				w, err := wit(name)
				if err != nil {
					return nil, err
				}
				list = append(list, w)
			}
			h, err := d.PublishHead(list, mivNum(op[3]), mwThreshold(op[5]))
			if err != nil {
				return nil, err
			}
			heads[str(op[2])] = h
			return h, nil
		case "fork", "forkHead":
			h, err := head(op[2])
			if err != nil {
				return nil, err
			}
			next := copyMap(h)
			if op[0] == "fork" {
				next[str(op[3])] = op[4]
			} else {
				inner := copyMap(vecObj(h["head"]))
				inner[str(op[3])] = op[4]
				next["head"] = inner
			}
			heads[str(op[1])] = next
			return nil, nil
		case "cosign":
			w, err := wit(op[1])
			if err != nil {
				return nil, err
			}
			h, err := head(op[2])
			if err != nil {
				return nil, err
			}
			inner := vecObj(h["head"])
			var d *MeshDomain
			for _, x := range doms {
				if inner["domain"] == any(x.ID) {
					d = x
				}
			}
			if d == nil {
				return nil, errors.New("no such domain")
			}
			req := map[string]any{"head": h}
			switch c := op[3].(type) {
			case string: // "domain": the domain's own proof from the witness's last-seen head
				if prev := w.LastSeen(d.ID); prev != nil {
					from, err := size(prev["size"])
					if err != nil {
						return nil, err
					}
					to, err := size(inner["size"])
					if err != nil {
						return nil, err
					}
					proof, err := d.ConsistencyProof(from, to)
					if err != nil {
						return nil, err
					}
					req["consistency"] = proof
				}
			default:
				if meshTruthy(c) {
					req["consistency"] = c
				}
			}
			if op[4] == "domain" {
				req["rev_ids"] = meshStringsJSON(d.RevocationSetCopy().List())
			} else {
				req["rev_ids"] = op[4]
			}
			return w.Cosign(req)
		case "lastSeen":
			w, err := wit(op[1])
			if err != nil {
				return nil, err
			}
			id := str(op[2])
			if d, isDomain := doms[id]; isDomain {
				id = d.ID
			}
			if h := w.LastSeen(id); h != nil {
				return h, nil
			}
			return nil, nil
		case "export":
			w, err := wit(op[1])
			if err != nil {
				return nil, err
			}
			return w.ExportState(), nil
		case "import":
			w, err := wit(op[1])
			if err != nil {
				return nil, err
			}
			state := vecObj(op[2])
			if from, isExport := state["$export"]; isExport {
				other, err := wit(from)
				if err != nil {
					return nil, err
				}
				state = other.ExportState()
			}
			return nil, w.ImportState(state)
		case "restart":
			st, err := store(op[2])
			if err != nil {
				return nil, err
			}
			w, err := NewMeshWitness(mwKey(t, "mesh-issue/w/"+str(op[3])), MeshWitnessOptions{Store: st})
			if err != nil {
				return nil, err
			}
			ws[str(op[1])] = w
			return w.ExportState(), nil
		case "consistency":
			d, err := dom(op[1])
			if err != nil {
				return nil, err
			}
			from, err := size(op[2])
			if err != nil {
				return nil, err
			}
			to := d.LogSize()
			if op[3] != nil {
				if to, err = size(op[3]); err != nil {
					return nil, err
				}
			}
			return d.ConsistencyProof(from, to)
		case "enroll":
			d, err := dom(op[1])
			if err != nil {
				return nil, err
			}
			b, err := d.Enroll(str(op[3]), str(op[4]))
			if err != nil {
				return nil, err
			}
			binds[str(op[2])] = b
			return b, nil
		case "evidence":
			d, err := dom(op[1])
			if err != nil {
				return nil, err
			}
			h, err := head(op[3])
			if err != nil {
				return nil, err
			}
			var binding map[string]any
			if op[4] != nil {
				b, ok := binds[str(op[4])]
				if !ok {
					return nil, unknown(op[4])
				}
				binding = b
			}
			return d.Evidence(mwCap(str(op[2]), true), h, binding)
		}
		return nil, errors.New("op")
	}
	out := []any{}
	for _, o := range ops {
		op, _ := o.([]any)
		var v any
		var err error
		if p := baseCall(func() { v, err = run(op) }); p != "" {
			err = errors.New("panic: " + p)
		}
		if err != nil {
			v = map[string]any{"$err": err.Error()}
		}
		out = append(out, v)
	}
	return out
}

func TestMeshIssuingMatchesTheReference(t *testing.T) {
	seedKey := func(v any) (*KeyPair, error) {
		s, _ := v.(string)
		k, err := KeyPairFromSeedB64u(s)
		if err != nil {
			return nil, errors.New("not an Ed25519 seed")
		}
		return k, nil
	}
	replayAll(t, "ref-mesh-issue.json.gz", 787, vecSeeded(map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"DEFAULT_MAX_HEAD_AGE_MS": MeshDefaultMaxHeadAgeMs, "DEFAULT_MAX_CLOCK_SKEW_MS": MeshDefaultMaxClockSkewMs,
				"DEFAULT_MAX_CHAIN_LENGTH": MeshDefaultMaxChainLength}, nil
		},
		// the key is text here: a caller formats what it has, as the reference's string coercion does
		"keyRevocationId":    func(a []any) (any, error) { return KeyRevocationID(jsValueString(a[0])), nil },
		"effectiveAuthority": func(a []any) (any, error) { return EffectiveAuthority(a[0]) },
		"meshProofSize":      func(a []any) (any, error) { return MeshProofSize(a[0]) },
		"revocationLatencyBound": func(a []any) (any, error) {
			// a parameter that is not a number is not a finite number
			m := vecObj(a[0])
			b := RevocationLatencyBound(LatencyParams{MaxHeadAgeMs: mivNum(m["maxHeadAgeMs"]), HeadIntervalMs: mivNum(m["headIntervalMs"]),
				MaxClockSkewMs: mivOptNum(m, "maxClockSkewMs"), PinRefreshMs: mivOptNum(m, "pinRefreshMs")})
			return pdvOut(map[string]any{"published_ms": b.PublishedMs, "unpinned_ms": b.UnpinnedMs, "pinned_ms": b.PinnedMs,
				"honest_provers_viable": b.HonestProversViable}), nil
		},
		"buildMeshExample": func(a []any) (any, error) {
			now := 1_800_000_000_000.0
			if a[0] != nil {
				now = mivNum(a[0])
			}
			ex, err := BuildMeshExample(now)
			if err != nil {
				return nil, err
			}
			return map[string]any{"trust": ex.Trust, "proof": ex.Proof, "evidence": mivMaps(ex.Evidence), "chain": mivMaps(ex.Chain), "heads": mivHeadMaps(ex.Heads),
				"bindings": mivHeadMaps(ex.Bindings), "domains": map[string]any{"A": ex.DomainA.ID, "B": ex.DomainB.ID, "C": ex.DomainC.ID},
				"witnesses": []any{ex.Witnesses[0].ID, ex.Witnesses[1].ID, ex.Witnesses[2].ID}}, nil
		},
		"demonstrateForkRejection": func([]any) (any, error) {
			d, err := DemonstrateForkRejection()
			if err != nil {
				return nil, err
			}
			return map[string]any{"honest_extension_cosigned": d.HonestExtensionCosigned, "fork_larger_than_prior": d.ForkLargerThanPrior,
				"size_only_check_would_accept": d.SizeOnlyCheckWouldAccept, "fork_rejected": d.ForkRejected, "fork_reason": d.ForkReason}, nil
		},
		"meshIssue": func(a []any) (any, error) {
			ops, _ := a[0].([]any)
			return mivScript(t, ops), nil
		},
		"translateCapability": func(a []any) (any, error) {
			chain, _ := a[0].([]any) // anything but a list is no chain
			m := vecObj(a[1])
			args := TranslateArgs{FromGuardian: vecStr(m, "fromGuardian"), ToGuardian: vecStr(m, "toGuardian"), IssuedAt: mivNum(m["issued_at"]),
				PqPins: rsStrMap(m["pqPins"])}
			if extra, given := m["additionalCaveats"]; given {
				list, isList := extra.([]any)
				if !isList { // the typed list cannot carry it
					return nil, errors.New("translateCapability: additionalCaveats must be an array of caveats")
				}
				args.AdditionalCaveats = list
			}
			bridge, err := seedKey(m["bridgeSecret"])
			if err != nil {
				return nil, err
			}
			args.Bridge = bridge
			return TranslateCapability(chain, args)
		},
		"translatedEffectiveAuthority": func(a []any) (any, error) { return TranslatedEffectiveAuthority(a[0]), nil },
		"verifyTranslatedCapability": func(a []any) (any, error) {
			if len(a) > 1 {
				return VerifyTranslatedCapability(a[0], a[1]), nil
			}
			return VerifyTranslatedCapability(a[0]), nil
		},
		"createFederatedBudget": func(a []any) (any, error) { return CreateFederatedBudget(a[0]), nil },
		"allocateSub":           func(a []any) (any, error) { return AllocateSub(a[0], a[1]), nil },
		"spendFederated":        func(a []any) (any, error) { return SpendFederated(a[0], a[1], a[2]), nil },
		"federatedSafetyBound":  func(a []any) (any, error) { return pdvOut(FederatedSafetyBound(a[0])), nil },
		"meshActionDigest":      func(a []any) (any, error) { return MeshActionDigest(a[0]) },
		"crossReferenceCommit": func(a []any) (any, error) {
			if a[0] == nil {
				return nil, errors.New("null has no members")
			}
			return CrossReferenceCommit(vecObj(a[0]))
		},
		"anchorCrossReference": func(a []any) (any, error) {
			k, err := seedKey(a[0])
			if err != nil {
				return nil, err
			}
			return AnchorCrossReference(k, a[1], a[2])
		},
		"verifyCrossReference": func(a []any) (any, error) { return VerifyCrossReference(a[0], vecArg(a, 1)), nil },
	}), nil, nil)
}
