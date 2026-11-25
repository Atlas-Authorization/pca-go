package pca

import (
	"errors"
	"strconv"
	"testing"
)

// Replay, against the reference, of the entry points of the shared small-surface and sweep corpora that no other replay owned:
// the goal commitment, the unmet-limit wording, threshold assembly and escalation, the detector receipt reference, the workflow
// commitment and receipt-chain checks, the cheap chain check, the holder PQ key, discovery (build and fetch), inclusion in the
// revocation set, the staleness policy check, the canonical JWS gates, the payment and CIBA approval profiles; and, for the sweep
// corpus, the verifier chain memo, the receipt chain, the capital pool and the standing approvals (class approval, coverage,
// decisions, pending requests, co-sign).

func gapOpErr() map[string]any { return map[string]any{"$err": "Error"} }

// gapTry runs one op of a script: a panic or an error is the reference's thrown error.
func gapTry(f func() (any, error)) (out any) {
	defer func() {
		if recover() != nil {
			out = gapOpErr()
		}
	}()
	v, err := f()
	if err != nil {
		return gapOpErr()
	}
	return v
}

func gapTryOk(f func() (any, error)) (any, error) {
	v, err := f()
	if err != nil {
		return map[string]any{"ok": false}, nil
	}
	return map[string]any{"ok": true, "v": v}, nil
}

func TestSmallSurfaceGapsMatchTheReference(t *testing.T) {
	s := func(v any) string { x, _ := v.(string); return x }
	rsReplaySubset(t, "ref-core-small-surface.json.gz", map[string]vecFn{
		"dischargeRequests": func(a []any) (any, error) {
			digest, _ := vecArg(a, 2).(string)
			rs := DischargeRequests(vecArg(a, 0), vecArg(a, 1), digest)
			out := make([]any, len(rs))
			for i, r := range rs {
				out[i] = r
			}
			return out, nil
		},
		"goalCommitOf": func(a []any) (any, error) {
			g, ok1 := vecArg(a, 0).(string)
			salt, ok2 := vecArg(a, 1).(string)
			if !ok1 || !ok2 {
				return nil, errors.New("goal and salt are strings")
			}
			return GoalCommitOf(g, salt)
		},
		"verifyGoalCommit": func(a []any) (any, error) {
			return VerifyGoalCommit(s(vecArg(a, 0)), s(vecArg(a, 1)), s(vecArg(a, 2))), nil
		},
		"namedUnmetLimitReason": func(a []any) (any, error) {
			return ppOrNull(NamedUnmetLimitReason(vecArg(a, 0), vecObj(vecArg(a, 1)))), nil
		},
		"assembleThreshold": func(a []any) (any, error) { return AssembleThreshold(vecArg(a, 0)), nil },
		"escalateThreshold": func(a []any) (any, error) {
			rt := vecObj(vecArg(a, 0))
			r := EscalateThreshold(RequiredThreshold{T: int(jsF(rt["t"])), Proof: s(rt["proof"]), OptimisticAllowed: rt["optimisticAllowed"] == true}, int(jsF(vecArg(a, 1))))
			return map[string]any{"t": jsNumber(float64(r.T)), "proof": r.Proof, "optimisticAllowed": r.OptimisticAllowed}, nil
		},
		"detectorReceiptRef": func(a []any) (any, error) { return DetectorReceiptRef(vecArg(a, 0)) },
		"workflowCommitmentError": func(a []any) (any, error) {
			return ppOrNull(WorkflowCommitmentError(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2))), nil
		},
		"workflowReceiptError": func(a []any) (any, error) {
			w := vecObj(vecArg(a, 0))
			if w == nil {
				return nil, errors.New("workflow body is not an object")
			}
			rs, _ := vecArg(a, 2).([]any)
			at, bad, err := WorkflowReceiptError(w, s(vecArg(a, 1)), rs, int64(jsF(vecArg(a, 3))))
			if err != nil || !bad {
				return nil, err
			}
			return jsNumber(float64(at)), nil
		},
		"verifyChainCheap": func(a []any) (any, error) {
			chain, _ := vecArg(a, 0).([]any)
			var allowed []string
			if l, ok := vecArg(a, 2).([]any); ok {
				allowed = []string{}
				for _, x := range l {
					allowed = append(allowed, s(x))
				}
			}
			root, haveRoot := vecArg(a, 1).(string)
			hops, why := VerifyChainCheap(chain, root, haveRoot, allowed)
			if why != "" {
				return map[string]any{"ok": false, "reason": why}, nil
			}
			return map[string]any{"ok": true, "pqHops": jsNumber(float64(hops))}, nil
		},
		"holderPqKey": func(a []any) (any, error) {
			if k, ok := HolderPqKey(vecArg(a, 0), vecArg(a, 2), vecArg(a, 3)); ok {
				return k, nil
			}
			return nil, nil
		},
		"buildDiscoveryDocument": func(a []any) (any, error) {
			o := vecObj(vecArg(a, 0))
			d := DiscoveryOptions{Audience: s(o["audience"]), ActionHeader: s(o["actionHeader"]), Endpoints: vecObj(o["endpoints"]), Metadata: vecObj(o["metadata"]), Intent: vecObj(o["intent"])}
			if _, has := o["signatureSuites"]; has {
				d.SignatureSuites = attStrings(o["signatureSuites"])
			}
			if _, has := o["requiredChecks"]; has {
				d.RequiredChecks = attStrings(o["requiredChecks"])
			}
			if _, has := o["trustedRoots"]; has {
				d.TrustedRoots = attStrings(o["trustedRoots"])
				if d.TrustedRoots == nil { // a present empty list is emitted as an empty list
					d.TrustedRoots = []string{}
				}
			}
			if _, has := o["obligationsSupported"]; has {
				d.ObligationsSupported = attStrings(o["obligationsSupported"])
				if d.ObligationsSupported == nil { // a present empty list stays an empty list
					d.ObligationsSupported = []string{}
				}
			}
			if l, has := o["pcaVersions"].([]any); has {
				d.PcaVersions = []int{}
				for _, x := range l {
					d.PcaVersions = append(d.PcaVersions, int(jsF(x)))
				}
			}
			return BuildDiscoveryDocument(d)
		},
		"fetchDiscovery": func(a []any) (any, error) {
			mode := s(vecArg(a, 1))
			urls := []any{}
			doc, err := FetchDiscovery(s(vecArg(a, 0)), func(url string, h map[string]string) (int, any, error) {
				urls = append(urls, url+"|"+h["accept"])
				if mode == "throw" {
					return 0, nil, errors.New("boom")
				}
				body, _ := ParseJSONLenient([]byte(`{"audience":"https://rs.example","pca_versions":[2],"signature_suites":["ed25519","ml-dsa-65"],"action_header":"PCA-Action"}`))
				if mode == "bad" {
					body, _ = ParseJSONLenient([]byte(`{"nope":1}`))
				}
				if mode == "500" {
					return 500, body, nil
				}
				return 200, body, nil
			})
			if err != nil {
				return map[string]any{"error": true, "urls": urls}, nil
			}
			return map[string]any{"doc": doc, "urls": urls}, nil
		},
		"verifyMembership": func(a []any) (any, error) {
			return VerifyMembership(s(vecArg(a, 0)), vecArg(a, 1), s(vecArg(a, 2))), nil
		},
		"validateRevocationStaleness": func(a []any) (any, error) {
			return map[string]any{"ok": RevocationStalenessPolicyFromJSON(vecArg(a, 0)).Validate() == nil}, nil
		},
		"isCanonicalCompactJws":       func(a []any) (any, error) { return IsCanonicalCompactJws(vecArg(a, 0), 3, 0, true), nil },
		"isCanonicalCompactJwsOpaque": func(a []any) (any, error) { return IsCanonicalCompactJws(vecArg(a, 0), 3, 0, false), nil },
		"isCanonicalCompactJwsMax":    func(a []any) (any, error) { return IsCanonicalCompactJws(vecArg(a, 0), 3, 40, true), nil },
		"isCanonicalCompactJwsFive":   func(a []any) (any, error) { return IsCanonicalCompactJws(vecArg(a, 0), 5, 0, true), nil },
		"assertCanonicalJwsSegments": func(a []any) (any, error) {
			h, err := AssertCanonicalJwsSegments(vecArg(a, 0), vecArg(a, 1), 0)
			if err != nil {
				return map[string]any{"ok": false}, nil
			}
			return map[string]any{"ok": true, "header": h}, nil
		},
		"spcExpectation": func(a []any) (any, error) {
			payee := "name"
			if p, ok := vecArg(a, 1).(string); ok {
				payee = p
			}
			return gapTryOk(func() (any, error) { return ActionSpcExpectation(vecObj(vecArg(a, 0)), "https://shop.example", payee) })
		},
		"cibaApprovalDetails": func(a []any) (any, error) {
			return gapTryOk(func() (any, error) { return ActionCibaApprovalDetails(vecObj(vecArg(a, 0))) })
		},
	})
}

func TestSweepGapsMatchTheReference(t *testing.T) {
	s := func(v any) string { x, _ := v.(string); return x }
	classApproval := func(v any) ClassApproval {
		m := vecObj(v)
		c := ClassApproval{ID: s(m["id"]), Verbs: attStrings(m["verbs"]), GrantedAt: int64(jsF(m["grantedAt"])), TTLMs: int64(jsF(m["ttlMs"])), By: s(m["by"])}
		if r, ok := m["resource"].(string); ok {
			c.Resource = &r
		}
		return c
	}
	rsReplaySubset(t, "ref-core-sweep-java.json.gz", map[string]vecFn{
		"chainMemo": func(a []any) (any, error) {
			var memo *ChainMemo
			out := []any{}
			for _, o := range rsList(vecArg(a, 0)) {
				op := rsList(o)
				out = append(out, gapTry(func() (any, error) {
					switch s(vecArg(op, 0)) {
					case "new":
						var opts ChainMemoOptions
						if cfg := vecObj(vecArg(op, 1)); cfg != nil {
							if f, ok := jsNum(cfg["maxEntries"]); ok {
								opts.MaxEntries = int(f)
							}
							if f, ok := jsNum(cfg["ttlMs"]); ok {
								opts.TTLMs = int64(f)
							}
						}
						memo = NewChainMemo(opts)
						return nil, nil
					case "remember":
						now, ok := ccClock(vecArg(op, 3))
						if !ok {
							return nil, errors.New("the clock is not a safe integer")
						}
						chain, _ := vecArg(op, 1).([]any)
						return memo.RememberVerified(chain, s(vecArg(op, 2)), now, nil)
					case "resolve":
						now, ok := ccClock(vecArg(op, 2))
						if !ok {
							return map[string]any{"ok": false, "reason": "the verifier clock is not a safe integer (fail closed)"}, nil
						}
						r := memo.Resolve(vecArg(op, 1), now)
						if !r.OK {
							return map[string]any{"ok": false, "reason": r.Reason}, nil
						}
						v, err := ccViewOut(r.View)
						return map[string]any{"ok": true, "view": v}, err
					case "prune":
						now, _ := ccClock(vecArg(op, 1))
						memo.Prune(now)
						return nil, nil
					case "forget":
						return memo.Forget(s(vecArg(op, 1))), nil
					case "size":
						return jsNumber(float64(memo.Size())), nil
					}
					return nil, errors.New("op")
				}))
			}
			return out, nil
		},
		"receiptChain": func(a []any) (any, error) {
			log := []any{}
			out := []any{}
			typed := func() ([]ActionReceipt, error) { return ppReceipts(log) }
			for _, o := range rsList(vecArg(a, 0)) {
				op := rsList(o)
				out = append(out, gapTry(func() (any, error) {
					switch s(vecArg(op, 0)) {
					case "append":
						l, err := typed()
						if err != nil {
							return nil, err
						}
						nl, err := AppendReceipt(l, vecObj(vecArg(op, 1)), ppVerify(vecArg(op, 2)), ppAt(vecArg(op, 3)))
						if err != nil {
							return nil, err
						}
						j, _ := vecJSON(nl).([]any)
						log = j
						return j[len(j)-1], nil
					case "head":
						l, err := typed()
						return ReceiptHead(l), err
					case "verify":
						return gapRawReceiptVerify(log)
					case "set":
						log = append([]any{}, rsList(vecArg(op, 1))...)
						return nil, nil
					case "tamper":
						i, _ := attSafeInt(vecArg(op, 1))
						cp, _ := vecJSON(log).([]any)
						r := vecObj(cp[int(i)])
						if vecArg(op, 3) == "$del" {
							delete(r, s(vecArg(op, 2)))
						} else {
							r[s(vecArg(op, 2))] = vecArg(op, 3)
						}
						log = cp
						return nil, nil
					case "swap":
						i, _ := attSafeInt(vecArg(op, 1))
						j, _ := attSafeInt(vecArg(op, 2))
						cp, _ := vecJSON(log).([]any)
						cp[int(i)], cp[int(j)] = cp[int(j)], cp[int(i)]
						log = cp
						return nil, nil
					case "drop":
						i, _ := attSafeInt(vecArg(op, 1))
						log = append(append([]any{}, log[:int(i)]...), log[int(i)+1:]...)
						return nil, nil
					case "truncate":
						i, _ := attSafeInt(vecArg(op, 1))
						log = append([]any{}, log[:int(i)]...)
						return nil, nil
					}
					return nil, errors.New("op")
				}))
			}
			return out, nil
		},
		"pool": func(a []any) (any, error) {
			var pool *InsuranceCapitalPool
			out := []any{}
			score := func(v any) (*float64, error) {
				m := vecObj(v)
				if m == nil {
					return nil, errors.New("no score object")
				}
				return rsOptNum(m["score"]), nil
			}
			for _, o := range rsList(vecArg(a, 0)) {
				op := rsList(o)
				out = append(out, gapTry(func() (any, error) {
					switch s(vecArg(op, 0)) {
					case "new":
						p, err := NewInsuranceCapitalPool(jsF(vecArg(op, 1)))
						if err != nil {
							return nil, err
						}
						pool = p
						return pool.State(), nil
					case "quote":
						sc, err := score(vecArg(op, 1))
						if err != nil {
							return nil, err
						}
						return pool.Quote(sc, jsF(vecArg(op, 2)), vecObj(vecArg(op, 3))), nil
					case "collect":
						sc, err := score(vecArg(op, 1))
						if err != nil {
							return nil, err
						}
						return pool.CollectPremium(sc, jsF(vecArg(op, 2)), vecObj(vecArg(op, 3)))
					case "canCover":
						return pool.CanCover(jsF(vecArg(op, 1))), nil
					case "pay":
						return pool.PayClaim(jsF(vecArg(op, 1)))
					case "state":
						return pool.State(), nil
					}
					return nil, errors.New("op")
				}))
			}
			return out, nil
		},
		"approveClass": func(a []any) (any, error) {
			now := int64(jsF(vecArg(a, 3)))
			o := ApproveClassOptions{TTLMs: int64(jsF(vecArg(a, 1))), By: s(vecArg(a, 2)), Now: &now}
			if r, ok := vecArg(a, 4).(string); ok {
				o.Resource = &r
			}
			return ApproveClass(attStrings(vecArg(a, 0)), o)
		},
		"classApprovalCovers": func(a []any) (any, error) {
			return ClassApprovalCovers(classApproval(vecArg(a, 0)), s(vecArg(a, 1)), s(vecArg(a, 2)), int64(jsF(vecArg(a, 3)))), nil
		},
		"coveredByAny": func(a []any) (any, error) {
			var l []ClassApproval
			for _, x := range rsList(vecArg(a, 0)) {
				l = append(l, classApproval(x))
			}
			return CoveredByAny(l, s(vecArg(a, 1)), s(vecArg(a, 2)), int64(jsF(vecArg(a, 3)))), nil
		},
		"recordDecision": func(a []any) (any, error) {
			at := int64(jsF(vecArg(a, 3)))
			return RecordDecision(StepUpRequest{ID: s(vecObj(vecArg(a, 0))["id"])}, s(vecArg(a, 1)), s(vecArg(a, 2)), &at), nil
		},
		"pendingRequests": func(a []any) (any, error) {
			origin := map[string]any{}
			var reviews []Review
			for i, x := range rsList(vecArg(a, 0)) {
				m := vecObj(x)
				r := Review{Kind: s(m["kind"]), Reason: s(m["reason"])}
				if req := vecObj(m["request"]); req != nil {
					id := jsNumberString(float64(i))
					origin[id] = req
					r.Request = &StepUpRequest{ID: id}
				}
				reviews = append(reviews, r)
			}
			out := []any{}
			for _, p := range PendingRequests(reviews) {
				out = append(out, origin[p.ID])
			}
			return out, nil
		},
		"applyCosign": func(a []any) (any, error) {
			p := vecObj(vecArg(a, 1))
			b := ApplyCosign(ppBudget(vecArg(a, 0)), RiskPolicy{Rho: jsF(p["rho"]), BMax: jsF(p["bMax"])}, jsF(vecArg(a, 2)), vecArg(a, 3) == true)
			return pdBudgetJSON(b), nil
		},
	})
}

// gapRawReceiptVerify is the reference's verifyReceiptChain over the raw JSON log (members of any type, missing members undefined),
// not over the typed ActionReceipt: a log that was edited by hand is judged the way JavaScript judges it.
func gapRawReceiptVerify(log []any) (any, error) {
	prev := any("")
	for i, x := range log {
		r, ok := x.(map[string]any)
		if !ok {
			return nil, errors.New("Cannot read properties of null (reading 'seq')")
		}
		seq, hasSeq := r["seq"]
		brk := func(reason string) (any, error) {
			out := map[string]any{"ok": false, "reason": reason}
			if hasSeq {
				out["brokenAt"] = seq
			}
			return out, nil
		}
		if f, isNum := jsNum(seq); !hasSeq || !isNum || f != float64(i) {
			return brk("seq " + jsMemberString(r, "seq") + " out of order (expected " + strconv.Itoa(i) + ")")
		}
		if !jsStrictEq(r["prev"], prev) {
			return brk("prev link mismatch at seq " + jsMemberString(r, "seq"))
		}
		body := map[string]any{"d": "atlas-pca/receipt/v1", "seq": r["seq"], "prev": r["prev"], "checks": nil}
		for _, k := range []string{"at", "actionDigest", "verb", "resource", "outcome"} {
			v, has := r[k]
			if !has {
				return nil, errors.New("canonicalize: unsupported type undefined")
			}
			body[k] = v
		}
		if c, has := r["checks"]; has {
			body["checks"] = c
		}
		h, err := HashCanonical(body)
		if err != nil {
			return nil, err
		}
		if !jsStrictEq(r["hash"], h) {
			return brk("hash mismatch at seq " + jsMemberString(r, "seq") + " (tampered body)")
		}
		prev = r["hash"]
	}
	return map[string]any{"ok": true}, nil
}
