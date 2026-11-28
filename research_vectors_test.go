package pca

import (
	"crypto/sha256"
	"errors"
	"math"
	"testing"
)

// Replay of the policy-and-agent modules against the reference corpora: DLP, the immune read side, the console, sessions, policy
// simulation and linting (ref-core-research-java); catalog risk, policy templates and the builder (ref-core-small-surface); the approval
// channels (ref-core-approval-channels); reputation, underwriting quotes and budget forecasting (ref-core-sweep-java).

// rsReplaySubset replays the entry points this file owns and skips, with a reason, every other function the shared corpus carries.
func rsReplaySubset(t *testing.T, file string, fns map[string]vecFn) {
	t.Helper()
	all := map[string]vecFn{}
	for k, f := range fns {
		all[k] = f
	}
	baseEachOrdered(t, file, func(c *baseCase) {
		if _, ok := all[c.Fn]; !ok {
			all[c.Fn] = func([]any) (any, error) { return nil, vecSkip("covered by another module's test") }
		}
	})
	replayVectors(t, file, all)
}

// rsReplaySubsetCmp is rsReplaySubset with per-fn comparators.
func rsReplaySubsetCmp(t *testing.T, file string, fns map[string]vecFn, cmp map[string]func(want, got any) bool) {
	t.Helper()
	all := map[string]vecFn{}
	for k, f := range fns {
		all[k] = f
	}
	baseEachOrdered(t, file, func(c *baseCase) {
		if _, ok := all[c.Fn]; !ok {
			all[c.Fn] = func([]any) (any, error) { return nil, vecSkip("covered by another module's test") }
		}
	})
	replayVectorsCmp(t, file, all, cmp)
}

func rsSeedKey(t *testing.T, label string) *KeyPair {
	t.Helper()
	h := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	k, err := KeyPairFromSeed(h[:])
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rsOptNum(v any) *float64 {
	if f, ok := jsNum(v); ok {
		return &f
	}
	return nil
}

func rsStrMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, x := range m {
		out[k], _ = x.(string)
	}
	return out
}

func rsList(v any) []any { l, _ := v.([]any); return l }

func rsStr(v any) string { s, _ := v.(string); return s }

func rsStringsOut(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func rsCompile(t *testing.T, spec any) *CompiledPolicy {
	t.Helper()
	p, err := rsCompileErr(spec)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// rsCompileErr is rsCompile returning the refusal (a corpus case may expect one).
func rsCompileErr(spec any) (*CompiledPolicy, error) {
	s := vecObj(spec)
	now, _ := jsNum(s["now"])
	at := int64(now)
	p, err := CompilePolicy(PolicyOptions{Permissions: s["permissions"], Limits: rsStrMap(s["limits"]), BudgetModel: rsStr(s["budgetModel"]),
		RiskPolicy: vecObj(s["riskPolicy"]), At: &at})
	return p, err
}

func TestResearchModulesMatchTheReference(t *testing.T) {
	needAgent := func(m map[string]*FacadeAgent, k any) (*FacadeAgent, error) {
		a := m[rsStr(k)]
		if a == nil {
			return nil, errors.New("unknown agent")
		}
		return a, nil
	}
	rsReplaySubsetCmp(t, "ref-core-research-java.json.gz", map[string]vecFn{
		"evaluateDlp":      func(a []any) (any, error) { return EvaluateDlp(vecObj(a[0]), vecObj(a[1])) },
		"defaultDlpPolicy": func(a []any) (any, error) { return DefaultDlpPolicy(vecObj(vecArg(a, 0))) },
		"assess":           func(a []any) (any, error) { return ImmuneAssess(a[0]), nil },
		"observe":          func(a []any) (any, error) { return ImmuneObserve(vecObj(a[0]), vecObj(a[1])), nil },
		"updateBaseline":   func(a []any) (any, error) { return ImmuneUpdateBaseline(vecObj(a[0]), jsF(a[1])), nil },
		"baselineStd":      func(a []any) (any, error) { return rsN(ImmuneBaselineStd(vecObj(a[0]))), nil },
		"buildConsole":     func(a []any) (any, error) { return BuildConsole(rsList(a[0])) },
		"freezeAgent":      func(a []any) (any, error) { return FreezeAgent(vecObj(a[0]), a[1]) },
		"unfreezeAgent":    func(a []any) (any, error) { return UnfreezeAgent(vecObj(a[0]), a[1]) },
		"isFrozen":         func(a []any) (any, error) { return IsFrozen(a[0], a[1]), nil },
		"validateImmuneState": func(a []any) (any, error) {
			if s := ValidateImmuneState(a[0]); s != "" {
				return s, nil
			}
			return nil, nil
		},
		"anomalies": func(a []any) (any, error) {
			v, err := BuildConsole(rsList(a[0]))
			if err != nil {
				return nil, err
			}
			return Anomalies(v), nil
		},
		"eventFromPCActn": func(a []any) (any, error) { return EventFromPCActn(vecObj(a[0]), rsStr(a[1]), rsOptNum(vecArg(a, 2))) },
		"session": func(a []any) (any, error) {
			ags := map[string]*FacadeAgent{}
			sess := map[string]*Session{}
			needSess := func(k any) (*Session, error) {
				s := sess[rsStr(k)]
				if s == nil {
					return nil, errors.New("unknown session")
				}
				return s, nil
			}
			out := []any{}
			for _, oo := range rsList(a[0]) {
				op := rsList(oo)
				v, err := func() (any, error) {
					switch rsStr(op[0]) {
					case "agent":
						spec := vecObj(op[2])
						now, _ := jsNum(spec["now"])
						at := int64(now)
						ag, err := CreateAgent(AgentOptions{Principal: rsSeedKey(t, "research/"+rsStr(spec["principal"])), Goal: rsStr(spec["goal"]),
							Permissions: spec["permissions"], Holder: rsSeedKey(t, "research/"+rsStr(spec["holder"])), GoalSalt: rsStr(spec["goalSalt"]), At: &at})
						if err != nil {
							return nil, err
						}
						ags[rsStr(op[1])] = ag
						return ag.Holder.Public, nil
					case "start":
						r, err := needAgent(ags, op[2])
						if err != nil {
							return nil, err
						}
						s := StartSession(r)
						sess[rsStr(op[1])] = s
						return s.GoalCommit, nil
					case "mk":
						var ms []*FacadeAgent
						for _, n := range rsList(op[2]) {
							m, err := needAgent(ags, n)
							if err != nil {
								return nil, err
							}
							ms = append(ms, m)
						}
						goal := ""
						if g, ok := op[3].(string); ok {
							goal = g
						} else if len(ms) > 0 {
							goal = sessionGoalOf(ms[0])
						}
						s := &Session{Members: ms, GoalCommit: goal}
						if len(ms) > 0 {
							s.Root = ms[0]
						}
						sess[rsStr(op[1])] = s
						return s.GoalCommit, nil
					case "add":
						var child *KeyPair
						if op[3] != nil {
							child = rsSeedKey(t, "research/"+rsStr(op[3]))
						}
						cur, err := needSess(op[2])
						if err != nil {
							return nil, err
						}
						ns, member, err := AddMember(cur, child, rsList(op[4]))
						if err != nil {
							return nil, err
						}
						sess[rsStr(op[1])] = ns
						return member.Holder.Public, nil
					case "agents":
						s, err := needSess(op[1])
						if err != nil {
							return nil, err
						}
						return rsStringsOut(SessionAgents(s)), nil
					case "depth":
						s, err := needSess(op[1])
						if err != nil {
							return nil, err
						}
						return jsNumber(float64(SessionDepth(s))), nil
					case "shares":
						s, err := needSess(op[1])
						if err != nil {
							return nil, err
						}
						return SharesGoal(s), nil
					case "goal":
						s, err := needSess(op[1])
						if err != nil {
							return nil, err
						}
						return s.GoalCommit, nil
					case "console":
						s, err := needSess(op[1])
						if err != nil {
							return nil, err
						}
						evs, isList := op[2].([]any)
						if !isList { // `events.filter` is not a function on a string or null: the reference throws
							return nil, errors.New("events must be an array")
						}
						return SessionConsole(s, evs)
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
		},
		"simulate": func(a []any) (any, error) {
			var acts []map[string]any
			for _, x := range rsList(a[1]) {
				acts = append(acts, vecObj(x))
			}
			start := 0.0
			if f := rsOptNum(vecArg(a, 2)); f != nil {
				start = *f
			}
			cp, err := rsCompileErr(a[0]) // a policy the compiler refuses is the reference's thrown refusal
			if err != nil {
				return nil, err
			}
			return SimulatePolicy(cp, acts, nil, start), nil
		},
		"lintPolicy": func(a []any) (any, error) {
			cp, err := rsCompileErr(a[0])
			if err != nil {
				return nil, err
			}
			return LintPolicy(cp, nil), nil
		},
		"disputesFromSettlements": func(a []any) (any, error) {
			guardian := rsStr(a[1])
			if guardian == "@g" {
				guardian = rsSeedKey(t, "research/guardian").Public
			}
			subjects := vecObj(a[2])
			records, _ := a[0].([]any)
			return DisputesFromSettlements(records, guardian, func(id string) (string, bool) {
				s, ok := subjects[id].(string)
				return s, ok
			}, bvPins(vecArg(a, 3))...)
		},
	}, map[string]func(want, got any) bool{"buildConsole": goalVxApprox, "anomalies": goalVxApprox})
}

func TestCatalogRiskAndPolicyTemplatesMatchTheReference(t *testing.T) {
	fromTemplate := func(a []any) (any, error) {
		o := FromTemplateOptions{Principal: rsSeedKey(t, "small/tpl/p"), Goal: "g", Holder: rsSeedKey(t, "small/tpl/h"), Now: 1_700_000_000_000}
		if ov := vecObj(vecArg(a, 1)); ov != nil {
			o.Permissions, o.Limits, o.RiskPolicy = vecObj(ov["permissions"]), rsStrMap(ov["limits"]), vecObj(ov["riskPolicy"])
			o.BudgetModel = rsStr(ov["budgetModel"])
		}
		h, err := FromTemplate(rsStr(a[0]), o)
		if err != nil {
			return map[string]any{"ok": false}, nil
		}
		return map[string]any{"ok": true, "predicates": h.Policy.Predicates, "caveats": h.Policy.Caveats, "riskPolicy": h.Policy.RiskPolicy, "budgetModel": h.Policy.BudgetModel}, nil
	}
	rsReplaySubset(t, "ref-core-small-surface.json.gz", map[string]vecFn{
		"catalogReversibilityScore": func(a []any) (any, error) { return CatalogReversibilityScore(), nil },
		"catalogRisk": func(a []any) (any, error) {
			return CatalogRisk(rsStr(a[0]), vecObj(a[1]), a[2], nil, rsOptNum(vecArg(a, 3))), nil
		},
		"listTemplates": func(a []any) (any, error) {
			out := []any{}
			for _, tp := range ListTemplates() {
				o := map[string]any{"name": tp.Name, "description": tp.Description, "permissions": tp.Permissions}
				if tp.Limits != nil {
					o["limits"] = tp.Limits
				}
				if tp.RiskPolicy != nil {
					o["riskPolicy"] = tp.RiskPolicy
				}
				out = append(out, o)
			}
			return out, nil
		},
		"fromTemplate": fromTemplate,
		"policyBuilder": func(a []any) (any, error) {
			fail := map[string]any{"ok": false}
			b := NewPolicyBuilder()
			for _, op0 := range rsList(a[0]) {
				op := rsList(op0)
				switch rsStr(op[0]) {
				case "from":
					nb, err := PolicyBuilderFrom(rsStr(op[1]))
					if err != nil {
						return fail, nil
					}
					b = nb
				case "allow":
					var acts []string
					for _, x := range rsList(op[2]) {
						acts = append(acts, rsStr(x))
					}
					b.Allow(rsStr(op[1]), acts)
				case "limit":
					b.Limit(rsStr(op[1]), rsStr(op[2]))
				default:
					b.Risk(vecObj(op[1]))
				}
			}
			p, err := b.Build()
			if err != nil {
				return fail, nil
			}
			built := map[string]any{"permissions": p.Permissions, "limits": p.Limits}
			if p.RiskPolicy != nil {
				built["riskPolicy"] = p.RiskPolicy
			}
			return map[string]any{"ok": true, "built": built}, nil
		},
	})
}

func TestApprovalChannelsMatchTheReference(t *testing.T) {
	ctxOf := func(c any) *NotifyContext {
		n := &NotifyContext{}
		if m := vecObj(c); m != nil {
			n.InboxURL = rsStr(m["inboxUrl"])
		}
		return n
	}
	transport := func(mode string) ApprovalFetch {
		return func(url string, headers map[string]string, body string) (ApprovalResponse, error) {
			switch mode {
			case "ok":
				return ApprovalResponse{OK: true, Status: 200}, nil
			case "http500":
				return ApprovalResponse{OK: false, Status: 500}, nil
			case "throw":
				return ApprovalResponse{}, errors.New("boom")
			}
			return ApprovalResponse{}, errors.New("")
		}
	}
	channel := func(kind string, cfg map[string]any) ApprovalChannel {
		configured := cfg["configured"] == true
		mode := rsStr(cfg["transport"])
		url := ""
		if configured {
			url = "https://hooks.example/secret"
		}
		switch kind {
		case "slack":
			return SlackApprovalChannel(url, transport(mode))
		case "webhook":
			return WebhookApprovalChannel(url, transport(mode), rsStrMap(cfg["headers"]))
		}
		var send ApprovalTextSender
		if configured {
			send = func(subject, text string) (string, error) {
				if mode == "ok" {
					return "m1", nil
				}
				if mode == "throw-empty" {
					return "", errors.New("")
				}
				return "", errors.New("boom")
			}
		}
		c, err := TextApprovalChannel(kind, send)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	rsReplaySubset(t, "ref-core-approval-channels.json.gz", map[string]vecFn{
		"actionSummary": func(a []any) (any, error) { return ApprovalActionSummary(vecObj(a[0])), nil },
		"lineageLines":  func(a []any) (any, error) { return ApprovalLineageLines(vecObj(a[0])) },
		"renderLines":   func(a []any) (any, error) { return ApprovalRenderLines(vecObj(a[0])) },
		"buildSlackMessage": func(a []any) (any, error) {
			return BuildSlackMessage(vecObj(a[0]), ctxOf(vecArg(a, 1)))
		},
		"buildWebhookBody": func(a []any) (any, error) {
			return BuildWebhookBody(vecObj(a[0]), ctxOf(vecArg(a, 1)))
		},
		"buildTextBody": func(a []any) (any, error) {
			return BuildTextBody(vecObj(a[0]), ctxOf(vecArg(a, 1)))
		},
		"notify": func(a []any) (any, error) {
			return channel(rsStr(a[0]), vecObj(a[3])).Notify(vecObj(a[1]), ctxOf(a[2]))
		},
		"notifyAll": func(a []any) (any, error) {
			var chans []ApprovalChannel
			for _, c := range rsList(a[2]) {
				m := vecObj(c)
				chans = append(chans, channel(rsStr(m["kind"]), m))
			}
			return CreateApprovalDispatcher(chans).NotifyAll(vecObj(a[0]), ctxOf(a[1]))
		},
	})
}

func TestReputationAndForecastMatchTheReference(t *testing.T) {
	uw := rsSeedKey(t, "sweep/underwriter")
	score := func(v any) *float64 {
		if m := vecObj(v); m != nil {
			return rsOptNum(m["score"])
		}
		return nil
	}
	rsReplaySubset(t, "ref-core-sweep-java.json.gz", map[string]vecFn{
		"reputation": func(a []any) (any, error) { return Reputation(vecObj(a[0])), nil },
		"priceCoverage": func(a []any) (any, error) {
			return PriceCoverage(score(a[0]), jsF(a[1]), vecObj(vecArg(a, 2))), nil
		},
		"issueCoverageQuote": func(a []any) (any, error) {
			return IssueCoverageQuote(vecObj(a[0]), jsF(a[1]), uw, jsF(a[2]), jsF(a[3]), vecObj(vecArg(a, 4)))
		},
		"verifyCoverageQuote": func(a []any) (any, error) {
			u := rsStr(a[1])
			if u == "@u" {
				u = uw.Public
			}
			now := math.NaN()
			if f := rsOptNum(a[2]); f != nil {
				now = *f
			}
			return VerifyCoverageQuote(a[0], u, now), nil
		},
		"recommendPolicy": func(a []any) (any, error) { return RecommendPolicy(jsF(a[0]), jsF(a[1]), rsOptNum(vecArg(a, 2))) },
		"autonomyBoundOf": func(a []any) (any, error) {
			f := AutonomyBoundOf(vecObj(a[0]))
			if math.IsNaN(f) || math.IsInf(f, 0) {
				return nil, nil // JSON.stringify prints a non-finite number as null
			}
			return rsN(f), nil
		},
	})
}

func TestDlpFreezeAndImmuneBasics(t *testing.T) {
	if !IsFrozen(nil, "a") {
		t.Fatal("a malformed freeze set fails closed")
	}
	s, err := FreezeAgent(EmptyFreeze(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if s, err = FreezeAgent(s, "a"); err != nil {
		t.Fatal(err)
	}
	if l := s["frozen"].([]any); len(l) != 2 || l[0] != "a" || l[1] != "b" {
		t.Fatalf("frozen set not sorted: %v", l)
	}
	if lvl := ImmuneAssess(InitialImmuneState())["level"]; lvl != "calm" {
		t.Fatalf("an empty history is calm, got %v", lvl)
	}
	if lvl := ImmuneAssess(map[string]any{})["level"]; lvl != "high" {
		t.Fatalf("a malformed state is the maximal threat, got %v", lvl)
	}
}
