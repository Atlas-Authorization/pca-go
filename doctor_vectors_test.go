package pca

// Replays the pca-doctor reference corpus: scrubbing, the clock / proxy / suites / root-caveat / enforcement checks, results
// formatting, configuration and the CLI, over scripted fetches and a scripted library probe.
//
// Skipped cases:
//   - scrubText outputs that end in a lone surrogate (a UTF-16 cut through a surrogate pair): the Go comparison goes through
//     encoding/json, which cannot carry one.
//
// Not replayed: the replay-store checks (they need an adapter and the conformance kit) and loading another deployed copy of the
// library (pcaDir), which a Go program cannot probe.

import (
	"errors"
	"testing"
)

type docTestEnv struct {
	t         float64
	idx       map[string]int
	responses map[string]any
}

func newDocTestEnv(spec any) *docTestEnv {
	m := vecObj(spec)
	t, _ := jsNum(m["now"])
	r, _ := m["responses"].(map[string]any)
	return &docTestEnv{t: t, idx: map[string]int{}, responses: r}
}

func (e *docTestEnv) fetch(u, _ string, _ map[string]string, _ float64) (*DoctorResponse, error) {
	lst, ok := e.responses[u].([]any)
	if !ok {
		return nil, errors.New("no route " + u)
	}
	i := e.idx[u]
	e.idx[u] = i + 1
	if i >= len(lst) {
		i = len(lst) - 1
	}
	rsp := vecObj(lst[i])
	if rtt, ok := jsNum(rsp["rtt"]); ok {
		e.t += rtt
	}
	if th, ok := rsp["throw"].(string); ok && th != "" {
		return nil, errors.New(th)
	}
	h := map[string]string{}
	if d, ok := rsp["date"].(string); ok {
		h["date"] = d
	}
	if rl, ok := rsp["rl"].(string); ok {
		h["ratelimit-remaining"] = rl
	}
	return &DoctorResponse{Headers: h}, nil
}

func (e *docTestEnv) now() float64 { return e.t }

// docTestPca scripts the library under test the way the reference's stand-in module decides.
func docTestPca(spec map[string]any) func(*string) (*DoctorPca, error) {
	return func(*string) (*DoctorPca, error) {
		if th, ok := spec["throws"].(string); ok && th != "" {
			return nil, errors.New(th)
		}
		behavior := vecStr(spec, "behavior")
		return &DoctorPca{Version: vecStr(spec, "version"), Path: vecStr(spec, "path"), Probe: func(cv map[string]any, amount float64) (any, error) {
			allow := func() any { return map[string]any{"allowed": true, "reasons": []any{}} }
			deny := func(r ...any) any { return map[string]any{"allowed": false, "reasons": r} }
			switch behavior {
			case "throws":
				return nil, errors.New("boom")
			case "allow-all":
				return allow(), nil
			case "deny-all":
				return deny("denied", jsNumber(7)), nil
			case "nonarray-reasons":
				return map[string]any{"allowed": false, "reasons": "x"}, nil
			}
			if cv["type"] == "max_spend" {
				usd, _ := jsNum(cv["usd"])
				if behavior == "ignore-max" || amount <= usd {
					return allow(), nil
				}
				return deny("over max_spend"), nil
			}
			if behavior == "ignore-unknown" {
				return allow(), nil
			}
			return deny("unknown caveat type"), nil
		}}, nil
	}
}

func docTestResults(v any) []map[string]any {
	out := []map[string]any{}
	if l, ok := v.([]any); ok {
		for _, x := range l {
			out = append(out, vecObj(x))
		}
	}
	return out
}

func docTestStrings(v any) []string {
	out := []string{}
	if l, ok := v.([]any); ok {
		for _, x := range l {
			s, _ := x.(string)
			out = append(out, s)
		}
	}
	return out
}

func docTestEnvMap(v any) map[string]string {
	out := map[string]string{}
	for k, x := range vecObj(v) {
		s, _ := x.(string)
		out[k] = s
	}
	return out
}

func docTestArgs(a *DoctorArgs) map[string]any {
	m := map[string]any{"flags": a.Flags, "only": docStrings(a.Only), "json": a.JSON, "strict": a.Strict, "help": a.Help}
	if a.Config != nil {
		m["config"] = *a.Config
	}
	return m
}

func TestDoctorVectors(t *testing.T) {
	cfg0 := func(a []any) any { return vecArg(a, 0) }
	replayVectors(t, "ref-doctor.json.gz", map[string]vecFn{
		"consts": func([]any) (any, error) {
			return map[string]any{"USAGE": DoctorUsage, "CHECK_GROUPS": docStrings(DoctorCheckGroups), "DEFAULT_REQUIRED": docStrings(DoctorDefaultRequired),
				"ROOT_CAVEAT_MIN_VERSION": DoctorRootCaveatMinVersion, "DEFAULT_REFERENCE_URL": DoctorDefaultReferenceURL,
				"SUITES_REMEDIATION": DoctorSuitesRemediation, "PQ_REMEDIATION": DoctorPqRemediation, "CLOCK_REMEDIATION": DoctorClockRemediation,
				"PROXY_REMEDIATION": DoctorProxyRemediation, "ATOMICITY_REMEDIATION": DoctorAtomicityRemediation,
				"DURABILITY_REMEDIATION": DoctorDurabilityRemediation, "CAVEAT_REMEDIATION": DoctorCaveatRemediation}, nil
		},
		"scrubText": func(a []any) (any, error) {
			s := DoctorScrubText(cfg0(a))
			if hasLoneSurrogate(s) {
				return nil, vecSkip("output ends in a lone surrogate")
			}
			return s, nil
		},
		"scrubDeep":          func(a []any) (any, error) { return DoctorScrubDeep(cfg0(a), 0), nil },
		"checkAllowedSuites": func(a []any) (any, error) { return DoctorCheckAllowedSuites(cfg0(a)), nil },
		"checkPqBinding":     func(a []any) (any, error) { return DoctorCheckPqBinding(cfg0(a)) },
		"checkProxyConfig":   func(a []any) (any, error) { return DoctorCheckProxyConfig(cfg0(a)), nil },
		"checkEnforcement":   func(a []any) (any, error) { return DoctorCheckEnforcement(cfg0(a)) },
		"testNetIp":          func(a []any) (any, error) { return DoctorTestNetIP(ControlMulberry32(cfg0(a))), nil },
		"forgedHeaders":      func(a []any) (any, error) { return DoctorForgedHeaders(ControlMulberry32(cfg0(a))), nil },
		"compareVersion": func(a []any) (any, error) {
			s, _ := a[0].(string)
			u, _ := a[1].(string)
			return DoctorCompareVersion(s, u), nil
		},
		"configProblems": func(a []any) (any, error) { return DoctorConfigProblems(cfg0(a)), nil },
		"readDate": func(a []any) (any, error) {
			e := newDocTestEnv(vecArg(a, 1))
			return DoctorReadDate("https://api.example.com", e.fetch, e.now, 1000), nil
		},
		"checkClock": func(a []any) (any, error) {
			e := newDocTestEnv(vecArg(a, 1))
			return DoctorCheckClock(cfg0(a), e.fetch, e.now), nil
		},
		"checkProxyProbe": func(a []any) (any, error) {
			e := newDocTestEnv(vecArg(a, 1))
			return DoctorCheckProxyProbe(cfg0(a), e.fetch, ControlMulberry32(jsNumber(7)))
		},
		"checkRootCaveats": func(a []any) (any, error) {
			return DoctorCheckRootCaveats(cfg0(a), docTestPca(vecObj(vecArg(a, 1)))), nil
		},
		"verdictOf": func(a []any) (any, error) {
			return DoctorVerdictOf(docTestResults(cfg0(a)), vecArg(a, 1) == true), nil
		},
		"formatResults": func(a []any) (any, error) {
			target, _ := vecArg(a, 1).(string)
			return DoctorFormatResults(docTestResults(cfg0(a)), target, vecArg(a, 2) == true), nil
		},
		"configFromEnv": func(a []any) (any, error) { return DoctorConfigFromEnv(docTestEnvMap(cfg0(a))) },
		"mergeConfig": func(a []any) (any, error) {
			var cs []map[string]any
			for _, x := range a {
				cs = append(cs, vecObj(x))
			}
			return DoctorMergeConfig(cs...)
		},
		"parseDoctorArgs": func(a []any) (any, error) {
			p, err := DoctorParseArgs(docTestStrings(cfg0(a)))
			if err != nil {
				return nil, err
			}
			return docTestArgs(p), nil
		},
		"main": func(a []any) (any, error) {
			out, errs := []any{}, []any{}
			code := DoctorMain(docTestStrings(cfg0(a)), docTestEnvMap(vecArg(a, 1)), func(s string) { out = append(out, s) }, func(s string) { errs = append(errs, s) }, DoctorDeps{})
			return map[string]any{"code": code, "out": out, "err": errs}, nil
		},
		"runDoctor": func(a []any) (any, error) {
			var only []string
			if vecArg(a, 1) != nil {
				only = docTestStrings(vecArg(a, 1))
			}
			e := newDocTestEnv(vecArg(a, 2))
			res := DoctorRun(cfg0(a), only, DoctorDeps{Fetch: e.fetch, Now: e.now, Load: docTestPca(vecObj(vecArg(a, 3)))})
			out := make([]any, len(res))
			for i, r := range res {
				out[i] = r
			}
			return out, nil
		},
	})
}
