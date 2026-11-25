package pca

// Replay of the reference corpus for the wallet side of the Intent Layer v2 (signed answers, friction tiers, cell coordinates,
// noise numerics, canaries, approval fatigue, risk-priced escalation, the trusted card, clarification, population priors,
// question delivery and the question channel). Keys are derived from seed labels, the clock and the randomness are scripted.
// Doubles from transcendental functions compare to a relative 1e-12, except the values that gate a decision (clopperPearsonUpper,
// estimateNoise, etaUnderLoad, noiseState, admissionPolicy), which compare exactly. Cases whose reference answer holds a lone UTF-16 surrogate
// are skipped: a Go string cannot carry one through JSON.

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

type wtEnv struct {
	omegaJSON map[string]any
	omegas    map[string]*WalletOmega
}

func wtSeed(label string) []byte {
	h := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	return h[:]
}

func wtSub(x any, e *wtEnv) any {
	switch t := x.(type) {
	case []any:
		out := make([]any, len(t))
		for i, v := range t {
			out[i] = wtSub(v, e)
		}
		return out
	case map[string]any:
		if len(t) == 1 {
			if id, ok := t["$omega"].(string); ok {
				return e.omegaJSON[id]
			}
			if l, ok := t["$seed"].(string); ok {
				return wtSeed(l)
			}
		}
		out := make(map[string]any, len(t))
		for k, v := range t {
			out[k] = wtSub(v, e)
		}
		recordKeyOrder(out, jsKeys(t))
		return out
	}
	return x
}

func wtNum(v any) (float64, error) {
	f, ok := jsNum(v)
	if !ok {
		return 0, errors.New("not a number")
	}
	return f, nil
}

func wtMap(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("not an object")
	}
	return m, nil
}

func wtStr(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", errors.New("not a string")
	}
	return s, nil
}

func wtInts(v any) ([]int, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([]int, len(l))
	for i, x := range l {
		f, ok := walletIntegral(x)
		if !ok {
			return nil, errors.New("not an integer")
		}
		out[i] = int(f)
	}
	return out, nil
}

func wtBox(v any) ([][]int, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([][]int, len(l))
	for i, x := range l {
		ids, err := wtInts(x)
		if err != nil {
			return nil, err
		}
		out[i] = ids
	}
	return out, nil
}

func wtRefs(v any) ([]WalletCellRef, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := make([]WalletCellRef, len(l))
	for i, x := range l {
		m, err := wtMap(x)
		if err != nil {
			return nil, err
		}
		verb, err := wtStr(m["verb"])
		if err != nil {
			return nil, err
		}
		idx, err := wtInts(m["idx"])
		if err != nil {
			return nil, err
		}
		out[i] = WalletCellRef{Verb: verb, Idx: idx}
	}
	return out, nil
}

func wtCounts(v any) (WalletNoiseCounts, error) {
	m, err := wtMap(v)
	if err != nil {
		return WalletNoiseCounts{}, err
	}
	get := func(k string) (int, error) {
		f, ok := walletIntegral(m[k])
		if !ok {
			return 0, errors.New("count is not an integer")
		}
		return int(f), nil
	}
	var c WalletNoiseCounts
	if c.FalseYes, err = get("falseYes"); err != nil {
		return c, err
	}
	if c.CorrectNo, err = get("correctNo"); err != nil {
		return c, err
	}
	if c.FalseNo, err = get("falseNo"); err != nil {
		return c, err
	}
	c.CorrectYes, err = get("correctYes")
	return c, err
}

func wtFatigue(v any) (WalletFatigue, error) {
	if v == nil {
		return WalletDefaultFatigue, nil
	}
	m, err := wtMap(v)
	if err != nil {
		return WalletFatigue{}, err
	}
	var f WalletFatigue
	for _, p := range []struct {
		k string
		d *float64
	}{{"betaF", &f.BetaF}, {"etaStop", &f.EtaStop}, {"deltaC", &f.DeltaC}, {"delta", &f.Delta}} {
		if *p.d, err = wtNum(m[p.k]); err != nil {
			return f, err
		}
	}
	f.FreezeOn, _ = m["freezeOn"].(string)
	f.AssumeNoiseFree = jsTruthy(m["assumeNoiseFree"])
	return f, nil
}

func wtSeq(xs any) (WalletRand, error) {
	l, ok := xs.([]any)
	if !ok {
		return nil, errors.New("rands is not a list")
	}
	i := 0
	return func() (float64, error) {
		if i >= len(l) {
			return 0, errors.New("rand exhausted")
		}
		f, err := wtNum(l[i])
		i++
		return f, err
	}, nil
}

func wtSet(v any) (map[string]bool, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, errors.New("not a list")
	}
	out := map[string]bool{}
	for _, x := range l {
		s, err := wtStr(x)
		if err != nil {
			return nil, err
		}
		out[s] = true
	}
	return out, nil
}

func wtEmptyNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func wtHasLone(v any) bool {
	switch t := v.(type) {
	case string:
		return hasLoneSurrogate(t)
	case []any:
		for _, x := range t {
			if wtHasLone(x) {
				return true
			}
		}
	case []map[string]any:
		for _, x := range t {
			if wtHasLone(x) {
				return true
			}
		}
	case []string:
		for _, x := range t {
			if hasLoneSurrogate(x) {
				return true
			}
		}
	case map[string]any:
		for k, x := range t {
			if hasLoneSurrogate(k) || wtHasLone(x) {
				return true
			}
		}
	case map[string]string:
		for k, x := range t {
			if hasLoneSurrogate(k) || hasLoneSurrogate(x) {
				return true
			}
		}
	}
	return false
}

func wtLone(f vecFn) vecFn {
	return func(a []any) (any, error) {
		r, err := f(a)
		if err == nil && wtHasLone(r) {
			return nil, vecSkip("the reference answer holds a lone UTF-16 surrogate")
		}
		return r, err
	}
}

func wtClose(want, got any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for k, x := range w {
			y, has := g[k]
			if !has || !wtClose(x, y) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !wtClose(w[i], g[i]) {
				return false
			}
		}
		return true
	}
	wf, wok := jsNum(want)
	gf, gok := jsNum(got)
	if wok && gok {
		if wf == gf {
			return true
		}
		return math.Abs(wf-gf) <= 1e-12*math.Max(math.Abs(wf), math.Abs(gf)) || math.Abs(wf-gf) <= 1e-15
	}
	return baseCanon(want) == baseCanon(got)
}

// wtHookBodies compares two webhook outputs, reading each request body as JSON (the reference keeps insertion order).
func wtHookCmp(want, got any) bool {
	w, ok1 := want.(map[string]any)
	g, ok2 := got.(map[string]any)
	if !ok1 || !ok2 {
		return false
	}
	norm := func(m map[string]any) map[string]any {
		out := make(map[string]any, len(m))
		for k, v := range m {
			out[k] = v
		}
		calls, _ := m["calls"].([]any)
		cs := make([]any, len(calls))
		for i, c := range calls {
			cm, _ := c.(map[string]any)
			nc := make(map[string]any, len(cm))
			for k, v := range cm {
				nc[k] = v
			}
			if body, isS := cm["body"].(string); isS {
				if parsed, err := ParseJSONLenient([]byte(body)); err == nil {
					nc["body"] = normalizeJSON(parsed)
				}
			}
			cs[i] = nc
		}
		out["calls"] = cs
		return out
	}
	return baseCanon(norm(w)) == baseCanon(norm(g))
}

func wtOmegas(t *testing.T) *wtEnv {
	t.Helper()
	e := &wtEnv{omegas: map[string]*WalletOmega{}}
	baseEachOrdered(t, "ref-wallet.json.gz", func(c *baseCase) {
		if c.Fn != "omegas" || e.omegaJSON != nil {
			return
		}
		e.omegaJSON, _ = c.Out.(map[string]any)
	})
	if e.omegaJSON == nil {
		t.Fatal("no outcome spaces in the corpus")
	}
	for id, v := range e.omegaJSON {
		om, err := WalletOmegaFromJSON(v)
		if err != nil {
			t.Fatal(err)
		}
		e.omegas[id] = om
	}
	return e
}

func (e *wtEnv) vs(id, verb any) (*WalletVerb, error) {
	ids, err := wtStr(id)
	if err != nil {
		return nil, err
	}
	vb, err := wtStr(verb)
	if err != nil {
		return nil, err
	}
	om := e.omegas[ids]
	if om == nil || om.Verb(vb) == nil {
		return nil, errors.New("unknown outcome space or verb")
	}
	return om.Verb(vb), nil
}

// idxFor checks a cell index against the verb's space: the reference throws on an index outside it.
func wtIdxFor(vs *WalletVerb, v any) ([]int, error) {
	idx, err := wtInts(v)
	if err != nil {
		return nil, err
	}
	if len(idx) < len(vs.Dims) {
		return nil, errors.New("index too short")
	}
	for k := range vs.Dims {
		if idx[k] < 0 || idx[k] >= WalletCellCount(&vs.Dims[k]) {
			return nil, errors.New("index out of range")
		}
	}
	return idx, nil
}

func wtScript(v any) []any {
	l, _ := v.([]any)
	return l
}

func wtFloatPtr(m map[string]any, k string) *float64 {
	v, has := m[k]
	if !has {
		return nil
	}
	f, ok := jsNum(v)
	if !ok {
		return nil
	}
	return &f
}

func TestWalletVectors(t *testing.T) {
	e := wtOmegas(t)
	omegaOf := func(v any) (*WalletOmega, error) { return WalletOmegaFromJSON(wtSub(v, e)) }
	fns := map[string]vecFn{}
	add := func(name string, f vecFn) { fns[name] = wtLone(f) }

	// the outcome spaces are the reference's own input fixture (no native builds them): every one must load through the native reader
	// (done above) and is handed back as it came
	fns["omegas"] = func([]any) (any, error) {
		for id, v := range e.omegaJSON {
			if _, err := WalletOmegaFromJSON(v); err != nil {
				return nil, fmt.Errorf("outcome space %s: %w", id, err)
			}
		}
		return e.omegaJSON, nil
	}
	add("constants", func([]any) (any, error) {
		tiers := func(xs []string) []any {
			out := make([]any, len(xs))
			for i, x := range xs {
				out[i] = x
			}
			return out
		}
		labels := map[string]any{}
		for k, v := range WalletReasonLabels {
			labels[k] = v
		}
		return map[string]any{
			"FRICTION_ORDER": tiers(WalletFrictionOrder), "INTENT_ANSWER_SIG_DOMAIN": WalletAnswerSigDomain, "INTENT_ANSWER_REF_DOMAIN": WalletAnswerRefDomain,
			"INTENT_TYPED_DOMAIN": WalletTypedDomain, "INTENT_DEVICE_CHALLENGE_DOMAIN": WalletDeviceChallengeDomain, "MIN_HOLD_MS": wN(WalletMinHoldMs),
			"PROVENANCE_ORDER": tiers(WalletProvenanceOrder), "DEFAULT_FRICTION_THRESHOLDS": WalletFrictionThresholds, "CARD_DOMAIN": WalletCardDomain,
			"CLARIFY_REASONS": tiers(WalletClarifyReasons), "REASON_LABELS": labels, "MAX_CANDIDATES": wN(WalletMaxCandidates),
			"EMPTY_NOISE": WalletNoiseCounts{}, "NOISE_PRIOR": map[string]any{"a": WalletNoisePrior.A, "b": WalletNoisePrior.B},
			"DEFAULT_FATIGUE": map[string]any{"betaF": WalletDefaultFatigue.BetaF, "etaStop": WalletDefaultFatigue.EtaStop, "deltaC": WalletDefaultFatigue.DeltaC,
				"freezeOn": WalletDefaultFatigue.FreezeOn, "assumeNoiseFree": WalletDefaultFatigue.AssumeNoiseFree, "delta": WalletDefaultFatigue.Delta},
			"PPM": wN(WalletPPM), "MAX_MULTIPLIER_PPM": wN(WalletMaxMultiplierPPM), "POPULATION_VOTE_DOMAIN": WalletPopulationVoteDomain, "BETA_MAX": WalletBetaMax,
		}, nil
	})

	// ---- friction ----
	add("isFrictionTier", func(a []any) (any, error) { return WalletIsFrictionTier(vecArg(a, 0)), nil })
	add("frictionRank", func(a []any) (any, error) { return WalletFrictionRank(vecArg(a, 0)), nil })
	add("isProvenanceLevel", func(a []any) (any, error) { return WalletIsProvenanceLevel(vecArg(a, 0)), nil })
	add("worstProvenance", func(a []any) (any, error) { return WalletWorstProvenance(vecArg(a, 0)) })
	add("satisfiesTier", func(a []any) (any, error) { return WalletSatisfiesTier(vecArg(a, 0), vecArg(a, 1)), nil })
	add("maxFriction", func(a []any) (any, error) { return WalletMaxFriction(a...), nil })
	add("frictionFor", func(a []any) (any, error) {
		inp, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		var th map[string]any
		if len(a) > 1 {
			if th, err = wtMap(a[1]); err != nil {
				return nil, err
			}
		}
		return WalletFrictionFor(inp, th)
	})

	// ---- the action, coordinates and the signed answer ----
	add("pcaActionDigest", func(a []any) (any, error) { return WalletActionDigest(vecArg(a, 0)) })
	add("actionValuesOf", func(a []any) (any, error) { return WalletActionValues(vecArg(a, 0)) })
	add("isB64u32", func(a []any) (any, error) { return WalletIsB64u32(vecArg(a, 0)), nil })
	add("isObj", func(a []any) (any, error) { return WalletIsObj(vecArg(a, 0)), nil })
	add("coordsError", func(a []any) (any, error) { return wtEmptyNil(WalletCoordsError(vecArg(a, 0))), nil })
	add("answerShapeError", func(a []any) (any, error) { return wtEmptyNil(WalletAnswerShapeError(vecArg(a, 0))), nil })
	add("signIntentAnswer", func(a []any) (any, error) {
		m, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		seed, ok := wtSub(vecArg(a, 1), e).([]byte)
		if !ok {
			return nil, errors.New("no seed")
		}
		return WalletSignIntentAnswer(m, seed)
	})
	add("verifyIntentAnswer", func(a []any) (any, error) {
		var principals []string
		if len(a) > 1 && a[1] != nil {
			l, ok := a[1].([]any)
			if !ok {
				return nil, vecSkip("principals that are not a list")
			}
			principals = []string{}
			for _, x := range l {
				s, isS := x.(string)
				if !isS {
					return nil, vecSkip("a principal that is not a string")
				}
				principals = append(principals, s)
			}
		}
		r := WalletVerifyIntentAnswer(vecArg(a, 0), principals)
		if s, _ := r["reason"].(string); strings.HasPrefix(s, "malformed answer:") {
			r["reason"] = "malformed answer"
		}
		return r, nil
	})
	add("answerRef", func(a []any) (any, error) { return WalletAnswerRef(vecArg(a, 0)) })
	add("typedDigest", func(a []any) (any, error) {
		q, err := wtStr(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		v, err := wtStr(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		return WalletTypedDigest(q, v)
	})
	add("deviceChallenge", func(a []any) (any, error) {
		m, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		q, err1 := wtStr(m["questionId"])
		r, err2 := wtStr(m["renderedDigest"])
		y, err3 := walletIntegral(m["y"])
		if err1 != nil || err2 != nil || !err3 {
			return nil, errors.New("bad challenge input")
		}
		return WalletDeviceChallenge(q, r, int(y), m["actionDigest"])
	})

	// ---- statistics ----
	add("lnGamma", func(a []any) (any, error) {
		x, err := wtNum(vecArg(a, 0))
		return WalletLnGamma(x), err
	})
	add("betacf", func(a []any) (any, error) {
		x, e1 := wtNum(vecArg(a, 0))
		y, e2 := wtNum(vecArg(a, 1))
		z, e3 := wtNum(vecArg(a, 2))
		if e1 != nil || e2 != nil || e3 != nil {
			return nil, errors.New("not numbers")
		}
		return WalletBetacf(x, y, z), nil
	})
	three := func(f func(x, y, z float64) (float64, error)) vecFn {
		return func(a []any) (any, error) {
			x, e1 := wtNum(vecArg(a, 0))
			y, e2 := wtNum(vecArg(a, 1))
			z, e3 := wtNum(vecArg(a, 2))
			if e1 != nil || e2 != nil || e3 != nil {
				return nil, errors.New("not numbers")
			}
			return f(x, y, z)
		}
	}
	add("betaInc", three(WalletBetaInc))
	add("betaQuantile", three(WalletBetaQuantile))
	add("clopperPearsonUpper", three(ClopperPearsonUpper))
	add("binEnt", func(a []any) (any, error) {
		p, err := wtNum(vecArg(a, 0))
		return WalletBinEnt(p), err
	})

	// ---- canaries and fatigue ----
	add("recordCanary", func(a []any) (any, error) {
		n, err := wtCounts(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		x, e1 := walletIntegral(vecArg(a, 1))
		y, e2 := walletIntegral(vecArg(a, 2))
		if !e1 || !e2 {
			return nil, errors.New("not integers")
		}
		r := WalletRecordCanary(n, int(x), int(y))
		// the reference spreads the counts, so a member beyond the four rides along; the typed struct cannot hold it
		out := map[string]any{"falseYes": jsNumber(float64(r.FalseYes)), "correctNo": jsNumber(float64(r.CorrectNo)),
			"falseNo": jsNumber(float64(r.FalseNo)), "correctYes": jsNumber(float64(r.CorrectYes))}
		in, _ := wtMap(vecArg(a, 0))
		for k, v := range in {
			if _, own := out[k]; !own {
				out[k] = v
			}
		}
		return out, nil
	})
	add("estimateNoise", func(a []any) (any, error) {
		n, err := wtCounts(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		dc := 0.05
		if len(a) > 1 {
			if dc, err = wtNum(a[1]); err != nil {
				return nil, err
			}
		}
		return WalletEstimateNoise(n, dc)
	})
	add("cellKey", func(a []any) (any, error) {
		verb, err := wtStr(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		idx, err := wtInts(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		return WalletCellKey(verb, idx), nil
	})
	add("boundaryNeighbours", func(a []any) (any, error) {
		om, err := omegaOf(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		refs, err := wtRefs(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		return WalletBoundaryNeighbours(om, refs)
	})
	add("pickCanary", func(a []any) (any, error) {
		m, err := wtMap(wtSub(vecArg(a, 0), e))
		if err != nil {
			return nil, err
		}
		om, err := WalletOmegaFromJSON(m["omega"])
		if err != nil {
			return nil, err
		}
		confirmed, err := wtRefs(m["confirmed"])
		if err != nil {
			return nil, err
		}
		knownYes, err := wtRefs(m["knownYes"])
		if err != nil {
			return nil, err
		}
		exclude, err := wtSet(m["exclude"])
		if err != nil {
			return nil, err
		}
		no, err := wtMap(m["knownNo"])
		if err != nil {
			return nil, err
		}
		rnd, err := wtSeq(m["rands"])
		if err != nil {
			return nil, err
		}
		ctx := WalletCanaryCtx{Omega: om, Confirmed: confirmed, KnownYes: knownYes, Exclude: exclude, Rand: rnd, LowHarmSession: jsTruthy(m["lowHarmSession"]),
			KnownNo: func(verb string, idx []int) string { s, _ := no[WalletCellKey(verb, idx)].(string); return s }}
		if ctx.CanariesSoFar, err = wtNum(m["canariesSoFar"]); err != nil {
			return nil, err
		}
		if m["rho"] != nil {
			rho, err := wtNum(m["rho"])
			if err != nil {
				return nil, err
			}
			ctx.Rho = &rho
		}
		return WalletPickCanary(ctx)
	})
	add("etaUnderLoad", three(WalletEtaUnderLoad))
	add("noiseState", func(a []any) (any, error) {
		n, err := wtCounts(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		recent, err := wtNum(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		model, err := wtFatigue(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		return WalletComputeNoiseState(n, recent, model)
	})
	add("admissionPolicy", func(a []any) (any, error) {
		m, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		var s WalletNoiseState
		if s.EtaPos, err = wtNum(m["etaPos"]); err != nil {
			return nil, err
		}
		if s.EtaPosBar, err = wtNum(m["etaPosBar"]); err != nil {
			return nil, err
		}
		if s.EtaNegBar, err = wtNum(m["etaNegBar"]); err != nil {
			return nil, err
		}
		model, err := wtFatigue(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		return WalletAdmissionPolicy(s, model)
	})
	add("doubleConfirmed", func(a []any) (any, error) {
		l, ok := vecArg(a, 0).([]any)
		if !ok {
			return nil, errors.New("not a list")
		}
		recs := make([]WalletConfirmation, len(l))
		for i, x := range l {
			m, err := wtMap(x)
			if err != nil {
				return nil, err
			}
			if recs[i].Screen, err = wtNum(m["screen"]); err != nil {
				return nil, err
			}
			recs[i].Tier, _ = m["tier"].(string)
		}
		return WalletDoubleConfirmed(recs), nil
	})
	add("slidingWindow", func(a []any) (any, error) {
		win := 3600000.0
		if w := vecArg(a, 0); w != nil {
			f, err := wtNum(w)
			if err != nil {
				return nil, err
			}
			win = f
		}
		c, err := NewWalletSlidingWindow(win)
		if err != nil {
			return nil, err
		}
		out := []any{}
		for _, opv := range wtScript(vecArg(a, 1)) {
			op, _ := opv.([]any)
			if len(op) < 2 {
				return nil, errors.New("bad op")
			}
			now, err := wtNum(op[1])
			if err != nil {
				out = append(out, map[string]any{"err": true})
				continue
			}
			if op[0] == "count" {
				out = append(out, map[string]any{"v": wN(c.Count(now))})
				continue
			}
			limit, err := wtNum(vecArg(op, 2))
			if err != nil {
				out = append(out, map[string]any{"err": true})
				continue
			}
			ok, err := c.TryAdd(now, limit)
			if err != nil {
				out = append(out, map[string]any{"err": true})
				continue
			}
			out = append(out, map[string]any{"v": ok})
		}
		return out, nil
	})

	// ---- risk-priced escalation ----
	seedOf := func(v any) ([]byte, error) {
		s, ok := wtSub(v, e).([]byte)
		if !ok {
			return nil, errors.New("no seed")
		}
		return s, nil
	}
	signer := func(f func(map[string]any, []byte) (map[string]any, error)) vecFn {
		return func(a []any) (any, error) {
			m, err := wtMap(vecArg(a, 0))
			if err != nil {
				return nil, err
			}
			s, err := seedOf(vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			return f(m, s)
		}
	}
	add("signPricingConfig", signer(WalletSignPricingConfig))
	add("signAnswer", signer(WalletSignAnswer))
	add("signAutonomyRaise", signer(WalletSignAutonomyRaise))
	add("pricingConfigError", func(a []any) (any, error) { return wtEmptyNil(WalletPricingConfigError(vecArg(a, 0))), nil })
	add("freshCalibration", func([]any) (any, error) { return WalletFreshCalibration(), nil })
	add("decideEscalation", func(a []any) (any, error) {
		cfg, ok := vecArg(a, 0).(map[string]any)
		if !ok {
			return walletDecision(true, "config_malformed"), nil
		}
		return WalletDecideEscalation(cfg, vecArg(a, 1), vecArg(a, 2)), nil
	})
	add("updateCalibration", func(a []any) (any, error) {
		cfg, ok := vecArg(a, 0).(map[string]any)
		if !ok {
			return vecArg(a, 1), nil
		}
		cal, err := wtMap(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		answers, _ := vecArg(a, 2).([]any)
		risks, err := wtMap(vecArg(a, 3))
		if err != nil {
			return nil, err
		}
		return WalletUpdateCalibration(cfg, cal, answers, risks)
	})
	add("applyAutonomyRaise", func(a []any) (any, error) {
		cfg, err1 := wtMap(vecArg(a, 0))
		raise, err2 := wtMap(vecArg(a, 1))
		s, err3 := seedOf(vecArg(a, 2))
		if err1 != nil || err2 != nil || err3 != nil {
			return nil, errors.New("bad input")
		}
		return WalletApplyAutonomyRaise(cfg, raise, s)
	})

	// ---- the outcome space ----
	add("omega.verbCellCount", func(a []any) (any, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		return WalletVerbCellCount(vs), nil
	})
	dimOf := func(a []any) (*WalletDim, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		k, ok := walletIntegral(vecArg(a, 2))
		if !ok || k < 0 || int(k) >= len(vs.Dims) {
			return nil, errors.New("no such dimension")
		}
		return &vs.Dims[int(k)], nil
	}
	add("omega.cellCount", func(a []any) (any, error) {
		d, err := dimOf(a)
		if err != nil {
			return nil, err
		}
		return WalletCellCount(d), nil
	})
	add("omega.numCells", func(a []any) (any, error) {
		d, err := dimOf(a)
		if err != nil {
			return nil, err
		}
		if d.Kind != "num" {
			return nil, errors.New("not a numeric dimension")
		}
		return WalletNumCells(d), nil
	})
	add("omega.labelOf", func(a []any) (any, error) {
		p, err := wtStr(vecArg(a, 0))
		return WalletLabelOf(p), err
	})
	add("omega.decodeCell", func(a []any) (any, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		f, ok := walletIntegral(vecArg(a, 2))
		if !ok || f < 0 {
			return nil, errors.New("not a cell number")
		}
		return WalletDecodeCell(vs, int(f)), nil
	})
	add("omega.cellStats", func(a []any) (any, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		idx, err := wtIdxFor(vs, vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		m, h := WalletCellStats(vs, idx, nil)
		return map[string]any{"mass": m, "harm": h}, nil
	})
	add("omega.cellRep", func(a []any) (any, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		idx, err := wtIdxFor(vs, vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		return WalletCellRep(vs, idx), nil
	})
	add("omega.cellOf", func(a []any) (any, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		o, err := wtMap(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		values, has := o["values"]
		if !has {
			return nil, errors.New("outcome has no values")
		}
		idx, ok := WalletCellOf(vs, values)
		if !ok {
			return nil, nil
		}
		return idx, nil
	})
	add("coordKeyOf", func(a []any) (any, error) {
		p, err := wtStr(vecArg(a, 0))
		return WalletCoordKeyOf(p), err
	})
	add("resolveCoords", func(a []any) (any, error) {
		om, err := omegaOf(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		r, err := WalletResolveCoords(om, vecArg(a, 1), vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		if !r.OK {
			return map[string]any{"ok": false, "reason": r.Reason}, nil
		}
		return map[string]any{"ok": true, "verb": r.VS.Verb, "box": r.Box}, nil
	})
	add("coordsOfBox", func(a []any) (any, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		box, err := wtBox(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		for k := range vs.Dims {
			if k >= len(box) {
				return nil, errors.New("box too short")
			}
			for _, i := range box[k] {
				if i < 0 || i >= WalletCellCount(&vs.Dims[k]) {
					return nil, errors.New("box index out of range")
				}
			}
		}
		return WalletCoordsOfBox(vs, box)
	})
	add("coordsOfCell", func(a []any) (any, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		idx, err := wtIdxFor(vs, vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		return WalletCoordsOfCell(vs, idx)
	})
	add("cellInBox", func(a []any) (any, error) {
		box, err := wtBox(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		idx, err := wtInts(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		return WalletCellInBox(box, idx), nil
	})
	add("boxCells", func(a []any) (any, error) {
		box, err := wtBox(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletBoxCells(box), nil
	})
	add("boxSize", func(a []any) (any, error) {
		box, err := wtBox(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletBoxSize(box), nil
	})
	add("cellOfAction", func(a []any) (any, error) {
		ids, err := wtStr(vecArg(a, 0))
		if err != nil || e.omegas[ids] == nil {
			return nil, errors.New("unknown outcome space")
		}
		vs, idx, err := WalletCellOfAction(e.omegas[ids], vecArg(a, 1))
		if err != nil || vs == nil {
			return nil, err
		}
		return map[string]any{"verb": vs.Verb, "idx": idx}, nil
	})
	add("flatIndex", func(a []any) (any, error) {
		vs, err := e.vs(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		idx, err := wtIdxFor(vs, vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		return WalletFlatIndex(vs, idx), nil
	})

	// ---- the card and clarification ----
	add("cleanText", func(a []any) (any, error) {
		m, err := walletIntegral(vecArg(a, 1))
		if !err {
			return nil, errors.New("max is not an integer")
		}
		return WalletCleanText(vecArg(a, 0), int(m))
	})
	add("last4", func(a []any) (any, error) {
		s, err := wtStr(vecArg(a, 0))
		return WalletLast4(s), err
	})
	add("formatNumber", func(a []any) (any, error) {
		x, err := wtNum(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletFormatNumber(x, vecArg(a, 1)), nil
	})
	add("renderCard", func(a []any) (any, error) {
		x, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		id, err := wtStr(x["omegaId"])
		if err != nil || e.omegas[id] == nil {
			return nil, errors.New("unknown outcome space")
		}
		inp := make(map[string]any, len(x))
		for k, v := range x {
			if k != "omegaId" {
				inp[k] = v
			}
		}
		return WalletRenderCard(e.omegas[id], inp, nil)
	})
	add("cardDigest", func(a []any) (any, error) {
		m, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletCardDigest(m)
	})
	add("cardDigestMatches", func(a []any) (any, error) {
		m, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletCardDigestMatches(m)
	})
	add("cardText", func(a []any) (any, error) {
		m, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletCardText(m)
	})
	add("partialError", func(a []any) (any, error) {
		card, err1 := wtMap(vecArg(a, 0))
		p, err2 := wtMap(vecArg(a, 1))
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad input")
		}
		s, err := WalletPartialError(card, p)
		return wtEmptyNil(s), err
	})
	add("normalizeTyped", func(a []any) (any, error) {
		in, err1 := wtStr(vecArg(a, 0))
		mode, err2 := wtStr(vecArg(a, 1))
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad input")
		}
		s, ok, err := WalletNormalizeTyped(in, mode, vecArg(a, 2))
		if err != nil || !ok {
			return nil, err
		}
		return s, nil
	})
	add("expectedTyped", func(a []any) (any, error) {
		card, err1 := wtMap(vecArg(a, 0))
		action, err2 := wtMap(vecArg(a, 1))
		if err1 != nil || err2 != nil {
			return nil, errors.New("bad input")
		}
		s, ok, err := WalletExpectedTyped(card, action)
		if err != nil || !ok {
			return nil, err
		}
		return s, nil
	})
	add("parseClarifyRequest", func(a []any) (any, error) { return WalletParseClarifyRequest(vecArg(a, 0)), nil })
	add("informationGain", func(a []any) (any, error) {
		p, e1 := wtNum(vecArg(a, 0))
		x, e2 := wtNum(vecArg(a, 1))
		y, e3 := wtNum(vecArg(a, 2))
		if e1 != nil || e2 != nil || e3 != nil {
			return nil, errors.New("not numbers")
		}
		return WalletInformationGain(p, x, y), nil
	})
	add("planClarification", func(a []any) (any, error) {
		m, err := wtMap(wtSub(vecArg(a, 0), e))
		if err != nil {
			return nil, err
		}
		om, err := WalletOmegaFromJSON(m["omega"])
		if err != nil {
			return nil, err
		}
		v, err := wtMap(m["view"])
		if err != nil {
			return nil, err
		}
		p, err := wtMap(v["p"])
		if err != nil {
			return nil, err
		}
		vetoed, err1 := wtSet(v["vetoed"])
		ceiling, err2 := wtSet(v["ceiling"])
		asked, err3 := wtSet(m["asked"])
		if err1 != nil || err2 != nil || err3 != nil {
			return nil, errors.New("bad view")
		}
		cands, _ := m["candidates"].([]any)
		etaPos, e4 := wtNum(m["etaPos"])
		etaNeg, e5 := wtNum(m["etaNeg"])
		if e4 != nil || e5 != nil {
			return nil, errors.New("bad noise")
		}
		view := WalletView{
			P: func(verb string, idx []int) float64 {
				f, _ := jsNum(p[WalletCellKey(verb, idx)])
				return f
			},
			Vetoed:         func(verb string, idx []int) bool { return vetoed[WalletCellKey(verb, idx)] },
			OutsideCeiling: func(verb string, idx []int) bool { return ceiling[WalletCellKey(verb, idx)] },
		}
		return WalletPlanClarification(WalletPlanInput{Omega: om, View: view, Candidates: cands, Asked: asked, EtaPos: etaPos, EtaNeg: etaNeg})
	})

	// ---- population priors ----
	add("gaussianSigma", three(WalletGaussianSigma))
	add("gaussian", func(a []any) (any, error) {
		r, err := wtSeq(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletGaussian(r)
	})
	add("rrKeepProbability", func(a []any) (any, error) {
		x, err := wtNum(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletRRKeepProbability(x)
	})
	add("randomizedResponse", func(a []any) (any, error) {
		y, e1 := wtNum(vecArg(a, 0))
		eps, e2 := wtNum(vecArg(a, 1))
		r, e3 := wtNum(vecArg(a, 2))
		if e1 != nil || e2 != nil || e3 != nil {
			return nil, errors.New("not numbers")
		}
		out, err := WalletRandomizedResponse(y, eps, func() (float64, error) { return r, nil })
		return jsNumber(out), err
	})
	add("debiasRandomizedResponse", three(WalletDebiasRandomizedResponse))
	add("populationCellKey", func(a []any) (any, error) {
		schema, err := wtStr(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		vs, err := e.vs(vecArg(a, 1), vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		idx, err := wtIdxFor(vs, vecArg(a, 3))
		if err != nil {
			return nil, err
		}
		return WalletPopulationCellKey(schema, vs, idx)
	})
	add("aggregate", func(a []any) (any, error) {
		schema, err := wtStr(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		opts, err := wtMap(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		rnd, err := wtSeq(vecArg(a, 5))
		if err != nil {
			return nil, err
		}
		agg, err := NewWalletPopulationAggregator(schema, vecArg(a, 1), opts["maxCellsPerPrincipal"], rnd)
		if err != nil {
			return nil, err
		}
		votes := []any{}
		for _, vv := range wtScript(vecArg(a, 3)) {
			vm, err := wtMap(vv)
			if err != nil {
				return nil, err
			}
			votes = append(votes, agg.Contribute(vm))
		}
		rel, err := wtMap(vecArg(a, 4))
		var release any = map[string]any{"err": true}
		if err == nil {
			eps, e1 := wtNum(rel["epsilon"])
			del, e2 := wtNum(rel["delta"])
			if e1 == nil && e2 == nil {
				o := WalletReleaseOptions{Epsilon: eps, Delta: del, QMin: wtFloatPtr(rel, "qMin"), MinCount: wtFloatPtr(rel, "minCount")}
				if r, rerr := agg.Release(o); rerr == nil {
					release = r
				}
			}
		}
		return map[string]any{"votes": votes, "release": release}, nil
	})
	add("populationPrior", func(a []any) (any, error) {
		rel, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		beta, err := wtNum(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		prior, err := NewWalletPopulationPrior(rel, beta)
		if err != nil {
			return nil, err
		}
		vs, err := e.vs(vecArg(a, 2), vecArg(a, 3))
		if err != nil {
			return nil, err
		}
		contained, err := wtInts(vecArg(a, 4))
		if err != nil {
			return nil, err
		}
		in := map[int]bool{}
		for _, c := range contained {
			in[c] = true
		}
		w, err := prior.Weight(vs, func(c int) bool { return in[c] })
		return map[string]any{"beta": prior.Beta, "weight": w}, err
	})

	// ---- delivery ----
	add("siteQuestionNotice", func(a []any) (any, error) {
		inbox := ""
		if len(a) > 4 {
			inbox, _ = a[4].(string)
		}
		return WalletSiteQuestionNotice(vecArg(a, 0), vecArg(a, 1), vecArg(a, 2), vecArg(a, 3), inbox)
	})
	add("clarificationNotice", func(a []any) (any, error) {
		s, e1 := wtStr(vecArg(a, 0))
		q, e2 := wtStr(vecArg(a, 1))
		if e1 != nil || e2 != nil {
			return nil, errors.New("bad input")
		}
		inbox := ""
		if len(a) > 2 {
			inbox, _ = a[2].(string)
		}
		return WalletClarificationNotice(s, q, inbox), nil
	})
	add("questionText", func(a []any) (any, error) {
		n, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		return WalletQuestionText(n, vecArg(a, 1))
	})
	notices := func(v any) ([]map[string]any, error) {
		l, ok := v.([]any)
		if !ok {
			return nil, errors.New("not a list")
		}
		out := make([]map[string]any, len(l))
		for i, x := range l {
			m, err := wtMap(x)
			if err != nil {
				return nil, err
			}
			out[i] = m
		}
		return out, nil
	}
	add("webhookChannel", func(a []any) (any, error) {
		cfg, err := wtMap(vecArg(a, 0))
		if err != nil {
			return nil, err
		}
		ns, err := notices(vecArg(a, 2))
		if err != nil {
			return nil, err
		}
		url, _ := cfg["url"].(string)
		headers := map[string]string{}
		if hm, ok := cfg["headers"].(map[string]any); ok {
			for k, v := range hm {
				headers[k], _ = v.(string)
			}
		}
		script := wtScript(vecArg(a, 1))
		calls := []any{}
		step := 0
		fetch := func(u string, init WalletFetchInit) (bool, int, error) {
			hdr := make(map[string]any, len(init.Headers))
			for k, v := range init.Headers {
				hdr[k] = v
			}
			calls = append(calls, map[string]any{"url": u, "method": init.Method, "headers": hdr, "body": init.Body})
			st := map[string]any{"ok": true, "status": wN(200)}
			if step < len(script) {
				st, _ = script[step].(map[string]any)
			}
			step++
			if msg, thrown := st["throw"]; thrown && msg != nil {
				return false, 0, errors.New(jsValueString(msg))
			}
			status, _ := jsNum(st["status"])
			return st["ok"] == true, int(status), nil
		}
		ch := WalletQuestionWebhookChannel(url, headers, fetch)
		deliveries := []any{}
		for _, n := range ns {
			deliveries = append(deliveries, ch.Notify(n))
		}
		return map[string]any{"kind": ch.Kind, "enabled": ch.Enabled, "deliveries": deliveries, "calls": calls}, nil
	})
	add("textChannel", func(a []any) (any, error) {
		kind, e1 := wtStr(vecArg(a, 0))
		site, e2 := wtStr(vecArg(a, 1))
		ns, e3 := notices(vecArg(a, 3))
		if e1 != nil || e2 != nil || e3 != nil {
			return nil, errors.New("bad input")
		}
		script, hasScript := vecArg(a, 2).([]any)
		sent := []any{}
		step := 0
		var send WalletTextSender
		if hasScript {
			send = func(body map[string]string) error {
				sent = append(sent, map[string]any{"subject": body["subject"], "text": body["text"]})
				var st map[string]any
				if step < len(script) {
					st, _ = script[step].(map[string]any)
				}
				step++
				if msg, thrown := st["throw"]; thrown && msg != nil {
					return errors.New(jsValueString(msg))
				}
				return nil
			}
		}
		ch := WalletQuestionTextChannel(kind, site, send)
		deliveries := []any{}
		for _, n := range ns {
			deliveries = append(deliveries, ch.Notify(n))
		}
		return map[string]any{"kind": ch.Kind, "enabled": ch.Enabled, "deliveries": deliveries, "sent": sent}, nil
	})
	add("dispatcher", func(a []any) (any, error) {
		cfgs, _ := vecArg(a, 0).([]any)
		note, err := wtMap(vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		chans := []*WalletQuestionChannel{}
		for _, cv := range cfgs {
			c, err := wtMap(cv)
			if err != nil {
				return nil, err
			}
			typ, _ := c["type"].(string)
			if typ == "webhook" {
				url, _ := c["url"].(string)
				chans = append(chans, WalletQuestionWebhookChannel(url, nil, func(string, WalletFetchInit) (bool, int, error) { return true, 200, nil }))
				continue
			}
			var send WalletTextSender
			if jsTruthy(c["enabled"]) {
				send = func(map[string]string) error { return nil }
			}
			chans = append(chans, WalletQuestionTextChannel(typ, "S", send))
		}
		d := NewWalletQuestionDispatcher(chans)
		out := d.NotifyAll(note)
		list := make([]any, len(out))
		for i, x := range out {
			list[i] = x
		}
		return map[string]any{"n": len(d.Channels), "deliveries": list}, nil
	})

	add("channel", func(a []any) (any, error) { return wtChannel(e, vecArg(a, 0)) })

	cmp := map[string]func(want, got any) bool{"webhookChannel": wtHookCmp}
	for _, fn := range []string{"lnGamma", "betacf", "betaInc", "betaQuantile", "binEnt",
		"omega.cellStats", "informationGain", "planClarification", "gaussianSigma", "gaussian", "rrKeepProbability",
		"debiasRandomizedResponse", "aggregate", "populationPrior", "channel"} {
		cmp[fn] = wtClose
	}
	replayVectorsCmp(t, "ref-wallet.json.gz", fns, cmp)
}

// wtChannel plays one session of the question channel as the corpus scripts it.
func wtChannel(e *wtEnv, specV any) (any, error) {
	spec, err := wtMap(wtSub(specV, e))
	if err != nil {
		return nil, err
	}
	om, err := WalletOmegaFromJSON(spec["omega"])
	if err != nil {
		return nil, err
	}
	t0, err := wtNum(spec["t0"])
	if err != nil {
		return nil, err
	}
	now := t0
	counts, err := wtCounts(spec["noise"])
	if err != nil {
		return nil, err
	}
	win := 3600000.0
	if _, has := spec["windowMs"]; has {
		if win, err = wtNum(spec["windowMs"]); err != nil {
			return nil, err
		}
	}
	hourly, err := NewWalletSlidingWindow(win)
	if err != nil {
		return nil, err
	}
	for _, ts := range wtScript(spec["hourlyPre"]) {
		f, err := wtNum(ts)
		if err != nil {
			return nil, err
		}
		if _, err := hourly.TryAdd(f, 9007199254740991); err != nil {
			return nil, err
		}
	}
	rnd, err := wtSeq(spec["rands"])
	if err != nil {
		return nil, err
	}
	v, err := wtMap(spec["view"])
	if err != nil {
		return nil, err
	}
	p, err := wtMap(v["p"])
	if err != nil {
		return nil, err
	}
	vetoed, err1 := wtSet(v["vetoed"])
	ceiling, err2 := wtSet(v["ceiling"])
	confirmed, err3 := wtRefs(v["confirmed"])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("bad view")
	}
	principal, err := wtStr(spec["principal"])
	if err != nil {
		return nil, err
	}
	siteM, err := wtMap(spec["site"])
	if err != nil {
		return nil, err
	}
	origin, _ := siteM["origin"].(string)
	name, _ := siteM["name"].(string)
	mapDigest, _ := spec["mapDigest"].(string)
	session, _ := spec["session"].(string)

	o := WalletChannelOptions{
		Omega: om, Session: session, MapDigest: func() string { return mapDigest }, PrincipalSeed: wtSeed(principal),
		Site: WalletSite{Origin: origin, Name: name, Keys: siteM["keys"]},
		View: WalletView{
			P: func(verb string, idx []int) float64 {
				f, _ := jsNum(p[WalletCellKey(verb, idx)])
				return f
			},
			Vetoed:         func(verb string, idx []int) bool { return vetoed[WalletCellKey(verb, idx)] },
			OutsideCeiling: func(verb string, idx []int) bool { return ceiling[WalletCellKey(verb, idx)] },
			Confirmed:      func() []WalletCellRef { return confirmed },
		},
		Hourly: hourly, Noise: func() WalletNoiseCounts { return counts }, OnNoise: func(n WalletNoiseCounts) { counts = n },
		Rand: rnd, Now: func() float64 { return now },
	}
	if st, has := spec["statementText"].(string); has {
		o.StatementText = &st
	}
	if jsTruthy(spec["units"]) {
		o.Units = spec["units"]
	}
	if sm, ok := spec["sensitivity"].(map[string]any); ok && len(sm) > 0 {
		o.Sensitivity = map[string]string{}
		for k, x := range sm {
			o.Sensitivity[k], _ = x.(string)
		}
	}
	if l, ok := spec["identityPaths"].([]any); ok {
		for _, x := range l {
			s, _ := x.(string)
			o.IdentityPaths = append(o.IdentityPaths, s)
		}
	}
	if caps, ok := spec["caps"].(map[string]any); ok {
		o.PerSession, o.PerHour = wtFloatPtr(caps, "perSession"), wtFloatPtr(caps, "perHour")
	}
	if fm, ok := spec["fatigue"].(map[string]any); ok && len(fm) > 0 {
		f, err := wtFatigue(fm)
		if err != nil {
			return nil, err
		}
		o.Fatigue = &f
	}
	o.Rho, o.MaxPerScreen, o.MaxBoxCells = wtFloatPtr(spec, "rho"), wtFloatPtr(spec, "maxPerScreen"), wtFloatPtr(spec, "maxBoxCells")
	if dm, ok := spec["device"].(map[string]any); ok && len(dm) > 0 {
		dev := &WalletDevice{Credentials: map[string]any{}, SignCounts: map[string]float64{}}
		dev.RPID, _ = dm["rpId"].(string)
		for _, x := range wtScript(dm["origins"]) {
			s, _ := x.(string)
			dev.Origins = append(dev.Origins, s)
		}
		if cm, ok := dm["credentials"].(map[string]any); ok {
			dev.Credentials = cm
		}
		if sc, ok := dm["signCounts"].(map[string]any); ok {
			for k, x := range sc {
				dev.SignCounts[k], _ = jsNum(x)
			}
		}
		o.Device = dev
	}
	if lm, ok := spec["lift"].(map[string]any); ok && len(lm) > 0 {
		add, _ := lm["add"].(map[string]any)
		o.Lift = func(action any) (any, error) {
			vals, err := WalletActionValues(action)
			if err != nil {
				return nil, err
			}
			merged := map[string]any{}
			for k, x := range vals["values"].(map[string]any) {
				merged[k] = x
			}
			for k, x := range add {
				merged[k] = x
			}
			return map[string]any{"verb": vals["verb"], "values": merged}, nil
		}
	}
	if lc, ok := spec["liftCand"].(map[string]any); ok && len(lc) > 0 {
		o.LiftCandidate = func(cand any) (any, error) {
			cm, err := wtMap(cand)
			if err != nil {
				return nil, err
			}
			merged := map[string]any{}
			vm, _ := cm["values"].(map[string]any)
			for k, x := range vm {
				merged[k] = x
			}
			for k, x := range lc {
				merged[k] = x
			}
			return map[string]any{"verb": cm["verb"], "values": merged}, nil
		}
	}
	ch := NewWalletChannel(o)
	resolver := func(sid string) *WalletChannel {
		if sid == session {
			return ch
		}
		return nil
	}
	seen := []string{}
	steps := []any{}
	for _, sv := range wtScript(spec["steps"]) {
		st, err := wtMap(sv)
		if err != nil {
			return nil, err
		}
		qid := ""
		if qf, hasQ := st["q"]; hasQ && qf != nil {
			if q, ok := walletIntegral(qf); ok && q >= 0 && int(q) < len(seen) {
				qid = seen[int(q)]
			}
		} else if s, ok := st["qid"].(string); ok {
			qid = s
		}
		op, _ := st["op"].(string)
		var r any
		var serr error
		switch op {
		case "time":
			now, serr = wtNum(st["t"])
			r = map[string]any{"t": jsNumber(now)}
		case "receive":
			r, serr = ch.Receive(st["ir"], st["action"])
		case "next":
			screen := ch.NextScreen()
			if screen == nil {
				r = nil
				break
			}
			r = screen
			qs, _ := screen["questions"].([]any)
			for _, x := range qs {
				xm, _ := x.(map[string]any)
				s, _ := xm["questionId"].(string)
				seen = append(seen, s)
			}
		case "answer":
			r, serr = ch.Answer(qid, st["response"])
		case "clarify":
			r, serr = ch.Clarify(st["body"])
		case "hQuestion", "hClarify":
			sid := session
			if s, ok := st["sid"].(string); ok {
				sid = s
			}
			if op == "hQuestion" {
				r, serr = WalletQuestionHandler(resolver)(sid, st["body"])
			} else {
				r, serr = WalletClarifyHandler(resolver)(sid, st["body"])
			}
		case "summary":
			r, serr = ch.Summary()
		case "state":
			var d string
			if d, serr = ch.StateDigest(); serr == nil {
				r = map[string]any{"digest": d, "asked": ch.QuestionsAsked()}
			}
		case "noise":
			ns, e1 := ch.Noise()
			ad, e2 := ch.Admission()
			serr = errors.Join(e1, e2)
			r = map[string]any{"noise": ns, "admission": ad}
		case "challenge":
			var c string
			if c, serr = ch.DeviceChallengeFor(qid); serr == nil && c != "" {
				r = c
			}
		default:
			serr = fmt.Errorf("bad op %s", op)
		}
		if serr != nil {
			r = map[string]any{"$err": true}
		}
		steps = append(steps, map[string]any{"op": op, "r": r})
	}
	var signCounts any
	if o.Device != nil {
		signCounts = o.Device.SignCounts
	}
	return map[string]any{"steps": steps, "noise": counts, "signCounts": signCounts}, nil
}
