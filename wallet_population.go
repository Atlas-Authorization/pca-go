package pca

// Opt-in, privacy-preserving population priors for the wallet (PCA Intent Layer v2): one vote per principal, cell and period; a
// central (epsilon, delta)-DP Gaussian release; local-DP randomized response; the mixture prior for the learner. Votes, releases
// and priors are JSON objects with the reference's member names; the randomness source is an injected function.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
)

const (
	// WalletPopulationVoteDomain is the digest domain of a population cell key.
	WalletPopulationVoteDomain = "atlas-pca/intent-population-cell/v1"
	// WalletBetaMax is the largest mixture weight of the population prior (full support needs beta < 1).
	WalletBetaMax = 0.9
)

func walletJSRound(x float64) float64 {
	f := math.Floor(x)
	if x-f >= 0.5 {
		return f + 1
	}
	return f
}

// WalletPopulationCellKey is the semantic key of a cell: its coordinates in schema terms, bound to the schema digest and the verb.
func WalletPopulationCellKey(schemaDigest string, vs *WalletVerb, idx []int) (string, error) {
	coords, err := WalletCoordsOfCell(vs, idx)
	if err != nil {
		return "", err
	}
	return HashCanonical(map[string]any{"d": WalletPopulationVoteDomain, "s": schemaDigest, "v": vs.Verb, "c": coords})
}

// WalletCryptoRand is a uniform (0, 1) draw from 53 random bits of the operating system's CSPRNG.
func WalletCryptoRand() (float64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	hi := float64(binary.BigEndian.Uint32(b[:4]) >> 5)
	lo := float64(binary.BigEndian.Uint32(b[4:]) >> 6)
	return (hi*67108864 + lo + 0.5) / 9007199254740992, nil
}

// WalletGaussian is a standard normal draw (Box-Muller) from a uniform source.
func WalletGaussian(r WalletRand) (float64, error) {
	u, err := r()
	if err != nil {
		return 0, err
	}
	for u <= 0 {
		if u, err = r(); err != nil {
			return 0, err
		}
	}
	v, err := r()
	if err != nil {
		return 0, err
	}
	return math.Sqrt(-2*math.Log(u)) * math.Cos(2*math.Pi*v), nil
}

// WalletGaussianSigma is sigma of the Gaussian mechanism for L2 sensitivity (it needs epsilon in (0, 1) and delta in (0, 1)).
func WalletGaussianSigma(epsilon, delta, l2Sensitivity float64) (float64, error) {
	if !(epsilon > 0 && epsilon < 1) {
		return 0, errors.New("gaussianSigma: the classic Gaussian mechanism needs epsilon in (0, 1)")
	}
	if !(delta > 0 && delta < 1) {
		return 0, errors.New("gaussianSigma: delta must be in (0, 1)")
	}
	if !(l2Sensitivity > 0) {
		return 0, errors.New("gaussianSigma: sensitivity must be > 0")
	}
	return (l2Sensitivity * math.Sqrt(2*math.Log(1.25/delta))) / epsilon, nil
}

type walletVoteCount struct{ yes, total float64 }

// WalletPopulationAggregator collects one vote per principal, cell and period and releases a DP aggregate.
type WalletPopulationAggregator struct {
	schemaDigest string
	period       any
	votes        map[string]*walletVoteCount
	voteKeys     map[string]any
	perPrincipal map[string]map[string]bool
	maxCells     float64
	rand         WalletRand
}

// NewWalletPopulationAggregator builds an aggregator; maxCellsPerPrincipal nil is 32 and rand nil is the system CSPRNG.
func NewWalletPopulationAggregator(schemaDigest string, period any, maxCellsPerPrincipal any, r WalletRand) (*WalletPopulationAggregator, error) {
	if !WalletIsB64u32(schemaDigest) {
		return nil, errors.New("PopulationAggregator: schemaDigest must be a canonical b64u digest")
	}
	mc := 32.0
	if maxCellsPerPrincipal != nil {
		f, ok := walletIntegral(maxCellsPerPrincipal)
		if !ok {
			return nil, errors.New("PopulationAggregator: maxCellsPerPrincipal must be a positive integer")
		}
		mc = f
	}
	if !(mc > 0) {
		return nil, errors.New("PopulationAggregator: maxCellsPerPrincipal must be a positive integer")
	}
	if r == nil {
		r = WalletCryptoRand
	}
	return &WalletPopulationAggregator{schemaDigest: schemaDigest, period: period, votes: map[string]*walletVoteCount{}, voteKeys: map[string]any{},
		perPrincipal: map[string]map[string]bool{}, maxCells: mc, rand: r}, nil
}

// Contribute accepts a vote; it refuses a second vote on a cell, a vote past the per-principal cell cap, or a foreign schema or
// period. The result is {ok: true} or {ok: false, reason}.
func (a *WalletPopulationAggregator) Contribute(v map[string]any) map[string]any {
	no := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if v["schemaDigest"] != any(a.schemaDigest) {
		return no("vote for another schema")
	}
	if !jsStrictEq(v["period"], a.period) {
		return no("vote for another period")
	}
	if !(wNumEq(v["y"], 0) || wNumEq(v["y"], 1)) {
		return no("y must be 0 or 1")
	}
	principal, ok := v["principal"].(string)
	if !ok || len(principal) == 0 {
		return no("an accountable principal is required")
	}
	key, _ := canonicalLenient(v["cellKey"])
	mine := a.perPrincipal[principal]
	if mine == nil {
		mine = map[string]bool{}
	}
	if mine[key] {
		return no("one vote per principal per cell per period (sensitivity 1)")
	}
	if !(float64(len(mine)) < a.maxCells) {
		return no("at most " + jsNumberString(a.maxCells) + " cells per principal per period")
	}
	mine[key] = true
	a.perPrincipal[principal] = mine
	c := a.votes[key]
	if c == nil {
		c = &walletVoteCount{}
		a.votes[key] = c
		a.voteKeys[key] = v["cellKey"]
	}
	c.yes += jsF(v["y"])
	c.total++
	return map[string]any{"ok": true}
}

// WalletReleaseOptions are the parameters of a release; QMin and MinCount nil take the reference defaults (0.02 and 3 sigma).
type WalletReleaseOptions struct {
	Epsilon, Delta float64
	QMin, MinCount *float64
}

// Release is the (epsilon, delta)-DP release. Cells whose noisy count is below minCount are suppressed.
func (a *WalletPopulationAggregator) Release(o WalletReleaseOptions) (map[string]any, error) {
	sensitivity := math.Sqrt(2 * a.maxCells)
	sigma, err := WalletGaussianSigma(o.Epsilon, o.Delta, sensitivity)
	if err != nil {
		return nil, err
	}
	qMin := 0.02
	if o.QMin != nil {
		qMin = *o.QMin
	}
	if !(qMin > 0 && qMin < 0.5) {
		return nil, errors.New("release: qMin must be in (0, 0.5)")
	}
	minCount := 3 * sigma
	if o.MinCount != nil {
		minCount = *o.MinCount
	}
	keys := make([]string, 0, len(a.votes))
	names := map[string]string{}
	for k := range a.votes {
		name := jsValueString(a.voteKeys[k])
		names[name] = k
		keys = append(keys, name)
	}
	walletSortUTF16(keys)
	cells := map[string]any{}
	for _, name := range keys {
		c := a.votes[names[name]]
		g1, err := WalletGaussian(a.rand)
		if err != nil {
			return nil, err
		}
		yes := c.yes + sigma*g1
		g2, err := WalletGaussian(a.rand)
		if err != nil {
			return nil, err
		}
		total := c.total + sigma*g2
		if !(total >= minCount) {
			continue
		}
		cells[name] = map[string]any{"q": math.Min(1-qMin, math.Max(qMin, yes/total)), "n": jsNumber(walletJSRound(total))}
	}
	return map[string]any{"v": wN(1), "kind": "pca-intent-population-prior", "schema": a.schemaDigest, "period": a.period, "epsilon": o.Epsilon,
		"delta": o.Delta, "sigma": sigma, "sensitivity": sensitivity, "cells": cells}, nil
}

// ---- local DP -------------------------------------------------------------------------------------------------------------------

// WalletRRKeepProbability is the keep probability e^eps / (1 + e^eps) of randomized response.
func WalletRRKeepProbability(epsilon float64) (float64, error) {
	if !(epsilon > 0 && !math.IsInf(epsilon, 0)) {
		return 0, errors.New("randomized response: epsilon must be > 0")
	}
	return math.Exp(epsilon) / (1 + math.Exp(epsilon)), nil
}

// WalletRandomizedResponse is epsilon-LDP randomized response: report y with probability e^eps/(1+e^eps), else 1 - y.
func WalletRandomizedResponse(y, epsilon float64, r WalletRand) (float64, error) {
	if r == nil {
		r = WalletCryptoRand
	}
	d, err := r()
	if err != nil {
		return 0, err
	}
	keep, err := WalletRRKeepProbability(epsilon)
	if err != nil {
		return 0, err
	}
	if d < keep {
		return y, nil
	}
	return 1 - y, nil
}

// WalletDebiasRandomizedResponse is the unbiased estimate of the true yes-rate from randomized reports.
func WalletDebiasRandomizedResponse(yesReports, total, epsilon float64) (float64, error) {
	if !(yesReports == math.Trunc(yesReports) && total == math.Trunc(total) && !math.IsInf(total, 0) && total > 0 && yesReports >= 0 && yesReports <= total) {
		return 0, errors.New("debias: bad counts")
	}
	p, err := WalletRRKeepProbability(epsilon)
	if err != nil {
		return 0, err
	}
	return (yesReports/total - (1 - p)) / (2*p - 1), nil
}

// ---- the mixture prior ----------------------------------------------------------------------------------------------------------

// WalletPopulationPrior is the learner's priorMix for a release: Weight(vs, contains) = prod_c q_c^{1[c in theta]} (1 -
// q_c)^{1[c not in theta]} over the released cells of the verb, mixed with weight Beta <= BetaMax < 1.
type WalletPopulationPrior struct {
	Beta   float64
	tables map[*WalletVerb]*walletPriorTable
	rel    map[string]any
}

type walletPriorTable struct {
	cells   []int
	lq, lnq []float64
}

// NewWalletPopulationPrior builds the mixture prior of a release.
func NewWalletPopulationPrior(release map[string]any, beta float64) (*WalletPopulationPrior, error) {
	if !(beta >= 0 && beta <= WalletBetaMax) {
		return nil, fmt.Errorf("populationPrior: beta must be in [0, %s] (full support needs beta < 1)", strings.TrimSpace(jsNumberString(WalletBetaMax)))
	}
	return &WalletPopulationPrior{Beta: beta, tables: map[*WalletVerb]*walletPriorTable{}, rel: release}, nil
}

func (p *WalletPopulationPrior) table(vs *WalletVerb) (*walletPriorTable, error) {
	if t := p.tables[vs]; t != nil {
		return t, nil
	}
	t := &walletPriorTable{}
	cells, _ := p.rel["cells"].(map[string]any)
	schema, _ := p.rel["schema"].(string)
	n := WalletVerbCellCount(vs)
	for c := 0; c < n; c++ {
		key, err := WalletPopulationCellKey(schema, vs, WalletDecodeCell(vs, c))
		if err != nil {
			return nil, err
		}
		r, ok := cells[key].(map[string]any)
		if !ok {
			continue
		}
		q := jsF(r["q"])
		t.cells = append(t.cells, c)
		t.lq = append(t.lq, math.Log(q))
		t.lnq = append(t.lnq, math.Log(1-q))
	}
	p.tables[vs] = t
	return t, nil
}

// Weight is the prior weight of the hypothesis that holds exactly the cells for which contains is true.
func (p *WalletPopulationPrior) Weight(vs *WalletVerb, contains func(cell int) bool) (float64, error) {
	t, err := p.table(vs)
	if err != nil {
		return 0, err
	}
	lw := 0.0
	for i, c := range t.cells {
		if contains(c) {
			lw += t.lq[i]
		} else {
			lw += t.lnq[i]
		}
	}
	return math.Exp(lw), nil
}
