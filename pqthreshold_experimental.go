package pca

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// EXPERIMENTAL lattice-threshold sketch (NOT PRODUCTION): the research design as data and a toy additive secret sharing of a lattice
// key vector over Z_q. It is n-of-n, not t-of-n, and not a signature scheme. The shippable post-quantum threshold step-up is the
// hybrid (a classical FROST threshold plus an ML-DSA co-signature quorum): see BuildQuorumSet and friends.

// ExperimentalBanner is the loud warning every experimental routine carries.
const ExperimentalBanner = "EXPERIMENTAL — NOT PRODUCTION. No security proof, timing-unsafe, for research/interop only. " +
	"The shippable post-quantum threshold step-up is the HYBRID (classical FROST threshold + ML-DSA " +
	"co-signature quorum) in @atlasauth/pca-pq-threshold; do NOT use this lattice-threshold prototype to sign."

// ExperimentalOptIn is the explicit, loud opt-in a caller must pass to run any experimental routine: IUnderstandThisIsNotProduction
// must be true, anything else is refused with the banner.
type ExperimentalOptIn struct{ IUnderstandThisIsNotProduction bool }

func assertExperimentalOptIn(o ExperimentalOptIn) error {
	if !o.IUnderstandThisIsNotProduction {
		return errors.New(ExperimentalBanner + " Pass { iUnderstandThisIsNotProduction: true } to proceed.")
	}
	return nil
}

// RaccoonDesignParameterSet is one illustrative parameter set of the research design.
type RaccoonDesignParameterSet struct {
	Name         string
	NistCategory int
	Note         string
}

// RaccoonDesignSpec documents the Raccoon / Ringtail-style lattice-threshold approach. It is DATA describing the research design: it
// performs no cryptography.
type RaccoonDesignSpec struct {
	Scheme               string
	Status               string
	ProductionReady      bool
	Banner               string
	Assumption           string
	Construction         []string
	WhyNoLibraryYet      []string
	ShippableAlternative string
	ParameterSets        []RaccoonDesignParameterSet
	References           []string
}

// RaccoonDesign returns a fresh copy of the research design (a caller cannot edit the shared one).
func RaccoonDesign() RaccoonDesignSpec {
	return RaccoonDesignSpec{
		Scheme:          "Raccoon/Ringtail-style lattice threshold (RESEARCH)",
		Status:          "research-prototype",
		ProductionReady: false,
		Banner:          ExperimentalBanner,
		Assumption:      "Module-LWE / Module-SIS (the same lattice assumptions as ML-DSA / FIPS-204), believed hard for quantum adversaries.",
		Construction: []string{
			"1. Distributed key generation: the signing key (a short vector / small polynomial) is SECRET-SHARED across n parties — Raccoon uses additive masking; Ringtail layers a one-time additive mask over a replicated/Shamir-style sharing to reach genuine t-of-n.",
			"2. Each party holds a share s_i such that the shares combine (additively, mod q, per coefficient) to the signing key s.",
			"3. Signing is a masked, multi-round protocol: parties jointly sample commitment randomness, each adds Gaussian NOISE FLOODING to its partial response so the partials leak nothing about the individual shares, and the masked partials are summed.",
			"4. The combined response is accepted only if it passes the standard ML-DSA-style rejection-sampling bound; otherwise the round restarts. The output is a single signature verifiable under ONE ordinary ML-DSA-style public key.",
			"5. A quantum break of a CLASSICAL threshold does not help here — forging requires solving the underlying lattice problem.",
		},
		WhyNoLibraryYet: []string{
			"Distributed discrete Gaussian / noise-flooding sampling with the right parameters is subtle and unimplemented in any audited library.",
			"Parameter selection for the threshold setting is still moving; interop test vectors are not standardised.",
			"No constant-time, side-channel-hardened reference implementation has been published and audited.",
			"The abort/restart rejection-sampling rounds complicate liveness and make a robust networked coordinator non-trivial.",
		},
		ShippableAlternative: "Use the HYBRID in @atlasauth/pca-pq-threshold: a classical FROST(Ed25519) t-of-n threshold AND a pqT-of-m ML-DSA-65 co-signature quorum over the same action. It is post-quantum-protected TODAY (a classical threshold break cannot forge the step-up without ALSO forging the ML-DSA quorum) using only audited, available primitives.",
		ParameterSets: []RaccoonDesignParameterSet{
			{Name: "Raccoon-128 (illustrative)", NistCategory: 1, Note: "Research parameters only; not implemented here."},
			{Name: "Raccoon-192 (illustrative)", NistCategory: 3, Note: "Matches ML-DSA-65 category; not implemented here."},
		},
		References: []string{
			"Raccoon: a side-channel-resilient lattice signature (NIST additional-signatures submission).",
			"Ringtail: two-round threshold signatures from lattices.",
			"FIPS-204 (ML-DSA) — the single-party base scheme the threshold variants mirror.",
		},
	}
}

// ToyLatticeParams are the toy lattice parameters: a tiny modulus for demonstration, NOT a real ML-DSA modulus.
type ToyLatticeParams struct {
	Q   *big.Int
	Dim int
}

// ToyDefaultParams is the illustrative ML-DSA modulus (q = 8380417, dimension 4), used purely so the arithmetic looks familiar.
func ToyDefaultParams() ToyLatticeParams { return ToyLatticeParams{Q: big.NewInt(8380417), Dim: 4} }

// LatticeKeyShare is one party's additive share of the toy lattice key: a coefficient vector mod q.
type LatticeKeyShare struct {
	Index  int        // 1-based party index
	Coeffs []*big.Int // length Dim, each in [0, q)
}

// CoeffSampler yields a random coefficient in [0, q). Injectable so tests are deterministic; nil draws from crypto/rand.
type CoeffSampler func(q *big.Int) *big.Int

func expModQ(x, q *big.Int) *big.Int { return new(big.Int).Mod(x, q) } // big.Int Mod is Euclidean: never negative

// AdditiveShareLatticeKey additively secret-shares a toy lattice key vector into n shares over Z_q, per coefficient: shares 1..n-1
// are random and the last absorbs the remainder, so the shares sum to the key (mod q). It is n-of-n (ALL shares reconstruct), NOT
// t-of-n and NOT a signature scheme. Gated behind the opt-in.
func AdditiveShareLatticeKey(key []*big.Int, n int, optIn ExperimentalOptIn, params ToyLatticeParams, sampler CoeffSampler) ([]LatticeKeyShare, error) {
	if err := assertExperimentalOptIn(optIn); err != nil {
		return nil, err
	}
	if params.Q == nil || params.Q.Sign() <= 0 {
		return nil, errors.New("additiveShareLatticeKey: q must be positive")
	}
	if n < 1 || n > 1024 {
		return nil, errors.New("additiveShareLatticeKey: n must be an integer in [1, 1024]")
	}
	if len(key) != params.Dim {
		return nil, fmt.Errorf("additiveShareLatticeKey: key must have %d coefficients", params.Dim)
	}
	if sampler == nil {
		sampler = func(q *big.Int) *big.Int {
			v, err := rand.Int(rand.Reader, q)
			if err != nil {
				panic(err)
			}
			return v
		}
	}
	shares := make([]LatticeKeyShare, n)
	for i := range shares {
		shares[i] = LatticeKeyShare{Index: i + 1, Coeffs: make([]*big.Int, params.Dim)}
	}
	for c := 0; c < params.Dim; c++ {
		target := expModQ(key[c], params.Q)
		running := new(big.Int)
		for i := 0; i < n-1; i++ {
			r := expModQ(sampler(params.Q), params.Q)
			shares[i].Coeffs[c] = r
			running = expModQ(running.Add(running, r), params.Q)
		}
		shares[n-1].Coeffs[c] = expModQ(new(big.Int).Sub(target, running), params.Q)
	}
	return shares, nil
}

// ReconstructLatticeKey reconstructs the toy lattice key by summing ALL shares' coefficient vectors mod q. Because the sharing is
// additive (n-of-n) every share must be present; a repeated share index is refused (it would be counted twice and silently yield a
// wrong key). Gated behind the opt-in.
func ReconstructLatticeKey(shares []LatticeKeyShare, optIn ExperimentalOptIn, params ToyLatticeParams) ([]*big.Int, error) {
	if err := assertExperimentalOptIn(optIn); err != nil {
		return nil, err
	}
	if params.Q == nil || params.Q.Sign() <= 0 {
		return nil, errors.New("reconstructLatticeKey: q must be positive")
	}
	if len(shares) == 0 {
		return nil, errors.New("reconstructLatticeKey: need at least one share")
	}
	seen := map[int]bool{}
	for _, s := range shares {
		if seen[s.Index] {
			return nil, errors.New("reconstructLatticeKey: duplicate share index")
		}
		seen[s.Index] = true
	}
	out := make([]*big.Int, params.Dim)
	for c := range out {
		out[c] = new(big.Int)
	}
	for _, s := range shares {
		if len(s.Coeffs) != params.Dim {
			return nil, errors.New("reconstructLatticeKey: a share has the wrong dimension")
		}
		for c := 0; c < params.Dim; c++ {
			if s.Coeffs[c] == nil {
				return nil, errors.New("reconstructLatticeKey: a share has the wrong dimension")
			}
			out[c] = expModQ(out[c].Add(out[c], s.Coeffs[c]), params.Q)
		}
	}
	return out, nil
}
