package pca

// Replays the reference oracle of the DPoP bridge (testdata/ref-dpop.json.gz). Stores and nonce issuers travel as specs:
// seenJti [...] = an ordered set (its final content is reported as `seen`), replayStore {kind: memory|true|false|throws,
// maxEntries?, preload?}, nonceIssuer {secret, ttl?}. Certificates are {"$bytes"} (DER) or a PEM string.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type dpopSeen struct{ list []string }

func (s *dpopSeen) Has(j string) bool {
	for _, x := range s.list {
		if x == j {
			return true
		}
	}
	return false
}
func (s *dpopSeen) Add(j string) {
	if !s.Has(j) {
		s.list = append(s.list, j)
	}
}

type dpopFixedStore struct {
	ok  bool
	err error
}

func (s dpopFixedStore) AddIfAbsent(string, float64, float64) (bool, error) { return s.ok, s.err }

func dpopF(v any) *float64 {
	f, ok := jsNum(v)
	if !ok {
		return nil
	}
	return &f
}

func dpopStore(spec map[string]any) (DpopReplayStore, error) {
	switch spec["kind"] {
	case "memory":
		max := DpopInMemoryMaxEntries
		if f := dpopF(spec["maxEntries"]); f != nil {
			max = int(*f)
		}
		st, err := NewInMemoryDpopReplayStore(max)
		if err != nil {
			return nil, err
		}
		for _, p := range vecArgList(spec["preload"]) {
			l := vecArgList(p)
			k, _ := l[0].(string)
			st.AddIfAbsent(k, *dpopF(l[1]), *dpopF(l[2]))
		}
		return st, nil
	case "true":
		return dpopFixedStore{ok: true}, nil
	case "false":
		return dpopFixedStore{}, nil
	}
	return dpopFixedStore{err: errors.New("boom")}, nil
}

func dpopIssuer(spec map[string]any) (*DpopNonceIssuer, error) {
	var ttl *float64
	if x, has := spec["ttl"]; has {
		ttl = dpopF(x)
	}
	return NewDpopNonceIssuer(vcBytes(map[string]any{"$bytes": spec["secret"]}), ttl)
}

func dpopVerifyOpts(m map[string]any) (VerifyDpopProofOptions, *dpopSeen, error) {
	var o VerifyDpopProofOptions
	o.Method, _ = m["method"].(string)
	o.URL, _ = m["url"].(string)
	if x, has := m["maxAgeSec"]; has {
		o.MaxAgeSec = dpopF(x)
	}
	o.ExpectedJkt, o.ExpectedNonce, o.AccessToken = vecPtrIfPresent(m, "expectedJkt"), vecPtrIfPresent(m, "expectedNonce"), vecPtrIfPresent(m, "accessToken")
	o.NowSec = dpopF(m["nowSec"])
	if b, ok := m["requireReplayStore"].(bool); ok {
		o.RequireReplayStore = &b
	}
	var seen *dpopSeen
	if l, ok := m["seenJti"].([]any); ok {
		seen = &dpopSeen{list: []string{}}
		for _, x := range l {
			s, _ := x.(string)
			seen.Add(s)
		}
		o.SeenJti = seen
	}
	if s, ok := m["replayStore"].(map[string]any); ok {
		st, err := dpopStore(s)
		if err != nil {
			return o, nil, err
		}
		o.ReplayStore = st
	}
	if s, ok := m["nonceIssuer"].(map[string]any); ok {
		iss, err := dpopIssuer(s)
		if err != nil {
			return o, nil, err
		}
		o.NonceIssuer = iss
	}
	return o, seen, nil
}

func dpopResult(r *DpopVerifyResult, seen *dpopSeen) any {
	out := map[string]any{"claims": r.Claims, "jwk": r.Jwk, "jkt": r.Jkt}
	if seen != nil {
		out["seen"] = seen.list
	}
	return out
}

// dpopProofArg: a non-string proof is refused by the size / type check, reached through an over-long string.
func dpopProofArg(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return strings.Repeat("a", DpopMaxProofBytes+1)
}

func dpopCert(v any) any {
	if m, ok := v.(map[string]any); ok {
		return vcBytes(m)
	}
	return v
}

func dpopCreateInput(m map[string]any) CreateDpopProofInput {
	in := CreateDpopProofInput{PrivateKey: vecObj(m["privateKey"]), PublicJwk: vecObj(m["publicJwk"]), Nonce: vecPtrIfPresent(m, "nonce"),
		Ath: vecPtrIfPresent(m, "ath"), Iat: dpopF(m["iat"]), Jti: vecPtrIfPresent(m, "jti")}
	in.Method, _ = m["method"].(string)
	in.URL, _ = m["url"].(string)
	return in
}

func TestDpopVectors(t *testing.T) { replayVectors(t, "ref-dpop.json.gz", dpopFns()) }

// TestDpopRSAVectors replays ref-dpop-rsa.json.gz (CI generates it; never committed): a missing file fails under CI, else skips.
func TestDpopRSAVectors(t *testing.T) {
	path := os.Getenv("PCA_DPOP_RSA_CORPUS")
	if path == "" {
		path, _ = filepath.Abs("testdata/ref-dpop-rsa.json.gz")
	}
	if _, err := os.Stat(path); err != nil {
		if ci := os.Getenv("CI"); ci == "true" || ci == "1" {
			t.Fatalf("RSA DPoP corpus missing (%s): CI must generate it with .github/scripts/dpop-rsa-corpus.sh", path)
		}
		t.Skipf("RSA DPoP corpus missing (%s): run .github/scripts/dpop-rsa-corpus.sh", path)
	}
	replayVectors(t, path, dpopFns())
}

func dpopFns() map[string]vecFn {
	return vecSeeded(map[string]vecFn{
		"constants": func([]any) (any, error) {
			return map[string]any{"allowedAlgs": DpopAllowedAlgs, "typ": DpopJwtTyp, "defaultMaxAgeSec": DpopDefaultMaxAgeSec, "clockSkewSec": DpopClockSkewSec,
				"maxProofBytes": DpopMaxProofBytes, "inMemoryMaxEntries": DpopInMemoryMaxEntries}, nil
		},
		"jwkThumbprint": func(a []any) (any, error) {
			d := "sha256"
			if len(a) > 1 {
				d, _ = a[1].(string)
			}
			return JWKThumbprint(vecArg(a, 0), d)
		},
		"dpopAlgForJwk": func(a []any) (any, error) {
			if vecArg(a, 0) == nil {
				return nil, errors.New("Cannot read properties of null (reading 'kty')")
			}
			return DpopAlgForJwk(vecObj(vecArg(a, 0)))
		},
		"dpopAlgMatchesJwk": func(a []any) (any, error) {
			alg, _ := vecArg(a, 0).(string)
			if vecArg(a, 1) == nil && dpopAllowed(alg) {
				return nil, errors.New("Cannot read properties of null (reading 'kty')")
			}
			return DpopAlgMatchesJwk(alg, vecObj(vecArg(a, 1))), nil
		},
		"normalizeHtu": func(a []any) (any, error) { return NormalizeHtu(jsValueString(vecArg(a, 0))) },
		"athFor":       func(a []any) (any, error) { s, _ := vecArg(a, 0).(string); return AthFor(s), nil },
		"nonceIssuer": func(a []any) (any, error) {
			spec := map[string]any{"secret": vecArg(a, 0)}
			if vecArg(a, 1) != nil {
				spec["ttl"] = a[1]
			}
			iss, err := dpopIssuer(spec)
			if err != nil {
				return nil, err
			}
			var issued []string
			out := []any{}
			for _, op := range vecArgList(vecArg(a, 2)) {
				m := vecObj(op)
				if m["op"] == "issue" {
					n, err := iss.Issue(dpopF(m["now"]))
					if err != nil {
						return nil, err
					}
					issued = append(issued, n)
					out = append(out, n)
					continue
				}
				nonce := m["nonce"]
				if nm, ok := nonce.(map[string]any); ok {
					if i, has := nm["$issued"]; has {
						nonce = issued[int(*dpopF(i))]
					}
				}
				out = append(out, iss.Check(nonce, dpopF(m["now"])))
			}
			return out, nil
		},
		"replayStore": func(a []any) (any, error) {
			max := DpopInMemoryMaxEntries
			if x := vecArg(a, 0); x != nil {
				f, ok := jsNum(x)
				if !ok || f != float64(int(f)) {
					f = 0 // not an integer: refused like any non-positive size
				}
				max = int(f)
			}
			st, err := NewInMemoryDpopReplayStore(max)
			if err != nil {
				return nil, err
			}
			out := []any{}
			for _, op := range vecArgList(vecArg(a, 1)) {
				m := vecObj(op)
				k, _ := m["key"].(string)
				ok, err := st.AddIfAbsent(k, *dpopF(m["exp"]), *dpopF(m["now"]))
				if err != nil {
					out = append(out, "throws")
				} else {
					out = append(out, ok)
				}
			}
			return out, nil
		},
		"replayConformance": func(a []any) (any, error) {
			kind, _ := vecArg(a, 0).(string)
			return RunDpopReplayStoreConformance(func() DpopReplayStore {
				switch kind {
				case "memory":
					st, _ := NewInMemoryDpopReplayStore(DpopInMemoryMaxEntries)
					return st
				case "alwaysTrue":
					return dpopFixedStore{ok: true}
				case "alwaysFalse":
					return dpopFixedStore{}
				}
				return &dpopNoExpiry{seen: map[string]bool{}}
			})
		},
		"createDpopProof": func(a []any) (any, error) { return CreateDpopProof(dpopCreateInput(vecObj(vecArg(a, 0)))) },
		"createThenVerify": func(a []any) (any, error) {
			in := vecObj(vecArg(a, 0))
			proof, err := CreateDpopProof(dpopCreateInput(in))
			if err != nil {
				return nil, err
			}
			iat := 1800000000.0
			if f := dpopF(in["iat"]); f != nil {
				iat = *f
			}
			m := map[string]any{"method": in["method"], "url": in["url"], "maxAgeSec": 300.0, "nowSec": iat + 1, "seenJti": []any{}}
			for k, v := range vecObj(vecArg(a, 1)) {
				m[k] = v
			}
			o, seen, err := dpopVerifyOpts(m)
			if err != nil {
				return nil, err
			}
			r, err := VerifyDpopProof(proof, o)
			if err != nil {
				return nil, err
			}
			return dpopResult(r, seen), nil
		},
		"verifyDpopProof": func(a []any) (any, error) {
			o, seen, err := dpopVerifyOpts(vecObj(vecArg(a, 1)))
			if err != nil {
				return nil, err
			}
			r, err := VerifyDpopProof(dpopProofArg(vecArg(a, 0)), o)
			if err != nil {
				return nil, err
			}
			return dpopResult(r, seen), nil
		},
		"mtlsCnf":        func(a []any) (any, error) { return MtlsCnf(dpopCert(vecArg(a, 0))) },
		"mtlsThumbprint": func(a []any) (any, error) { return MtlsThumbprint(dpopCert(vecArg(a, 0))) },
		"assertMtlsBound": func(a []any) (any, error) {
			return AssertMtlsBound(dpopCert(vecArg(a, 0)), vecArg(a, 1))
		},
		"leafHolderJwk": func(a []any) (any, error) { return LeafHolderJwk(vecObj(vecArg(a, 0))) },
		"bindPcaToDpop": func(a []any) (any, error) { return BindPcaToDpop(vecObj(vecArg(a, 0))) },
		"assertPcaDpop": func(a []any) (any, error) {
			o, seen, err := dpopVerifyOpts(vecObj(vecArg(a, 2)))
			if err != nil {
				return nil, err
			}
			r, err := AssertPcaDpop(vecObj(vecArg(a, 0)), dpopProofArg(vecArg(a, 1)), o)
			if err != nil {
				return nil, err
			}
			return dpopResult(r, seen), nil
		},
	})
}

// dpopNoExpiry remembers keys forever (the conformance suite must flag it).
type dpopNoExpiry struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (s *dpopNoExpiry) AddIfAbsent(k string, _, _ float64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[k] {
		return false, nil
	}
	s.seen[k] = true
	return true, nil
}

// A NaN or infinite maxAgeSec would disable the stale check, and a non-finite nowSec would void the window: both are refused.
func TestDpopNonFiniteMaxAgeAndNowRefused(t *testing.T) {
	seed := sha256.Sum256([]byte("dpop-non-finite"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	x := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	d := base64.RawURLEncoding.EncodeToString(seed[:])
	iat := 1800000000.0
	url := "https://rs.example/r"
	proof, err := CreateDpopProof(CreateDpopProofInput{Method: "GET", URL: url, Iat: &iat,
		PrivateKey: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x, "d": d}, PublicJwk: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": x}})
	if err != nil {
		t.Fatal(err)
	}
	no := false
	verify := func(maxAge, now *float64) error {
		_, err := VerifyDpopProof(proof, VerifyDpopProofOptions{Method: "GET", URL: url, MaxAgeSec: maxAge, NowSec: now, RequireReplayStore: &no})
		return err
	}
	code := func(err error) string {
		var ce *CodedError
		if errors.As(err, &ce) {
			return ce.Code
		}
		return ""
	}
	now := iat + 1
	if err := verify(nil, &now); err != nil {
		t.Fatalf("control: %v", err)
	}
	stale := iat + 301
	if code(verify(nil, &stale)) != "iat_stale" {
		t.Error("an absent maxAgeSec must mean the 300 s default")
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		v := v
		if c := code(verify(&v, &stale)); c != "max_age" {
			t.Errorf("maxAgeSec %v: got %q, want max_age", v, c)
		}
		if c := code(verify(nil, &v)); c != "now" {
			t.Errorf("nowSec %v: got %q, want now", v, c)
		}
	}
}
