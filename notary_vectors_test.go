package pca

// Replays the notary reference corpus. A byte string is {"$bytes": b64url}. A notary key pair is {"secretKey": {"$fill": n},
// "publicKey": {"$bytes": ...}}: the corpus carries no key material, so the 32-byte seed is rebuilt as n repeated 32 times and the
// public key is derived from it. Hiding salts come from the reference's deterministic salt stream: salt_i = sha256("notary-oracle-salt/" + i)[:16],
// restarted at 0 for every notarizeResponse case.
//
// Skipped cases:
//   - evaluateAttestedFactCaveat with an explicit null policy: Go nil is the absent policy (the reference throws on null).

import (
	"crypto/sha256"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

func nyTBytes(v any) ([]byte, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	s, ok := m["$bytes"].(string)
	if !ok {
		return nil, false
	}
	b, err := b64.DecodeString(s)
	return b, err == nil
}

// nyKeyArg maps a corpus key value onto the Go key inputs; anything else stays as is (and is refused by the entry points).
func nyKeyArg(v any) any {
	if b, ok := nyTBytes(v); ok {
		return b
	}
	m, ok := v.(map[string]any)
	if !ok {
		return v
	}
	sk, ok := m["secretKey"].(map[string]any)
	if !ok {
		return v
	}
	f, ok := jsNum(sk["$fill"])
	if l, isSeed := sk["$seed"].(string); isSeed && strings.HasPrefix(l, "fill:") { // the oracle's repeated-byte seed, as a label
		if n, err := strconv.Atoi(strings.TrimPrefix(l, "fill:")); err == nil {
			f, ok = float64(n), true
		}
	}
	if !ok || f < 0 || f > 255 {
		return v
	}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(f)
	}
	kp, err := KeyPairFromSeed(seed)
	if err != nil {
		return v
	}
	return kp
}

func nyArg(args []any, i int) any { return vecArg(args, i) }

func TestNotaryVectors(t *testing.T) {
	replayVectors(t, "ref-notary.json.gz", map[string]vecFn{
		"constants": func(a []any) (any, error) {
			return map[string]any{"BODY_COMMIT_ALG": NotaryBodyCommitAlg, "ATTESTED_FACT_CAVEAT": NotaryAttestedFactCaveat}, nil
		},
		"notaryMessage": func(a []any) (any, error) {
			b, err := NotaryMessage(nyArg(a, 0))
			if err != nil {
				return nil, err
			}
			return map[string]any{"$bytes": b64.EncodeToString(b)}, nil
		},
		"notarizeResponse": func(a []any) (any, error) {
			o, _ := nyArg(a, 1).(map[string]any)
			kp, _ := nyKeyArg(o["notaryKey"]).(*KeyPair)
			opts := NotarizeOptions{NotaryKey: kp}
			if f, ok := jsNum(o["observedAt"]); ok {
				if f != math.Trunc(f) || math.Abs(f) > 1<<62 {
					return nil, errors.New("observedAt is not an integer")
				}
				v := int64(f)
				opts.ObservedAt = &v
			}
			if f, ok := jsNum(o["textChunkSize"]); ok {
				opts.TextChunkSize = f
			}
			ctr := 0
			opts.Salt = func() []byte {
				h := sha256.Sum256([]byte("notary-oracle-salt/" + strconv.Itoa(ctr)))
				ctr++
				return h[:16]
			}
			return NotarizeResponse(nyArg(a, 0), opts)
		},
		"discloseField": func(a []any) (any, error) { return DiscloseField(nyArg(a, 0), nyArg(a, 1), nyArg(a, 2)) },
		"verifyNotaryAttestation": func(a []any) (any, error) {
			return VerifyNotaryAttestation(nyArg(a, 0), nyKeyArg(nyArg(a, 1))), nil
		},
		"verifyDisclosedField": func(a []any) (any, error) {
			return VerifyDisclosedField(nyArg(a, 0), nyArg(a, 1), nyKeyArg(nyArg(a, 2))), nil
		},
		"factRef":              func(a []any) (any, error) { return FactRef(nyArg(a, 0)) },
		"bindFactToPcActn":     func(a []any) (any, error) { return BindFactToPcActn(nyArg(a, 0), nyArg(a, 1)) },
		"factMatchesPcActn":    func(a []any) (any, error) { return FactMatchesPcActn(nyArg(a, 0), nyArg(a, 1)), nil },
		"isAttestedFactCaveat": func(a []any) (any, error) { return IsAttestedFactCaveat(nyArg(a, 0)), nil },
		"notaryKeyUsable": func(a []any) (any, error) {
			return NotaryKeyUsable(nyArg(a, 0), nyArg(a, 1), nyArg(a, 2)), nil
		},
		"requireAttestedFact": func(a []any) (any, error) {
			m, ok := nyArg(a, 0).(map[string]any)
			if !ok {
				return nil, errors.New("opts must be an object")
			}
			o := RequireAttestedFactOpts{Notary: nyKeyArg(m["notary"]), Path: m["path"], Equals: m["equals"]}
			if s, ok := m["url"].(string); ok {
				o.URL = &s
			}
			if b, ok := m["bindToPcActn"].(bool); ok {
				o.BindToPcActn = &b
			}
			return RequireAttestedFact(o)
		},
		"evaluateAttestedFactCaveat": func(a []any) (any, error) {
			var policy any
			if len(a) >= 3 {
				if a[2] == nil {
					return nil, vecSkip("an explicit null policy: Go nil is the absent policy")
				}
				policy = a[2]
			}
			return EvaluateAttestedFactCaveat(nyArg(a, 0), nyArg(a, 1), policy), nil
		},
	})
}
