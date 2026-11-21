package pca

import (
	"errors"
	"testing"
)

// Replay of the chain-compaction corpus: hop leaves, hops root, compact chain and its shape check, the verifier memo and the
// chain view, against the reference.

func ccViewOut(v ChainView) (any, error) {
	hashes, counts := []any{}, []any{}
	for i := 0; i < v.N; i++ {
		h, err := v.Hash(i)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, h)
		counts = append(counts, jsNumber(float64(v.Count(i))))
	}
	return map[string]any{"n": jsNumber(float64(v.N)), "leaf": v.Leaf, "hashes": hashes, "counts": counts}, nil
}

// ccClock is the clock the reference takes only when it is a safe integer.
func ccClock(v any) (int64, bool) {
	if !jsIsInt(v) {
		return 0, false
	}
	f, _ := jsNum(v)
	return int64(f), true
}

func ccMemoSeq(a []any) (any, error) {
	var opts ChainMemoOptions
	if o := vecObj(a[0]); o != nil {
		if f, ok := jsNum(o["maxEntries"]); ok {
			opts.MaxEntries = int(f)
		}
		if f, ok := jsNum(o["ttlMs"]); ok {
			opts.TTLMs = int64(f)
		}
	}
	m := NewChainMemo(opts)
	out := []any{}
	for _, s0 := range a[1].([]any) {
		s := s0.([]any)
		switch s[0] {
		case "remember":
			now, ok := ccClock(s[3])
			chain, _ := s[1].([]any)
			issuer, _ := s[2].(string)
			var compact map[string]any
			var err error
			if ok {
				compact, err = m.RememberVerified(chain, issuer, now, nil)
			}
			if !ok || err != nil {
				out = append(out, map[string]any{"ok": false})
			} else {
				out = append(out, map[string]any{"ok": true, "compact": compact})
			}
		case "resolve":
			now, ok := ccClock(s[2])
			if !ok {
				out = append(out, map[string]any{"ok": false, "reason": "the verifier clock is not a safe integer (fail closed)"})
				break
			}
			r := m.Resolve(s[1], now)
			if !r.OK {
				out = append(out, map[string]any{"ok": false, "reason": r.Reason})
				break
			}
			v, err := ccViewOut(r.View)
			if err != nil {
				return nil, err
			}
			out = append(out, map[string]any{"ok": true, "view": v})
		case "prune":
			now, _ := ccClock(s[1])
			m.Prune(now)
			out = append(out, nil)
		case "forget":
			out = append(out, m.Forget(s[1].(string)))
		default:
			out = append(out, jsNumber(float64(m.Size())))
		}
	}
	return out, nil
}

func TestChainCompactMatchesTheReference(t *testing.T) {
	replayVectors(t, "ref-core-chain-compact.json.gz", map[string]vecFn{
		"hopLeaf":  func(a []any) (any, error) { return HopLeaf(vecObj(a[0])) },
		"hopsRoot": func(a []any) (any, error) { return HopsRoot(a[0].([]any)) },
		"compactChain": func(a []any) (any, error) {
			chain, ok := vecArg(a, 0).([]any)
			if !ok {
				return nil, errors.New("chain is not an array")
			}
			return CompactChain(chain)
		},
		"compactChainShapeError": func(a []any) (any, error) { return ccNilIfEmpty(CompactChainShapeError(a[0])), nil },
		"viewOfChain":            func(a []any) (any, error) { return ccViewOut(ViewOfChain(a[0], a[1])) },
		"memoSeq":                ccMemoSeq,
	})
}

func ccNilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
