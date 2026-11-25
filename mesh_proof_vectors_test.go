package pca

import (
	"errors"
	"testing"
)

// Replay of mesh proof assembly against the reference (ref-core-mesh-proof-java): scripts that build domains, witnesses, heads and
// per-hop evidence, then assemble compact proofs and sign actions. Every op answers its value, or {"$err": "Error"}.
func TestMeshProofAssemblyMatchesTheReference(t *testing.T) {
	key := func(label any) *KeyPair { s, _ := label.(string); return mwKey(t, "mesh-proof/"+s) }
	chainOf := func(v any) []map[string]any {
		var out []map[string]any
		for _, l := range v.([]any) {
			out = append(out, mwCap(l.(string), true))
		}
		return out
	}
	count := 0
	replayVectors(t, "ref-core-mesh-proof-java.json.gz", map[string]vecFn{"meshProof": func(a []any) (any, error) {
		count++
		doms := map[string]*MeshDomain{}
		ws := map[string]*MeshWitness{}
		store := map[string]map[string]any{}
		need := func(name any) map[string]any {
			s, _ := name.(string)
			v, ok := store[s]
			if !ok {
				panic("unknown " + s)
			}
			return v
		}
		out := []any{}
		for _, oo := range a[0].([]any) {
			op := oo.([]any)
			v, err := func() (v any, err error) {
				defer func() {
					if r := recover(); r != nil {
						err = errors.New("panic")
					}
				}()
				str := func(i int) string { return op[i].(string) }
				switch op[0] {
				case "domain":
					d := NewMeshDomain(str(1), key(op[2]))
					doms[str(1)] = d
					return d.ID, nil
				case "witness":
					w, e := NewMeshWitness(key(op[2]), MeshWitnessOptions{})
					if e != nil {
						return nil, e
					}
					ws[str(1)] = w
					return w.ID, nil
				case "record":
					i, e := doms[str(1)].Record(mwCap(str(2), true))
					return mwNum(i), e
				case "revoke":
					doms[str(1)].Revoke(str(2))
					return nil, nil
				case "publish":
					var list []*MeshWitness
					for _, w := range op[4].([]any) {
						list = append(list, ws[w.(string)])
					}
					h, e := doms[str(1)].PublishHead(list, jsF(op[3]), mwThreshold(op[5]))
					if e != nil {
						return nil, e
					}
					store[str(2)] = h
					return h, nil
				case "subcos":
					h := copyMap(need(op[2]))
					all, _ := h["cosigs"].([]any)
					keep := []any{}
					for _, i := range op[3].([]any) {
						keep = append(keep, all[int(jsF(i))])
					}
					h["cosigs"] = keep
					store[str(1)] = h
					return nil, nil
				case "fork":
					h := copyMap(need(op[2]))
					h[str(3)] = op[4]
					store[str(1)] = h
					return nil, nil
				case "forkHead":
					h := copyMap(need(op[2]))
					inner := copyMap(vecObj(h["head"]))
					inner[str(3)] = op[4]
					h["head"] = inner
					store[str(1)] = h
					return nil, nil
				case "enroll":
					b, e := doms[str(1)].Enroll(str(3), str(4))
					if e != nil {
						return nil, e
					}
					store[str(2)] = b
					return b, nil
				case "ev":
					var binding map[string]any
					if op[5] != nil {
						binding = need(op[5])
					}
					e, err := doms[str(1)].Evidence(mwCap(str(3), true), need(op[4]), binding)
					if err != nil {
						return nil, err
					}
					store[str(2)] = e
					return e, nil
				case "setEv":
					e := copyMap(need(op[2]))
					val := op[4]
					name, isName := val.(string)
					_, known := store[name]
					switch {
					case vecObj(val) != nil && vecObj(val)["$del"] != nil:
						delete(e, str(3))
					case str(3) == "head" && isName && known: // a head name stands for the stored head
						e["head"] = store[name]
					default:
						e[str(3)] = val
					}
					store[str(1)] = e
					return nil, nil
				case "pinProofAs":
					pin := vecObj(op[3])
					if name, isName := op[3].(string); isName {
						pin = vecObj(need(name)["head"])
					}
					p, e := doms[str(1)].PinProof(pin, need(op[4]))
					if e != nil {
						return nil, e
					}
					store[str(2)] = p
					return p, nil
				case "assemble":
					var hops []map[string]any
					for _, n := range op[2].([]any) {
						hops = append(hops, need(n))
					}
					var pins []any
					if op[5] != nil {
						pins = []any{}
						for _, n := range op[5].([]any) {
							pins = append(pins, need(n))
						}
					}
					return AssembleMeshProof(chainOf(op[1]), hops, vecObj(op[3]), key(op[4]), pins)
				case "sign":
					return SignMeshAction(chainOf(op[1]), vecObj(op[2]), key(op[3]))
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
	}})
	if count != 8 {
		t.Fatalf("replayed %d cases, the corpus has 8", count)
	}
}
