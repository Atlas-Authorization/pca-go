package pca

// Replays the reference oracle of the revocation registry, the chain check and the CAEP bridge (testdata/ref-revoke.json.gz).
// A scenario runs its steps over a fresh registry; a step's result is the JSON of what the call returned, or {"$err": true}.

import (
	"errors"
	"math"
	"os"
	"testing"
	"time"
)

var errBoom = errors.New("boom")

type failingRevocationStore struct {
	*MemoryRevocationStore
	failGet, failAll bool
}

func (s failingRevocationStore) Get(kind, value string) (RevocationEntry, error) {
	if s.failGet {
		return nil, errBoom
	}
	return s.MemoryRevocationStore.Get(kind, value)
}

func (s failingRevocationStore) All() ([]RevocationEntry, error) {
	if s.failAll {
		return nil, errBoom
	}
	return s.MemoryRevocationStore.All()
}

// vecRevNow marks a revokedAt within two minutes of the wall clock, or of the oracle's fixed clock, as "<now>" (the reference does
// the same against the clock it ran under).
func vecRevNow(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = vecRevNow(x)
		}
		return out
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			if f, ok := jsNum(x); ok && k == "revokedAt" && (math.Abs(f-float64(time.Now().UnixMilli())) < 120_000 || math.Abs(f-vecOracleNow()) < 120_000) {
				out[k] = "<now>"
			} else {
				out[k] = vecRevNow(x)
			}
		}
		return out
	}
	return v
}

// vecNowPtr maps the reference opts.now: absent / null = the wall clock; a non-number = a non-finite clock.
func vecNowPtr(opts any) *float64 {
	x := vecObj(opts)["now"]
	if x == nil {
		return nil
	}
	f, ok := jsNum(x)
	if !ok {
		f = math.NaN()
	}
	return &f
}

func revokeScenario(spec map[string]any) []any {
	mem := NewMemoryRevocationStore()
	var store RevocationStore = mem
	switch spec["store"] {
	case "failGet":
		store = failingRevocationStore{mem, true, false}
	case "failAll":
		store = failingRevocationStore{mem, false, true}
	}
	reg := NewRevocationRegistry(store)
	ops, _ := spec["ops"].([]any)
	out := make([]any, 0, len(ops))
	for _, x := range ops {
		s := vecObj(x)
		var r any
		var err error
		switch s["op"] {
		case "revoke":
			r, err = reg.Revoke(vecObj(s["input"]))
		case "revokeSubtree":
			r, err = reg.RevokeSubtree(s["target"], vecObj(s["opts"]))
		case "unrevoke":
			r, err = reg.Unrevoke(s["key"])
		case "list":
			r, err = reg.List()
		case "lookup":
			var e RevocationEntry
			e, err = reg.Lookup(jsTemplate(s["kind"], true), jsTemplate(s["value"], true))
			if e != nil {
				r = e
			}
		case "prefixes":
			r, err = reg.Prefixes()
		case "clear":
			err = reg.Clear()
		case "killAgent":
			r, err = reg.KillAgent(s["holder"], vecObj(s["opts"]))
		case "killSubtree":
			r, err = reg.KillSubtree(s["root"], vecObj(s["opts"]))
		case "check":
			r = CheckRevocation(s["p"], reg, vecNowPtr(s["opts"]))
		case "verify":
			r = VerifyWithRevocation(s["p"], s["core"], reg, vecNowPtr(s["opts"]))
		case "ingest":
			r, err = IngestCaepEvent(s["event"], reg)
		default:
			err = errors.New("bad op")
		}
		if err != nil {
			out = append(out, map[string]any{"$err": true})
			continue
		}
		out = append(out, vecRevNow(vecJSON(r)))
	}
	return out
}

func TestRevokeVectors(t *testing.T) {
	replayVectors(t, "ref-revoke.json.gz", map[string]vecFn{
		"scenario": func(a []any) (any, error) { return revokeScenario(vecObj(a[0])), nil },
		"isActiveAt": func(a []any) (any, error) {
			now, ok := jsNum(vecArg(a, 1))
			if !ok {
				now = math.NaN()
			}
			return IsActiveAt(vecObj(a[0]), now), nil
		},
		"caepEventTypes": func(a []any) (any, error) {
			return map[string]any{"sessionRevoked": CaepSessionRevoked, "grantRevoked": CaepGrantRevoked, "killSwitch": CaepKillSwitch}, nil
		},
	})
}

func TestFileRevocationStoreRoundTrip(t *testing.T) {
	path := t.TempDir() + "/rev.json"
	s, err := OpenFileRevocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	reg := NewRevocationRegistry(s)
	if _, err := reg.Revoke(map[string]any{"kind": "prefix", "prefix": []any{"a", "b"}, "revokedAt": 5.0}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.KillAgent("h1", nil); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenFileRevocationStore(path)
	if err != nil {
		t.Fatal(err)
	}
	all, _ := s2.All()
	if len(all) != 2 || all[0]["value"] != "a,b" || all[1]["value"] != "h1" {
		t.Fatalf("reloaded %v", all)
	}
	if ok, _ := NewRevocationRegistry(s2).Unrevoke(map[string]any{"kind": "holder", "value": "h1"}); !ok {
		t.Fatal("unrevoke")
	}
	if err := os.WriteFile(path, []byte(`{"v":1,"entries":[{"kind":"bogus","value":"x","reason":"","revokedAt":1}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileRevocationStore(path); err == nil {
		t.Fatal("an invalid file must be refused, not started empty")
	}
}
