package pca

// Replays the agent-side adapter corpus: messageSegments, provenanceHeaders and the recorder flow (record* helpers feeding a
// provenance recorder with a fixed key, session and clock, so the signed bundles are byte-deterministic).
//
// Skipped: a recorder flow that stringifies an object with several members (JSON.stringify keeps insertion order, and a decoded
// Go map only keeps it through the parser's side table).

import (
	"crypto/sha256"
	"testing"
)

func adapterSeedOf(label string) []byte {
	d := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
	return d[:]
}

// adapterMultiKeyContent reports whether recording the messages would JSON-stringify an object with several members.
func adapterMultiKeyContent(msgs any) bool {
	list, _ := msgs.([]any)
	for _, m := range list {
		for _, seg := range AdapterMessageSegments(m) {
			if seg["origin"] != "principal" {
				continue
			}
			if o, ok := seg["content"].(map[string]any); ok && len(o) > 1 {
				return true
			}
		}
	}
	return false
}

func adapterFlow(spec map[string]any) (any, error) {
	steps, _ := spec["steps"].([]any)
	for _, s := range steps {
		st := vecObj(s)
		if adapterMultiKeyContent(st["messages"]) || adapterMultiKeyContent(st["input"]) {
			return nil, vecSkip("object content stringified with several members")
		}
		if in := vecObj(st["input"]); in != nil {
			for _, k := range []string{"input", "text"} {
				if adapterMultiKeyContent(in[k]) {
					return nil, vecSkip("object content stringified with several members")
				}
			}
			if adapterMultiKeyContent(in["messages"]) {
				return nil, vecSkip("object content stringified with several members")
			}
		}
	}
	key, err := KeyPairFromSeed(adapterSeedOf("ref-adapters/recorder"))
	if err != nil {
		return nil, err
	}
	rec, err := NewProvenanceRecorder(ProvenanceRecorderOptions{Mediator: "harness", Kid: "k1", Key: key,
		Session: b64.EncodeToString(adapterSeedOf("ref-adapters/session")), Now: /* scenario input, not the generator clock: the reference oracle injects this fixed T0 into its own clock and bakes it into the case data (token iat/exp, budget tau, grant times), so it must not follow the header clockMs (the Date.now default 1.7e12). */ func() int64 { return 1_800_000_000_000 }})
	if err != nil {
		return nil, err
	}
	bundles := []any{}
	for _, s := range steps {
		st := vecObj(s)
		switch st["op"] {
		case "messages":
			err = AdapterRecordMessages(rec, st["messages"])
		case "input":
			err = AdapterRecordInput(rec, st["input"])
		case "principal":
			text, _ := st["text"].(string)
			err = AdapterRecordPrincipal(rec, text)
		case "tool":
			name, _ := st["tool"].(string)
			err = AdapterRecordToolResult(rec, name, st["output"])
		case "act":
			a := vecObj(st["action"])
			params, _ := a["params"].(map[string]any)
			var b map[string]any
			b, err = rec.ForAction(Operation{Verb: vecStr(a, "verb"), Resource: vecStr(a, "resource"), Params: params})
			bundles = append(bundles, b)
		}
		if err != nil {
			return nil, err
		}
	}
	receipts := []any{}
	for _, r := range rec.Receipts() {
		receipts = append(receipts, r)
	}
	return map[string]any{"bundles": bundles, "receipts": receipts}, nil
}

func TestAdaptersReferenceVectors(t *testing.T) {
	replayVectors(t, "ref-adapters.json.gz", map[string]vecFn{
		"messageSegments": func(args []any) (any, error) { return AdapterMessageSegments(vecArg(args, 0)), nil },
		"provenanceHeaders": func(args []any) (any, error) {
			return AdapterProvenanceHeaders(vecArg(args, 0))
		},
		"recordFlow": func(args []any) (any, error) { return adapterFlow(vecObj(vecArg(args, 0))) },
	})
}
