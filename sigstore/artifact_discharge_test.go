package pcasigstore

// Replays the issueArtifactDischarge cases of the shared EAT corpus: the Sigstore bundle, the provenance gate over the verifier's
// own pins, the join with the running digest, and the signed discharge (Ed25519 is deterministic, so the bytes must match).

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	pca "github.com/Atlas-Authorization/pca-go"
)

type eatCorpusCase struct {
	Fn   string            `json:"fn"`
	Name string            `json:"name"`
	Args []json.RawMessage `json:"args"`
	Out  json.RawMessage   `json:"out"`
}

func TestIssueArtifactDischargeVectors(t *testing.T) {
	f, err := os.Open("../testdata/ref-attest-eat.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []eatCorpusCase `json:"cases"`
	}
	if err := json.NewDecoder(zr).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	nonceSum := sha256.Sum256([]byte("eat-oracle-nonce/0"))
	nonce := base64.RawURLEncoding.EncodeToString(nonceSum[:16])
	ran := 0
	for _, c := range corpus.Cases {
		if c.Fn != "issueArtifactDischarge" {
			continue
		}
		ran++
		in := baseSigDecode(c.Args[0]).(map[string]any)
		bundle, _ := json.Marshal(in["bundle"])
		rootsJSON, _ := json.Marshal(in["roots"])
		roots, err := ParseTrustedRoot(rootsJSON)
		if err != nil {
			t.Fatalf("%s: roots: %v", c.Name, err)
		}
		label := in["issuerKey"].(map[string]any)["seed"].(map[string]any)["$seed"].(string)
		seed := sha256.Sum256([]byte("atlas-pca-conformance/" + label))
		kp, err := pca.KeyPairFromSeed(seed[:])
		if err != nil {
			t.Fatal(err)
		}
		req, _ := in["request"].(map[string]any)
		now, _ := in["now"].(json.Number).Int64()
		input := ArtifactDischargeInput{Bundle: bundle, Roots: roots, Policy: in["policy"], Request: req, Now: now, Issuer: kp, Nonce: nonce}
		if rt, has := in["runtime"]; has {
			input.RuntimeSet = true
			input.Runtime, _ = rt.(map[string]any)
		}
		if tv, has := in["ttl_ms"]; has {
			n, _ := tv.(json.Number).Int64()
			input.TtlMs = &n
		}
		res, err := IssueArtifactDischarge(input)
		var want map[string]any
		_ = json.Unmarshal(c.Out, &want)
		if msg, throws := want["$throws"].(string); throws {
			if err == nil {
				t.Errorf("%s: reference refuses (%s), Go returned a result", c.Name, msg)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: Go refuses (%v)", c.Name, err)
			continue
		}
		var got map[string]any
		if res.OK {
			got = map[string]any{"ok": true, "discharge": res.Discharge, "facts": res.Facts, "level": res.Level}
		} else {
			got = map[string]any{"ok": false, "stage": res.Stage, "code": res.Code}
			delete(want, "detail") // the detail embeds runtime messages of the reference
		}
		if !reflect.DeepEqual(baseSigJSON(got), baseSigDecode(c.Out).(map[string]any)) && !res.OK {
			g := baseSigJSON(got).(map[string]any)
			if g["ok"] != want["ok"] || g["stage"] != want["stage"] || g["code"] != want["code"] {
				t.Errorf("%s: want %s got %v", c.Name, strings.TrimSpace(string(c.Out)), g)
			}
		} else if res.OK && !reflect.DeepEqual(baseSigJSON(got), baseSigDecode(c.Out)) {
			t.Errorf("%s: discharge differs from the reference", c.Name)
		}
	}
	if ran != 28 {
		t.Fatalf("ran %d discharge cases, want 28", ran)
	}
}
