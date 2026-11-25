package pca

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

// Replays packages/pca/conformance/allowlist-anchor-vectors.json (wire-level allowlist anchor evidence).
func TestAllowlistAnchorConformance(t *testing.T) {
	raw, err := os.ReadFile(dir + "allowlist-anchor-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc struct {
		Trust struct {
			LogKey     string `json:"logKey"`
			InstanceID string `json:"instanceId"`
			Principal  string `json:"principal"`
		} `json:"trust"`
		Vectors []map[string]any `json:"allowlist_anchor"`
	}
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) < 74 {
		t.Fatalf("only %d vectors", len(doc.Vectors))
	}
	num := func(v any) *int64 {
		if v == nil {
			return nil
		}
		n, _ := v.(json.Number).Int64()
		return &n
	}
	for _, v := range doc.Vectors {
		name := v["name"].(string)
		m := v["manifest"].(map[string]any)
		ver, _ := m["version"].(json.Number).Int64()
		mine := AnchorEntry{Issuer: m["issuer"].(string), Version: ver, Digest: m["digest"].(string)}
		now, _ := v["now"].(json.Number).Int64()
		var ev map[string]any
		if e, ok := v["evidence"].(map[string]any); ok {
			ev = e
		}
		var cached map[string]any
		if c, ok := v["cachedHead"].(map[string]any); ok {
			cached = c
		}
		got := VerifyAllowlistAnchored(mine, ev, AnchorOptions{
			Trust: AnchorTrust{LogKey: doc.Trust.LogKey, InstanceID: doc.Trust.InstanceID, Principal: doc.Trust.Principal},
			NowMs: now, MaxHeadAgeMs: num(v["maxHeadAgeMs"]), ClockSkewMs: num(v["clockSkewMs"]), CachedHead: cached,
		})
		want := v["expect"].(map[string]any)
		if want["ok"].(bool) {
			wh, _ := want["highestAnchoredVersion"].(json.Number).Int64()
			if !got.Ok || got.HighestAnchoredVersion != wh {
				t.Errorf("%s: got %+v, want ok highest=%d", name, got, wh)
			}
		} else if got.Ok || got.Code != want["code"].(string) {
			t.Errorf("%s: got %+v, want code %v", name, got, want["code"])
		}
	}
}
