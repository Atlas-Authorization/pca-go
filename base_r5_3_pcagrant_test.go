package pca

import (
	"encoding/json"
	"testing"
)

func TestR5N3PcaGrantURLAuthorityEndsAtTheFirstSeparator(t *testing.T) {
	for u, want := range map[string]bool{"https://a/@/x": true, "https://a/?@/x": true, "https://a?/@": true, "https://a/x@y": true} {
		if got := PcaGrantHTTPSURL(u); got != want {
			t.Errorf("PcaGrantHTTPSURL(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestR5N3PcaGrantDetailAcceptedAndRefused(t *testing.T) {
	d, err := PcaGrantChainDigest([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]any{"type": "pca_grant", "chain_len": json.Number("1"), "chain_digest": d}
	if code, good := ValidatePcaGrantDetail(ok); code != "" || !good {
		t.Errorf("valid detail: %q %v", code, good)
	}
	for _, bad := range []any{nil, 5, "x"} {
		if code, good := ValidatePcaGrantDetail(map[string]any{"type": "pca_grant", "chain_len": json.Number("1"), "chain_digest": bad}); code != "bad_chain_digest" || good {
			t.Errorf("chain_digest %v: %q %v", bad, code, good)
		}
	}
	for _, e := range []any{nil, "x", 5} {
		if out, code := ParsePcaGrantDetails([]any{e}); out != nil || code != "bad_entry" {
			t.Errorf("entry %v: %v %q", e, out, code)
		}
	}
}

func TestR5N3PcaGrantPresentationSkipsAWrongLocationDetail(t *testing.T) {
	d, err := PcaGrantChainDigest([]string{"a"})
	if err != nil {
		t.Fatal(err)
	}
	wrong := map[string]any{"type": "pca_grant", "chain_len": json.Number("1"), "chain_digest": d, "locations": []any{"https://other"}}
	right := map[string]any{"type": "pca_grant", "chain_len": json.Number("1"), "chain_digest": d}
	if i, code := CheckPcaGrantPresentation([]map[string]any{wrong, right}, "https://rs", []string{"a"}, true); i != 1 || code != "" {
		t.Errorf("second detail: %d %q", i, code)
	}
	if i, code := CheckPcaGrantPresentation([]map[string]any{wrong}, "https://rs", []string{"a"}, true); i != -1 || code != "wrong_location" {
		t.Errorf("only the wrong location: %d %q", i, code)
	}
}
