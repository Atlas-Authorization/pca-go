package pca

// The `pca_grant` OAuth authorization-details type (RFC 9396): validation and the resource-server presentation check. The
// type is a pointer to a PCA grant, not authority: a verified per-action PCActn is still required. Total functions.

const (
	pcaGrantType      = "pca_grant"
	pcaGrantDomain    = "atlas-pca/pca-grant-chain/v1"
	pcaGrantMaxDetail = 16
	pcaGrantMaxChain  = 16
	pcaGrantMaxURL    = 2048
	pcaGrantMaxLoc    = 8
)

var pcaGrantMembers = map[string]bool{"type": true, "chain_digest": true, "chain_len": true, "chain_ref": true, "bundle_revision": true, "locations": true}
var pcaGrantRefused = map[string]bool{"actions": true, "datatypes": true, "identifier": true, "privileges": true}

// PcaGrantHTTPSURL: starts with https://, only printable ASCII without '#' or '\', at most 2048 characters, and a non-empty
// authority (up to the first '/' or '?') with no '@'.
func PcaGrantHTTPSURL(v any) bool {
	u, ok := v.(string)
	if !ok || len(u) > pcaGrantMaxURL || len(u) < 8 || u[:8] != "https://" {
		return false
	}
	for i := 0; i < len(u); i++ {
		if c := u[i]; c < 0x21 || c > 0x7e || c == '#' || c == '\\' {
			return false
		}
	}
	rest := u[8:]
	end := len(rest)
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' || rest[i] == '?' {
			end = i
			break
		}
	}
	authority := rest[:end]
	if authority == "" {
		return false
	}
	for i := 0; i < len(authority); i++ {
		if authority[i] == '@' {
			return false
		}
	}
	return true
}

// PcaGrantChainDigest is the digest over the first hops' capability ids.
func PcaGrantChainDigest(ids []string) (string, error) {
	list := make([]any, len(ids))
	for i, s := range ids {
		list[i] = s
	}
	return HashCanonical(map[string]any{"d": pcaGrantDomain, "ids": list})
}

// ValidatePcaGrantDetail returns ("", true) for an accepted detail, else the refusal code.
func ValidatePcaGrantDetail(x any) (string, bool) {
	m, ok := x.(map[string]any)
	if !ok {
		return "bad_entry", false
	}
	if t, _ := m["type"].(string); t != pcaGrantType {
		return "bad_type", false
	}
	for k := range m {
		if pcaGrantRefused[k] {
			return "refused_member", false
		}
		if !pcaGrantMembers[k] {
			return "unknown_member", false
		}
	}
	d, isStr := m["chain_digest"].(string)
	if !isStr {
		return "bad_chain_digest", false
	}
	if _, ok := DecodeB64uStrict(d, 32); !ok {
		return "bad_chain_digest", false
	}
	if f, ok := jsNum(m["chain_len"]); !ok || !jsIsSafeInteger(m["chain_len"]) || f < 1 || f > pcaGrantMaxChain {
		return "bad_chain_len", false
	}
	if v, has := m["chain_ref"]; has && !PcaGrantHTTPSURL(v) {
		return "bad_chain_ref", false
	}
	if v, has := m["bundle_revision"]; has && !k3Int(v) {
		return "bad_bundle_revision", false
	}
	if v, has := m["locations"]; has {
		l, ok := v.([]any)
		if !ok || len(l) == 0 || len(l) > pcaGrantMaxLoc {
			return "bad_locations", false
		}
		for _, u := range l {
			if !PcaGrantHTTPSURL(u) {
				return "bad_locations", false
			}
		}
	}
	return "", true
}

// ParsePcaGrantDetails returns the pca_grant entries of an authorization_details array, or the refusal code.
func ParsePcaGrantDetails(arr any) ([]map[string]any, string) {
	l, ok := arr.([]any)
	if !ok {
		return nil, "not_an_array"
	}
	if len(l) > pcaGrantMaxDetail {
		return nil, "too_many_details"
	}
	out := []map[string]any{}
	for _, e := range l {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, "bad_entry"
		}
		t, isStr := m["type"].(string)
		if !isStr {
			return nil, "bad_entry"
		}
		if t != pcaGrantType {
			continue
		}
		if code, ok := ValidatePcaGrantDetail(m); !ok {
			return nil, code
		}
		out = append(out, m)
	}
	return out, ""
}

// CheckPcaGrantPresentation allows only with a verified per-action proof and a detail naming a prefix of the presented
// chain (and this resource). It returns the index of the passing detail, or the deny code.
func CheckPcaGrantPresentation(details []map[string]any, resource string, chainIDs []string, proofVerified bool) (int, string) {
	if len(details) == 0 {
		return -1, "no_detail"
	}
	if !proofVerified {
		return -1, "proof_required"
	}
	reason := "chain_mismatch"
	for i, d := range details {
		n64, _ := safeInt(d["chain_len"])
		n := int(n64)
		if len(chainIDs) < n {
			continue
		}
		got, err := PcaGrantChainDigest(chainIDs[:n])
		if err != nil || got != d["chain_digest"] {
			continue
		}
		if loc, has := d["locations"].([]any); has {
			found := false
			for _, u := range loc {
				if u == resource {
					found = true
				}
			}
			if !found {
				reason = "wrong_location"
				continue
			}
		}
		return i, ""
	}
	return -1, reason
}
