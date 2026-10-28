package pca

import (
	"sort"
)

// "Unconfirmed means maximally dangerous": the only thing that lowers an action's effective traits is a valid signed human
// confirmation by a key pinned with the reviewer role. Every failure here is "not confirmed"; nothing throws.

const reviewDomain = "atlas-pca/action-review/v2\x00"

var keyRoles = []string{"reviewer", "importer", "model", "publisher"}

func hasRole(k map[string]any, role string) bool {
	rs, _ := strsOf(k["roles"])
	return contains(rs, role)
}

// reviewerPinsError mirrors the reference: "" iff the pin set is sound (pv is the parsed `{keys, traits_digests?}`).
func reviewerPinsError(pv any) string {
	p, _ := pv.(map[string]any)
	keys, ok := p["keys"].([]any)
	if !ok {
		return "pins must be {keys: [...]}"
	}
	kids, machine := map[string]bool{}, map[string]bool{}
	for _, kv := range keys {
		k, _ := kv.(map[string]any)
		kid, ok := k["kid"].(string)
		if !ok || kid == "" || len(utf16Units(kid)) > 128 {
			return "a pinned key needs a kid"
		}
		if kids[kid] {
			return "kid '" + kid + "' is pinned twice"
		}
		kids[kid] = true
		if !b64uOK(k["pk"], b32) {
			return "key '" + kid + "': pk is not canonical base64url (32 bytes)"
		}
		rs, ok := strsOf(k["roles"])
		if !ok || len(rs) == 0 || len(sortUniqS(rs)) != len(rs) || !subsetS(rs, keyRoles) {
			return "key '" + kid + "': roles must be distinct known roles"
		}
		if contains(rs, "reviewer") && (contains(rs, "importer") || contains(rs, "model")) {
			return "key '" + kid + "': an importer or model key cannot hold the reviewer role"
		}
		for _, t := range []string{"not_before", "not_after"} {
			if x, has := k[t]; has && !(jsIsSafeInteger(x) && jsF(x) >= 0) {
				return "key '" + kid + "': " + t + " must be a non-negative integer"
			}
		}
		if contains(rs, "importer") || contains(rs, "model") {
			machine[k["pk"].(string)] = true
		}
	}
	for _, kv := range keys {
		if k := kv.(map[string]any); hasRole(k, "reviewer") && machine[k["pk"].(string)] {
			return "key '" + k["kid"].(string) + "': the same key material is pinned as an importer or model key"
		}
	}
	return ""
}

// confirmationError: "" iff attestation `av` is a valid review of the def digest `want` against an accepted registry digest,
// whose final traits satisfy finalOK, signed by a pinned reviewer key inside its validity window.
func confirmationError(av any, want string, wantFacts *string, reg Registry, pins any, finalOK func([]string) bool) (res string) {
	defer func() {
		if r := recover(); r != nil {
			res = "malformed confirmation"
		}
	}()
	if pe := reviewerPinsError(pins); pe != "" {
		return "bad pins: " + pe
	}
	a, ok := av.(map[string]any)
	if !ok {
		return "no confirmation"
	}
	sig, ok := a["sig"].(string)
	if !ok {
		return "the confirmation is unsigned"
	}
	if dd, ok := a["def_digest"].(string); !ok || want == "" || dd != want {
		return "the confirmation covers a different def digest"
	}
	pm := pins.(map[string]any)
	accepted, err := traitsDigest(reg)
	if err != nil {
		return "the trait registry has no digest"
	}
	td, _ := a["traits_digest"].(string)
	if extra, _ := strsOf(pm["traits_digests"]); td != accepted && !contains(extra, td) {
		return "the confirmation was made against a different trait registry"
	}
	fd, fdOK := a["facts_digest"].(string)
	if wantFacts != nil && (!fdOK || fd != *wantFacts) {
		return "the verb facts differ from the facts the reviewer confirmed"
	}
	final, fok := strsOf(a["final_traits"])
	dis, dok := a["dismissed"].([]any)
	kid, kok := a["reviewer_kid"].(string)
	if !fok || !dok || !kok || !jsIsSafeInteger(a["ts"]) || !finalOK(final) {
		return "malformed confirmation"
	}
	type dism struct{ trait, reason string }
	ds := make([]dism, 0, len(dis))
	for _, x := range dis {
		m, _ := x.(map[string]any)
		t, tok := m["trait"].(string)
		r, rok := m["reason"].(string)
		if !tok || !rok || contains(final, t) || jsTrim(r) == "" {
			return "a dismissed trait is also final, or has no reason"
		}
		ds = append(ds, dism{t, r})
	}
	var key map[string]any
	for _, kv := range pm["keys"].([]any) {
		if k := kv.(map[string]any); k["kid"] == kid {
			key = k
			break
		}
	}
	if key == nil || !hasRole(key, "reviewer") {
		return "no pinned reviewer key '" + kid + "'"
	}
	ts := jsF(a["ts"])
	if nb, has := key["not_before"]; has && ts < jsF(nb) {
		return "the confirmation time is outside the key validity"
	}
	if na, has := key["not_after"]; has && ts > jsF(na) {
		return "the confirmation time is outside the key validity"
	}
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].trait < ds[j].trait })
	dl := make([]any, len(ds))
	for i, d := range ds {
		dl[i] = map[string]any{"trait": d.trait, "reason": d.reason}
	}
	if !fdOK { // a def-level attestation without facts_digest cannot verify
		return "the confirmation signature is invalid"
	}
	msg, ok := domainMessage(reviewDomain, map[string]any{"def_digest": want, "traits_digest": td, "facts_digest": fd, "final_traits": anyStrs(sortUniqS(final)),
		"dismissed": dl, "reviewer_kid": kid, "ts": a["ts"]})
	if !ok || !verifyB64u(key["pk"].(string), msg, sig) {
		return "the confirmation signature is invalid"
	}
	return ""
}

const verbFactsDomain = "atlas-pca/action-verb-facts/v1"

// factsDigest: digest of what a verb says (the verb minus traits, floors, confirmation and def); the reviewer signs it.
func factsDigest(v map[string]any) (string, error) {
	m := make(map[string]any, len(v))
	for k, x := range v {
		if k != "traits" && k != "floors" && k != "confirmation" && k != "def" {
			m[k] = x
		}
	}
	return HashCanonical(map[string]any{"d": verbFactsDomain, "verb": m})
}

// verbConfirmationError: "" iff the signed schema verb carries a valid confirmation (final traits all carried by the verb).
func verbConfirmationError(v map[string]any, reg Registry, pins any) string {
	if pins == nil {
		return "no reviewer keys are pinned"
	}
	carried, _ := strsOf(v["traits"])
	want, _ := v["def"].(string)
	fd, err := factsDigest(v)
	if err != nil {
		return "malformed confirmation"
	}
	return confirmationError(v["confirmation"], want, &fd, reg, pins, func(f []string) bool { return subsetS(f, carried) })
}

// defConfirmed: the def's review is `confirmed` and its attestation is valid for exactly this def (final traits == declared traits).
func defConfirmed(d map[string]any, reg Registry, pins any) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	rv, _ := d["review"].(map[string]any)
	if pins == nil || rv["state"] != "confirmed" {
		return false
	}
	dg, err := defDigest(d)
	if err != nil {
		return false
	}
	declared, _ := strsOf(d["traits"])
	want := sortUniqS(declared)
	return confirmationError(rv["attestation"], dg, nil, reg, pins, func(f []string) bool {
		g := sortUniqS(f)
		if len(g) != len(want) {
			return false
		}
		for i := range g {
			if g[i] != want[i] {
				return false
			}
		}
		return true
	}) == ""
}

// topTraits is every trait id of the registry: the effective traits of anything unconfirmed.
func topTraits(reg Registry) []string {
	out := make([]string, 0, len(reg))
	for id := range reg {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
