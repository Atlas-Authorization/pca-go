package pca

import (
	"errors"
	"sort"
)

// ProvenanceDischargeBody is the discharge an `artifact` verifier signs (SignDischarge) after a passing ProvenanceGate: the request's
// binding and the gate's claims. It errors when the gate did not pass (no discharge without a verified provenance) or when ttlMs
// exceeds what the caveat accepts. request is a decoded pca-discharge-request (see DischargeRequests); iat is epoch milliseconds and
// the discharge lives ttlMs.
func ProvenanceDischargeBody(request map[string]any, gate ProvenanceGateResult, iat, ttlMs int64, nonce string) (DischargeInput, error) {
	if !gate.OK {
		return DischargeInput{}, errors.New("provenanceDischargeBody: the provenance gate refused (" + gate.Code + ")")
	}
	if float64(ttlMs) > jsF(request["ttl_ms"]) {
		return DischargeInput{}, errors.New("provenanceDischargeBody: ttl_ms exceeds what the caveat accepts")
	}
	claims := make(map[string]any, len(gate.Claims))
	for k, v := range gate.Claims {
		claims[k] = v
	}
	d := DischargeInput{CaveatID: evidStr(request["caveat_id"]), IssuerLabel: evidStr(request["issuer"]), CapHash: evidStr(request["cap_hash"]),
		Bind: evidStr(request["bind"]), Claims: claims, Iat: iat, NotAfter: iat + ttlMs, Nonce: nonce}
	if ad, isStr := request["action_digest"].(string); isStr {
		d.ActionDigest = ad
	}
	return d, nil
}

// LowerMedian is the lower median of a non-empty list: the element at index floor((n-1)/2) of the ascending order.
func LowerMedian(xs []float64) (float64, error) {
	if len(xs) == 0 {
		return 0, errors.New("lowerMedian: empty")
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	return s[(len(s)-1)/2], nil
}
