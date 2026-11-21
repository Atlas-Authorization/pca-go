package pca

// x402 (HTTP 402 "Payment Required") for ACP: the v1 challenge, the v2 requirements, headers and negotiation, the v2 HTTP transport
// (PAYMENT-SIGNATURE / PAYMENT-RESPONSE) and the injectable settle flow that gates a settlement on a verified, PCActn-bound payment.
// Values are JSON values (see acp.go); no network is performed.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The x402 constants.
const (
	AcpX402Version1               = 1
	AcpX402Version2               = 2
	AcpX402PaymentRequiredHeader  = "PAYMENT-REQUIRED"
	AcpX402PaymentSignatureHeader = "PAYMENT-SIGNATURE"
	AcpX402PaymentResponseHeader  = "PAYMENT-RESPONSE"
)

// AcpX402SupportedVersions are the versions this implementation speaks, highest first.
var AcpX402SupportedVersions = []int{2, 1}

// AcpX402HTTPStatus maps an x402 outcome to its HTTP status.
var AcpX402HTTPStatus = map[string]int{"payment_required": 402, "malformed": 400, "failed": 402, "internal_error": 500, "settled": 200}

var (
	acpCAIP2  = regexp.MustCompile(`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$`)
	acpAtomic = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	acpBase64 = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
)

func acpHas(m map[string]any, k string) bool {
	v, ok := m[k]
	return ok && v != acpU
}

func acpNonEmpty(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func acpPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// acpDefault is `v ?? d`.
func acpDefault(v, d any) any {
	if acpNullish(v) {
		return d
	}
	return v
}

func acpAbsoluteHTTP(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	u, err := whatwgParse(wellFormedUTF8(s))
	return err == nil && (u.scheme == "http" || u.scheme == "https")
}

// AcpResourceInfoProblems lists the problems with an x402 v2 ResourceInfo (empty = valid).
func AcpResourceInfoProblems(r any) []string {
	m, ok := r.(map[string]any)
	if !ok {
		return []string{"resource must be an object"}
	}
	p := []string{}
	if !acpAbsoluteHTTP(m["url"]) {
		p = append(p, "resource.url must be an absolute http(s) URL")
	}
	for _, k := range []string{"description", "mimeType"} {
		if _, isS := m[k].(string); acpHas(m, k) && !isS {
			p = append(p, "resource."+k+" must be a string")
		}
	}
	if acpHas(m, "serviceName") {
		sn, isS := m["serviceName"].(string)
		if !(isS && jsLen(sn) <= 32 && acpPrintable(sn)) {
			p = append(p, "resource.serviceName must be printable ASCII up to 32 characters")
		}
	}
	if acpHas(m, "tags") {
		tags, isL := m["tags"].([]any)
		good := isL && len(tags) <= 5
		if good {
			for _, t := range tags {
				ts, isS := t.(string)
				if !isS || jsLen(ts) > 32 || !acpPrintable(ts) {
					good = false
					break
				}
			}
		}
		if !good {
			p = append(p, "resource.tags must be up to 5 printable ASCII strings of up to 32 characters")
		}
	}
	if acpHas(m, "iconUrl") {
		icon, isS := m["iconUrl"].(string)
		if !(isS && acpAbsoluteHTTP(icon) && jsLen(icon) <= 2048) {
			p = append(p, "resource.iconUrl must be an absolute http(s) URL up to 2048 characters")
		}
	}
	return p
}

// AcpRequirementV2Problems lists the problems with one v2 PaymentRequirements (empty = valid).
func AcpRequirementV2Problems(q any) []string {
	m, ok := q.(map[string]any)
	if !ok {
		return []string{"requirements must be an object"}
	}
	p := []string{}
	if !acpNonEmpty(m["scheme"]) {
		p = append(p, "scheme is required")
	}
	if n, isS := m["network"].(string); !isS || !acpCAIP2.MatchString(n) {
		p = append(p, "network must be a CAIP-2 identifier")
	}
	if a, isS := m["amount"].(string); !isS || !acpAtomic.MatchString(a) || a == "0" {
		p = append(p, "amount must be a positive decimal string of atomic units")
	}
	if !acpNonEmpty(m["asset"]) {
		p = append(p, "asset is required")
	}
	if !acpNonEmpty(m["payTo"]) {
		p = append(p, "payTo is required")
	}
	if t, isN := jsNum(m["maxTimeoutSeconds"]); !isN || !jsIsSafeInteger(m["maxTimeoutSeconds"]) || t <= 0 {
		p = append(p, "maxTimeoutSeconds must be a positive integer")
	}
	if acpHas(m, "extra") {
		if _, isO := m["extra"].(map[string]any); !isO {
			p = append(p, "extra must be an object")
		}
	}
	return p
}

// AcpPaymentRequiredV2Problems lists the problems with a v2 PaymentRequired (empty = valid).
func AcpPaymentRequiredV2Problems(pr any) []string {
	m, ok := pr.(map[string]any)
	if !ok {
		return []string{"PaymentRequired must be an object"}
	}
	p := []string{}
	if v, isN := jsNum(m["x402Version"]); !isN || v != 2 {
		p = append(p, "x402Version must be 2")
	}
	if _, isS := m["error"].(string); acpHas(m, "error") && !isS {
		p = append(p, "error must be a string")
	}
	p = append(p, AcpResourceInfoProblems(acpGet(m, "resource"))...)
	acc, isL := m["accepts"].([]any)
	if !isL || len(acc) == 0 {
		p = append(p, "accepts must be a non-empty array")
	} else {
		for i, q := range acc {
			for _, msg := range AcpRequirementV2Problems(q) {
				p = append(p, fmt.Sprintf("accepts[%d].%s", i, msg))
			}
		}
	}
	if acpHas(m, "extensions") {
		ex, isO := m["extensions"].(map[string]any)
		if !isO {
			p = append(p, "extensions must be an object")
		} else {
			for _, k := range acpKeys(ex) {
				e, eo := ex[k].(map[string]any)
				_, io := acpGet(e, "info").(map[string]any)
				_, so := acpGet(e, "schema").(map[string]any)
				if !eo || !io || !so {
					p = append(p, "extensions."+k+" needs info and schema objects")
				}
			}
		}
	}
	return p
}

func acpProblemsErr(problems []string) error {
	return errors.New("x402: " + strings.Join(problems, "; "))
}

func acpEncodeHeader(obj any, problems []string) (string, error) {
	if len(problems) > 0 {
		return "", acpProblemsErr(problems)
	}
	return base64.StdEncoding.EncodeToString([]byte(acpStringify(obj))), nil
}

// acpDecodeHeader decodes a header value like Node's Buffer.from(v, 'base64') behind the shape gate, then JSON.parse.
func acpDecodeHeader(value any, name string) (any, error) {
	s, ok := value.(string)
	if !ok || !acpBase64.MatchString(s) {
		return nil, fmt.Errorf("x402: %s is not base64", name)
	}
	doc, err := acpParse(acpUTF8(nodeB64(s)))
	if err != nil {
		return nil, fmt.Errorf("x402: %s is not JSON", name)
	}
	return normalizeJSON(doc), nil
}

// AcpEncodePaymentRequiredHeader encodes a v2 PaymentRequired for the PAYMENT-REQUIRED header (validated first).
func AcpEncodePaymentRequiredHeader(pr any) (string, error) {
	return acpEncodeHeader(pr, AcpPaymentRequiredV2Problems(pr))
}

// AcpDecodePaymentRequiredHeader decodes and validates a PAYMENT-REQUIRED header value.
func AcpDecodePaymentRequiredHeader(value any) (map[string]any, error) {
	doc, err := acpDecodeHeader(value, "PAYMENT-REQUIRED")
	if err != nil {
		return nil, err
	}
	if p := AcpPaymentRequiredV2Problems(doc); len(p) > 0 {
		return nil, acpProblemsErr(p)
	}
	return doc.(map[string]any), nil
}

// AcpX402Challenge is the x402 v1 HTTP 402 challenge for a protected resource. opts: amount (positive integer atomic units),
// currency (the x402 asset), payTo, network, description, scheme, mimeType, error, maxTimeoutSeconds. It refuses anything the v1
// wire would make invalid.
func AcpX402Challenge(resource any, opts any) (map[string]any, error) {
	if acpNullish(opts) {
		return nil, errors.New("Cannot read properties of null (reading 'amount')")
	}
	amount := acpGet(opts, "amount")
	if !acpIsAmount(amount) {
		return nil, errors.New("x402Challenge: amount must be a positive integer in atomic/minor units")
	}
	payTo, currency := acpGet(opts, "payTo"), acpGet(opts, "currency")
	if !acpNonEmpty(payTo) {
		return nil, errors.New("x402Challenge: payTo is required")
	}
	if !acpNonEmpty(currency) {
		return nil, errors.New("x402Challenge: currency (the x402 asset) is required")
	}
	timeout := acpDefault(acpGet(opts, "maxTimeoutSeconds"), json.Number("60"))
	if tf, isN := jsNum(timeout); !isN || !jsIsSafeInteger(timeout) || tf <= 0 {
		return nil, errors.New("x402Challenge: maxTimeoutSeconds must be a positive integer")
	}
	requirement := map[string]any{
		"maxTimeoutSeconds": timeout,
		"scheme":            acpDefault(acpGet(opts, "scheme"), "exact"),
		"network":           acpDefault(acpGet(opts, "network"), "base-sepolia"),
		"maxAmountRequired": acpS(amount),
		"resource":          resource,
		"description":       acpDefault(acpGet(opts, "description"), "Payment required for "+acpS(resource)),
		"payTo":             payTo,
		"asset":             currency,
		"mimeType":          acpDefault(acpGet(opts, "mimeType"), "application/json"),
	}
	return map[string]any{
		"status":  402,
		"headers": map[string]any{"Content-Type": "application/json"},
		"body": map[string]any{
			"x402Version": 1,
			"error":       acpDefault(acpGet(opts, "error"), "X-PAYMENT header is required"),
			"accepts":     []any{requirement},
		},
	}, nil
}

// AcpX402ChallengeV2 is the v2 402 challenge: the JSON body plus the base64 PAYMENT-REQUIRED header. resource is a URL string or a
// ResourceInfo object. opts: amount (positive integer atomic units), asset, payTo, network, scheme, maxTimeoutSeconds, extra, error,
// extensions. It refuses anything the v2 spec makes invalid.
func AcpX402ChallengeV2(resource any, opts any) (map[string]any, error) {
	if acpNullish(opts) {
		return nil, errors.New("Cannot read properties of null (reading 'amount')")
	}
	amount := acpGet(opts, "amount")
	if af, isN := jsNum(amount); !isN || !jsIsSafeInteger(amount) || af <= 0 {
		return nil, errors.New("x402Challenge: amount must be a positive integer in atomic units")
	}
	var info map[string]any
	if s, isS := resource.(string); isS {
		info = map[string]any{"url": s}
	} else {
		info = acpSpread(resource)
	}
	req := map[string]any{"amount": acpS(amount)}
	for _, e := range []struct {
		k string
		v any
	}{
		{"scheme", acpDefault(acpGet(opts, "scheme"), "exact")}, {"network", acpGet(opts, "network")}, {"asset", acpGet(opts, "asset")},
		{"payTo", acpGet(opts, "payTo")}, {"maxTimeoutSeconds", acpDefault(acpGet(opts, "maxTimeoutSeconds"), json.Number("60"))},
		{"extra", acpGet(opts, "extra")},
	} {
		if e.v != acpU {
			req[e.k] = e.v
		}
	}
	body := map[string]any{"x402Version": 2, "error": acpDefault(acpGet(opts, "error"), "PAYMENT-SIGNATURE header is required"),
		"resource": info, "accepts": []any{req}}
	if v := acpGet(opts, "extensions"); v != acpU {
		body["extensions"] = v
	}
	header, err := AcpEncodePaymentRequiredHeader(body)
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": 402, "headers": map[string]any{"Content-Type": "application/json", AcpX402PaymentRequiredHeader: header}, "body": body}, nil
}

// AcpX402Negotiate returns the highest x402 version both sides speak, or ok false (answer 402 v1 with an error, never guess).
// offered is what the client says it speaks (nil or empty means [1]); supported nil means AcpX402SupportedVersions.
func AcpX402Negotiate(offered, supported []float64) (version int, ok bool) {
	if supported == nil {
		supported = []float64{2, 1}
	}
	theirs := offered
	if len(theirs) == 0 {
		theirs = []float64{1}
	}
	for _, v := range []float64{2, 1} {
		var mine bool
		for _, s := range supported {
			mine = mine || s == v
		}
		if !mine {
			continue
		}
		for _, t := range theirs {
			if t == v {
				return int(v), true
			}
		}
	}
	return 0, false
}

func acpStable(v any) string {
	switch t := v.(type) {
	case []any:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = acpStable(x)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]any:
		ks := make([]string, 0, len(t))
		for k := range t {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool { return compareUnits(utf16Units(ks[i]), utf16Units(ks[j])) < 0 })
		parts := make([]string, len(ks))
		for i, k := range ks {
			parts[i] = acpStringify(k) + ":" + acpStable(t[k])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return acpStringify(v)
}

// AcpX402AcceptedMatches reports whether accepted (echoed by the client in its v2 payload) is exactly one of the requirements the
// server offered (member order does not matter).
func AcpX402AcceptedMatches(offered, accepted any) (bool, error) {
	if len(AcpRequirementV2Problems(accepted)) > 0 {
		return false, nil
	}
	l, ok := offered.([]any)
	if !ok {
		return false, errors.New("offered.some is not a function")
	}
	a := acpStable(accepted)
	for _, o := range l {
		if acpStable(o) == a {
			return true, nil
		}
	}
	return false, nil
}

// AcpNormalizeX402Payload reads a client payload of either version: {ok, version, token, merchant?, amount?, accepted?} or
// {ok: false, reason}. v1: the token, merchant and amount are top-level members. v2: the token is payload.token and the echoed
// accepted must be a valid v2 requirement (the merchant is never read from a v2 payload, the amount only from accepted.amount).
func AcpNormalizeX402Payload(raw any) map[string]any {
	m, ok := raw.(map[string]any)
	if !ok {
		return map[string]any{"ok": false, "reason": "x402 payment payload is not an object"}
	}
	ver := acpGet(m, "x402Version")
	if f, isN := jsNum(ver); isN && f == 2 {
		inner, _ := m["payload"].(map[string]any)
		tok, isS := inner["token"].(string)
		if inner == nil || !isS || tok == "" {
			return map[string]any{"ok": false, "reason": "x402 v2 payload is missing payload.token"}
		}
		if problems := AcpRequirementV2Problems(m["accepted"]); len(problems) > 0 {
			return map[string]any{"ok": false, "reason": "x402 v2 payload.accepted is invalid: " + strings.Join(problems, "; ")}
		}
		accepted, _ := m["accepted"].(map[string]any)
		out := map[string]any{"ok": true, "version": 2, "token": tok, "accepted": accepted}
		if af := acpToNumber(accepted["amount"]); jsIsSafeInteger(jsNumber(af)) {
			out["amount"] = jsNumber(af)
		}
		return out
	}
	if ver != acpU {
		if f, isN := jsNum(ver); !isN || f != 1 {
			return map[string]any{"ok": false, "reason": "unsupported x402Version " + acpS(ver)}
		}
	}
	tok, isS := m["token"].(string)
	if !isS {
		return map[string]any{"ok": false, "reason": "x402 payment payload is missing a token"}
	}
	out := map[string]any{"ok": true, "version": 1, "token": tok}
	if mer, isM := m["merchant"].(string); isM {
		out["merchant"] = mer
	}
	if _, isN := jsNum(m["amount"]); isN {
		out["amount"] = m["amount"]
	}
	return out
}

// AcpX402Verify verifies an x402 payment payload; the result is {ok, reason?, claims?}.
type AcpX402Verify func(payload any) (map[string]any, error)

// AcpX402Settler is the optional settlement step run once a payment verified (for example a facilitator call). A nil receipt
// means none.
type AcpX402Settler func(payload any, claims any) (any, error)

// AcpX402Settle gates an x402 settlement on a verified, PCActn-bound payment: it runs verify over the client's payload and REFUSES
// with a fresh 402 on failure (fail closed); on success it optionally runs settle and returns its receipt. A verify or settle error
// is returned as is (nothing is settled).
func AcpX402Settle(payload any, verify AcpX402Verify, settle AcpX402Settler) (map[string]any, error) {
	norm := AcpNormalizeX402Payload(payload)
	if norm["ok"] != true {
		return map[string]any{"settled": false, "status": 402, "reason": norm["reason"]}, nil
	}
	v, err := verify(payload)
	if err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errors.New("Cannot read properties of undefined (reading 'ok')")
	}
	if !acpTruthy(v["ok"]) {
		out := map[string]any{"settled": false, "status": 402, "reason": acpDefault(v["reason"], "payment verification failed")}
		if acpTruthy(v["claims"]) {
			out["claims"] = v["claims"]
		}
		return out, nil
	}
	if _, has := v["claims"]; !has {
		return map[string]any{"settled": false, "status": 402, "reason": "verifier admitted the payment but returned no claims (fail closed)"}, nil
	}
	out := map[string]any{"settled": true, "status": 200, "claims": v["claims"]}
	if settle != nil {
		receipt, err := settle(payload, v["claims"])
		if err != nil {
			return nil, err
		}
		if receipt != nil {
			out["receipt"] = receipt
		}
	}
	return out, nil
}

// AcpX402Verifier adapts AcpVerifyDelegatedPaymentToken into the verify step of AcpX402Settle: it reads the token from the payload
// of either version and verifies its binding and bound proof. Strict by default: expectedMerchant and amount must come from the
// server (the payload's own are never read) and a singleUse store and expectedCurrency are required. opts: verifyKey, alg, now,
// expectedMerchant, offered (v2: the requirements this server offered), amount, expectedSession, expectedCurrency, pcActn, grant,
// audience, authorizedPlanRoots, insecureSkipPlanRootCheck, singleUse, strict.
func AcpX402Verifier(opts map[string]any) AcpX402Verify {
	return func(payload any) (map[string]any, error) {
		if opts == nil {
			return nil, errors.New("Cannot read properties of null (reading 'offered')")
		}
		norm := AcpNormalizeX402Payload(payload)
		if norm["ok"] != true {
			return map[string]any{"ok": false, "reason": norm["reason"]}, nil
		}
		if offered := acpGet(opts, "offered"); norm["version"] == 2 && offered != acpU {
			match, err := AcpX402AcceptedMatches(offered, norm["accepted"])
			if err != nil {
				return nil, err
			}
			if !match {
				return map[string]any{"ok": false, "reason": "x402 v2 payload.accepted is not one of the requirements this server offered"}, nil
			}
		}
		em, amt := acpGet(opts, "expectedMerchant"), acpGet(opts, "amount")
		if v, isB := opts["strict"].(bool); (!isB || v) && (em == acpU || amt == acpU) {
			return map[string]any{"ok": false, "reason": "strict settlement requires the server to supply expectedMerchant and amount (fail closed)"}, nil
		}
		merchant, isS := acpDefault(em, norm["merchant"]).(string)
		if !isS || merchant == "" {
			return map[string]any{"ok": false, "reason": "x402 payload has no merchant to check the token against"}, nil
		}
		amount := acpDefault(amt, norm["amount"])
		if !acpIsAmount(amount) {
			return map[string]any{"ok": false, "reason": "x402 payload has no amount to check the token against"}, nil
		}
		o2 := map[string]any{"expectedMerchant": merchant, "amount": amount, "verifyKey": opts["verifyKey"]}
		for _, k := range []string{"alg", "now", "expectedSession", "expectedCurrency", "pcActn", "grant", "audience", "authorizedPlanRoots",
			"insecureSkipPlanRootCheck", "singleUse", "strict"} {
			if v := acpGet(opts, k); v != acpU {
				o2[k] = v
			}
		}
		res, err := AcpVerifyDelegatedPaymentToken(norm["token"], o2)
		if err != nil {
			return nil, err
		}
		out := map[string]any{"ok": res["ok"]}
		if res["reason"] != nil {
			out["reason"] = res["reason"]
		}
		if acpTruthy(res["claims"]) {
			out["claims"] = res["claims"]
		}
		return out, nil
	}
}

// ---- x402 v2 HTTP transport -------------------------------------------------------------------------------------------

// AcpPaymentPayloadV2Problems lists the problems with a v2 PaymentPayload (empty = valid).
func AcpPaymentPayloadV2Problems(p any) []string {
	m, ok := p.(map[string]any)
	if !ok {
		return []string{"PaymentPayload must be an object"}
	}
	out := []string{}
	if v, isN := jsNum(m["x402Version"]); !isN || v != 2 {
		out = append(out, "x402Version must be 2")
	}
	if acpHas(m, "resource") {
		out = append(out, AcpResourceInfoProblems(m["resource"])...)
	}
	for _, msg := range AcpRequirementV2Problems(acpGet(m, "accepted")) {
		out = append(out, "accepted."+msg)
	}
	if _, isO := m["payload"].(map[string]any); !isO {
		out = append(out, "payload must be an object")
	}
	if _, isO := m["extensions"].(map[string]any); acpHas(m, "extensions") && !isO {
		out = append(out, "extensions must be an object")
	}
	return out
}

// AcpSettlementResponseProblems lists the problems with a SettlementResponse (empty = valid). A success must not carry an
// errorReason; a failure must.
func AcpSettlementResponseProblems(r any) []string {
	m, ok := r.(map[string]any)
	if !ok {
		return []string{"SettlementResponse must be an object"}
	}
	out := []string{}
	success, isBool := m["success"].(bool)
	if !isBool {
		out = append(out, "success must be a boolean")
	}
	tx, isS := m["transaction"].(string)
	if !isS {
		out = append(out, "transaction must be a string")
	} else if isBool && success && tx == "" {
		out = append(out, "a successful settlement needs a transaction")
	}
	if n, nIsS := m["network"].(string); !nIsS || !acpCAIP2.MatchString(n) {
		out = append(out, "network must be a CAIP-2 identifier")
	}
	er, erIsS := m["errorReason"].(string)
	if acpHas(m, "errorReason") && !erIsS {
		out = append(out, "errorReason must be a string")
	}
	if isBool && success && acpHas(m, "errorReason") {
		out = append(out, "errorReason must be omitted on success")
	}
	if isBool && !success && (!erIsS || er == "") {
		out = append(out, "errorReason is required on failure")
	}
	if _, pIsS := m["payer"].(string); acpHas(m, "payer") && !pIsS {
		out = append(out, "payer must be a string")
	}
	if acpHas(m, "amount") {
		if a, aIsS := m["amount"].(string); !aIsS || !acpAtomic.MatchString(a) {
			out = append(out, "amount must be a decimal string of atomic units")
		}
	}
	if _, eIsO := m["extensions"].(map[string]any); acpHas(m, "extensions") && !eIsO {
		out = append(out, "extensions must be an object")
	}
	return out
}

// AcpEncodePaymentSignatureHeader encodes a v2 PaymentPayload for the PAYMENT-SIGNATURE request header (validated first).
func AcpEncodePaymentSignatureHeader(p any) (string, error) {
	return acpEncodeHeader(p, AcpPaymentPayloadV2Problems(p))
}

// AcpDecodePaymentSignatureHeader decodes and validates a PAYMENT-SIGNATURE header value.
func AcpDecodePaymentSignatureHeader(value any) (map[string]any, error) {
	doc, err := acpDecodeHeader(value, "PAYMENT-SIGNATURE")
	if err != nil {
		return nil, err
	}
	if p := AcpPaymentPayloadV2Problems(doc); len(p) > 0 {
		return nil, acpProblemsErr(p)
	}
	return doc.(map[string]any), nil
}

// AcpEncodePaymentResponseHeader encodes a SettlementResponse for the PAYMENT-RESPONSE response header (validated first).
func AcpEncodePaymentResponseHeader(r any) (string, error) {
	return acpEncodeHeader(r, AcpSettlementResponseProblems(r))
}

// AcpDecodePaymentResponseHeader decodes and validates a PAYMENT-RESPONSE header value.
func AcpDecodePaymentResponseHeader(value any) (map[string]any, error) {
	doc, err := acpDecodeHeader(value, "PAYMENT-RESPONSE")
	if err != nil {
		return nil, err
	}
	if p := AcpSettlementResponseProblems(doc); len(p) > 0 {
		return nil, acpProblemsErr(p)
	}
	return doc.(map[string]any), nil
}

// AcpReadPaymentSignature is the server side: it reads the client's PAYMENT-SIGNATURE header (name case-insensitive, the first value
// of a list). A missing header is 402 (answer with a PAYMENT-REQUIRED challenge); a present but undecodable or invalid one is 400.
// Never errors. Several keys that differ only by case and carry different values are refused as malformed (a Go map has no member
// order to pick the first one by).
func AcpReadPaymentSignature(headers any) map[string]any {
	hm, _ := headers.(map[string]any)
	var found []string
	for k := range hm {
		if acpLower(k) == strings.ToLower(AcpX402PaymentSignatureHeader) {
			found = append(found, k)
		}
	}
	sort.Strings(found)
	var v any = acpU
	for i, k := range found {
		cur := hm[k]
		if l, isL := cur.([]any); isL {
			cur = any(acpU)
			if len(l) > 0 {
				cur = l[0]
			}
		}
		if i > 0 && acpStable(cur) != acpStable(v) {
			return map[string]any{"ok": false, "status": AcpX402HTTPStatus["malformed"], "reason": "x402: PAYMENT-SIGNATURE is given more than once"}
		}
		v = cur
	}
	if v == acpU || v == "" {
		return map[string]any{"ok": false, "status": AcpX402HTTPStatus["payment_required"], "reason": "PAYMENT-SIGNATURE header is required"}
	}
	doc, err := AcpDecodePaymentSignatureHeader(v)
	if err != nil {
		return map[string]any{"ok": false, "status": AcpX402HTTPStatus["malformed"], "reason": err.Error()}
	}
	return map[string]any{"ok": true, "payload": doc}
}

// AcpX402SettlementResponse is the server side: the status and PAYMENT-RESPONSE header for a settlement outcome. A success
// ({settled, transaction, payer?, amount?}) is 200 and needs the transaction; a failure ({settled: false, reason, transaction?,
// payer?}) is 402 with success false, the reason and an empty transaction unless one was broadcast. It refuses a response that would
// be invalid.
func AcpX402SettlementResponse(outcome, network any) (map[string]any, error) {
	if acpNullish(outcome) {
		return nil, errors.New("Cannot read properties of null (reading 'settled')")
	}
	om, _ := outcome.(map[string]any)
	body := map[string]any{}
	settled := acpTruthy(acpGet(outcome, "settled"))
	if settled {
		body["success"] = true
		if v := acpGet(outcome, "transaction"); v != acpU {
			body["transaction"] = v
		}
		for _, k := range []string{"payer", "amount"} {
			if acpHas(om, k) {
				body[k] = om[k]
			}
		}
	} else {
		body["success"] = false
		if v := acpGet(outcome, "reason"); v != acpU {
			body["errorReason"] = v
		}
		body["transaction"] = acpDefault(acpGet(outcome, "transaction"), "")
		if acpHas(om, "payer") {
			body["payer"] = om["payer"]
		}
	}
	if network != acpU {
		body["network"] = network
	}
	status := AcpX402HTTPStatus["failed"]
	if settled {
		status = AcpX402HTTPStatus["settled"]
	}
	header, err := AcpEncodePaymentResponseHeader(body)
	if err != nil {
		return nil, err
	}
	return map[string]any{"status": status, "headers": map[string]any{AcpX402PaymentResponseHeader: header}}, nil
}

// AcpX402PaymentSignatureHeaders is the client side: the request header to attach on the retry, from a payload built for an offered
// requirement.
func AcpX402PaymentSignatureHeaders(p any) (map[string]any, error) {
	h, err := AcpEncodePaymentSignatureHeader(p)
	if err != nil {
		return nil, err
	}
	return map[string]any{AcpX402PaymentSignatureHeader: h}, nil
}
