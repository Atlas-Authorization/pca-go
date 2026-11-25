package pca

// Detector receipts: what a PINNED detector gateway saw (Lakera Guard, Prompt Security, a home-grown classifier), bound to
// the exact content. Tighten-only by construction: `suspicious` may lower a decision, `no_finding` is exactly no receipt.
// The vendor adapters are one-sided: a response is `no_finding` only when well-formed AND clean; anything malformed or
// ambiguous becomes `suspicious` with category `detector_error`.

import (
	"errors"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	DetectorReceiptDomain    = "atlas-pca/detector-receipt/v1\x00"
	DetectorReceiptRefDomain = "atlas-pca/detector-receipt-ref/v1"
)

// DetectorInputDigest is b64u(sha256(strictCanonical({d: "atlas-pca/detector-input/v1", content}))).
func DetectorInputDigest(content any) (string, error) {
	return HashCanonical(map[string]any{"d": "atlas-pca/detector-input/v1", "content": content})
}

// DetectorReceiptRef is the content address of a receipt (signature included).
func DetectorReceiptRef(r any) (string, error) {
	return HashCanonical(map[string]any{"d": DetectorReceiptRefDomain, "receipt": r})
}

// DetectorReceiptShapeError is "" when the receipt is well-formed.
func DetectorReceiptShapeError(v any) string {
	r, ok := v.(map[string]any)
	if !ok {
		return "receipt must be an object"
	}
	if e := closedMembersMsg(r, "receipt", []string{"v", "kind", "detector", "version", "input_digest", "verdict", "categories", "iat", "sig"},
		"session", "calibration_ref", "alg", "pq_pk", "pq_sig"); e != "" {
		return e
	}
	if v, ok := jsNum(r["v"]); !ok || v != 1 || r["kind"] != "pca-detector-receipt" {
		return "not a pca-detector-receipt v1"
	}
	if d, ok := r["detector"].(string); !ok || !matchName(d) {
		return "detector id is malformed"
	}
	if !boundedStr(r["version"], 64) {
		return "version must be 1..64 bytes"
	}
	if !isDigestV(r["input_digest"]) {
		return "input_digest must be a b64u 32-byte digest"
	}
	verdict := r["verdict"]
	if verdict != "suspicious" && verdict != "no_finding" {
		return "verdict must be 'suspicious' or 'no_finding'"
	}
	c, ok := r["categories"].([]any)
	if !ok || len(c) > 8 {
		return "categories must be 0..8 ids"
	}
	for _, x := range c {
		if s, ok := x.(string); !ok || !matchName(s) {
			return "categories must be 0..8 ids"
		}
	}
	for i := 1; i < len(c); i++ {
		if !(c[i-1].(string) < c[i].(string)) {
			return "categories must be sorted and distinct"
		}
	}
	if verdict == "no_finding" && len(c) > 0 {
		return "a no_finding receipt carries no categories"
	}
	if !(jsIsSafeInteger(r["iat"]) && jsF(r["iat"]) >= 0) {
		return "iat must be a non-negative integer"
	}
	if s, has := r["session"]; has && !isDigestV(s) {
		return "session must be a b64u 32-byte id"
	}
	if s, has := r["calibration_ref"]; has && !boundedStr(s, 256) {
		return "calibration_ref must be 1..256 bytes"
	}
	if _, ok := r["sig"].(string); !ok {
		return "sig must be a string"
	}
	return artifactSuiteError(r)
}

// SignDetectorReceipt signs a receipt body with the gateway key; refuses a malformed result.
func SignDetectorReceipt(body map[string]any, key *KeyPair, suite *SuiteOpts) (map[string]any, error) {
	signed, err := SignArtifact(DetectorReceiptDomain, body, key, suite)
	if err != nil {
		return nil, err
	}
	if e := DetectorReceiptShapeError(signed); e != "" {
		return nil, errors.New("signDetectorReceipt: " + e)
	}
	return signed, nil
}

// DetectorAdapterContext is what the gateway knows about one screening. Session / CalibrationRef nil are absent.
type DetectorAdapterContext struct {
	Detector       string
	Version        string
	Content        any
	Key            *KeyPair
	Now            int64
	Session        *string
	CalibrationRef *string
}

var (
	catNonAlnum  = regexp.MustCompile(`[^a-z0-9]+`)
	catEdgeUnder = regexp.MustCompile(`^_+|_+$`)
)

// jsLower is String.prototype.toLowerCase for the purpose of categoryId: only mappings that land in ASCII matter (every
// other character becomes `_`), and U+0130 lowers to "i" + U+0307 under the Unicode special casing JavaScript applies.
func jsLower(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == 0x130 {
			b.WriteString("i̇")
			continue
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// DetectorCategoryID turns vendor category text into a receipt category id; unusable text becomes "other".
func DetectorCategoryID(v any) string {
	s, ok := v.(string)
	if !ok {
		return "other"
	}
	c := catEdgeUnder.ReplaceAllString(catNonAlnum.ReplaceAllString(jsLower(s), "_"), "")
	if c != "" && c[0] >= '0' && c[0] <= '9' {
		c = "c_" + c
	}
	if len(c) > 64 { // ASCII only at this point
		c = c[:64]
	}
	if !matchName(c) {
		return "other"
	}
	return c
}

func detectorReceipt(ctx DetectorAdapterContext, suspicious bool, cats []string) (map[string]any, error) {
	list := []any{}
	if suspicious {
		d := distinct(cats)
		sort.Strings(d)
		for i, x := range d {
			if i == 8 {
				break
			}
			list = append(list, x)
		}
	}
	dig, err := DetectorInputDigest(ctx.Content)
	if err != nil {
		return nil, err
	}
	verdict := "no_finding"
	if suspicious {
		verdict = "suspicious"
	}
	body := map[string]any{"v": jsNumber(1), "kind": "pca-detector-receipt", "detector": ctx.Detector, "version": ctx.Version,
		"input_digest": dig, "verdict": verdict, "categories": list, "iat": i64Num(ctx.Now)}
	if ctx.Session != nil {
		body["session"] = *ctx.Session
	}
	if ctx.CalibrationRef != nil {
		body["calibration_ref"] = *ctx.CalibrationRef
	}
	return SignDetectorReceipt(body, ctx.Key, nil)
}

func detectorErrorReceipt(ctx DetectorAdapterContext) (map[string]any, error) {
	return detectorReceipt(ctx, true, []string{"detector_error"})
}

// LakeraReceipt maps a Lakera Guard v2 /guard response ({flagged, breakdown?: [{detector_type, detected}]}).
func LakeraReceipt(response any, ctx DetectorAdapterContext) (map[string]any, error) {
	r, ok := response.(map[string]any)
	flagged, ok2 := r["flagged"].(bool)
	if !ok || !ok2 {
		return detectorErrorReceipt(ctx)
	}
	cats := []string{}
	if bd, has := r["breakdown"]; has {
		l, ok := bd.([]any)
		if !ok {
			return detectorErrorReceipt(ctx)
		}
		for _, x := range l {
			b, ok := x.(map[string]any)
			det, ok2 := b["detected"].(bool)
			if !ok || !ok2 {
				return detectorErrorReceipt(ctx)
			}
			if det {
				cats = append(cats, DetectorCategoryID(b["detector_type"]))
			}
		}
	}
	suspicious := flagged || len(cats) > 0
	if suspicious && len(cats) == 0 {
		cats = append(cats, "flagged")
	}
	return detectorReceipt(ctx, suspicious, cats)
}

// PromptSecurityReceipt maps a Prompt Security /api/protect response; both integration shapes are accepted (result.action
// and result.prompt.{action, violations}); clean only when no action is block / modify and no violation is listed.
func PromptSecurityReceipt(response any, ctx DetectorAdapterContext) (map[string]any, error) {
	top, _ := response.(map[string]any)
	r, ok := top["result"].(map[string]any)
	if !ok {
		return detectorErrorReceipt(ctx)
	}
	pv, hasP := r["prompt"]
	p, pObj := pv.(map[string]any)
	if hasP && !pObj {
		return detectorErrorReceipt(ctx)
	}
	var actions []any
	if a, has := r["action"]; has {
		actions = append(actions, a)
	}
	if pObj {
		if a, has := p["action"]; has {
			actions = append(actions, a)
		}
	}
	if len(actions) == 0 {
		return detectorErrorReceipt(ctx)
	}
	for _, a := range actions {
		if _, ok := a.(string); !ok {
			return detectorErrorReceipt(ctx)
		}
	}
	cats := []string{}
	if pObj {
		if vv, has := p["violations"]; has {
			l, ok := vv.([]any)
			if !ok {
				return detectorErrorReceipt(ctx)
			}
			for _, x := range l {
				cats = append(cats, DetectorCategoryID(x))
			}
		}
	}
	for _, a := range actions {
		switch a {
		case "block":
			cats = append(cats, "blocked")
		case "modify":
			cats = append(cats, "modified")
		}
	}
	return detectorReceipt(ctx, len(cats) > 0, cats)
}

// GenericReceipt maps any detector answering {flagged, categories?}; categories on a clean answer are ambiguous.
func GenericReceipt(response any, ctx DetectorAdapterContext) (map[string]any, error) {
	r, ok := response.(map[string]any)
	flagged, ok2 := r["flagged"].(bool)
	if !ok || !ok2 {
		return detectorErrorReceipt(ctx)
	}
	cats := []string{}
	if cv, has := r["categories"]; has {
		l, ok := cv.([]any)
		if !ok {
			return detectorErrorReceipt(ctx)
		}
		for _, x := range l {
			cats = append(cats, DetectorCategoryID(x))
		}
	}
	if !flagged && len(cats) > 0 {
		return detectorErrorReceipt(ctx)
	}
	if flagged && len(cats) == 0 {
		cats = append(cats, "flagged")
	}
	return detectorReceipt(ctx, flagged, cats)
}
