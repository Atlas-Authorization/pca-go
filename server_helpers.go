package pca

import (
	"net/http"
)

// Small public helpers of the resource-server guard, under the reference's semantics.

// DecisionOfResult is the ternary decision of a guard result: allow when ok, escalate when the refusal says so, else deny.
func DecisionOfResult(ok bool, decision string) string {
	switch {
	case ok:
		return "allow"
	case decision == "escalate":
		return "escalate"
	}
	return "deny"
}

// PcaStateKey is the store key of a holder's counter stream. scope is "grant-holder" ("<grant>:<holder>") or
// "audience-grant-holder" ("aud:<uri-encoded audience>:<grant>:<holder>"); an empty scope is the 0.5 default: audience-scoped
// whenever an audience is given (non-nil), else grant-holder. StateKey is the narrower grant-holder form.
func PcaStateKey(grantID, leafHolder, scope string, audience *string) string {
	if scope == "" {
		scope = "grant-holder"
		if audience != nil {
			scope = "audience-grant-holder"
		}
	}
	if scope == "audience-grant-holder" {
		aud := ""
		if audience != nil {
			aud = *audience
		}
		return "aud:" + encodeURIComponent(aud) + ":" + grantID + ":" + leafHolder
	}
	return grantID + ":" + leafHolder
}

// UndoAdmissionError is "" when a is a usable admission {id, window_end, compensation: {verb}} (an UndoAdmission or its decoded
// JSON object), else the reason.
func UndoAdmissionError(a any) string {
	var id string
	var windowEnd float64
	var verb string
	switch v := a.(type) {
	case UndoAdmission:
		id, windowEnd, verb = v.ID, float64(v.WindowEnd), v.Compensation.Verb
	case *UndoAdmission:
		if v == nil {
			return "an admission must be an object"
		}
		id, windowEnd, verb = v.ID, float64(v.WindowEnd), v.Compensation.Verb
	case map[string]any:
		s, isStr := v["id"].(string)
		if !isStr || s == "" || jsLen(s) > 128 {
			return "admission id must be a non-empty string of at most 128 characters"
		}
		id = s
		we, ok := jsNum(v["window_end"])
		if !ok || !jsIsInt(v["window_end"]) || we < 0 {
			return "admission window_end must be a non-negative safe integer"
		}
		windowEnd = we
		c, isObj := v["compensation"].(map[string]any)
		verb, _ = c["verb"].(string)
		if !isObj || verb == "" {
			return "admission compensation.verb must be a non-empty string"
		}
		return ""
	default:
		return "an admission must be an object"
	}
	if id == "" || jsLen(id) > 128 {
		return "admission id must be a non-empty string of at most 128 characters"
	}
	if windowEnd < 0 || windowEnd > 9007199254740991 {
		return "admission window_end must be a non-negative safe integer"
	}
	if verb == "" {
		return "admission compensation.verb must be a non-empty string"
	}
	return ""
}

// DefaultEscalationAnswer extracts the principal's escalation answer from a request: the header PCA-Escalation-Answer (strict
// unpadded base64url of JSON), else the JSON body member escalation_answer. body is the request body already read (nil: none).
// nil when absent or unreadable (an unreadable answer is no answer).
func DefaultEscalationAnswer(r *http.Request, body []byte) any {
	return extractEscalationAnswer(r, body, body != nil)
}
