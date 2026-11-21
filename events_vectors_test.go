package pca

// Replays the reference oracle of the step-up events / signed webhooks (testdata/ref-events.json.gz).

import (
	"errors"
	"math"
	"strings"
	"testing"
	"unicode/utf8"
)

// vecSecret is the secret as the reference reads it: bytes, or a string (encoded as UTF-8: a lone surrogate becomes U+FFFD); any
// other value is not a secret (nil, which is shorter than the minimum).
func vecSecret(v any) []byte {
	if b := baseBytes(v); b != nil {
		return b
	}
	if s, ok := v.(string); ok {
		return []byte(wtfToUTF8(s))
	}
	return nil
}

// vecEventCheck is the reference's checkEventFields over a raw value (the typed Go API cannot hold a hostile member).
func vecEventCheck(who string, e any, withID bool) error {
	bad := func(m string) error { return errors.New(who + ": " + m) }
	o, ok := e.(map[string]any)
	if !ok {
		return bad("not an object")
	}
	tier, tok := jsNum(o["tier"])
	if t, isStr := o["type"].(string); !isStr || !isStepUpType(t) || !tok || (tier != 2 && tier != 3) {
		return bad("unknown event type or tier")
	}
	if x, has := o["at"]; has {
		if f, ok := jsNum(x); !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return bad("at must be a finite number")
		}
	}
	wf := func(x any) bool { s, ok := x.(string); return ok && utf8.ValidString(s) }
	if !wf(o["grant_ref"]) {
		return bad("grant_ref must be a well-formed string")
	}
	a, isObj := o["action"].(map[string]any)
	if !isObj || !wf(a["verb"]) || !wf(a["resource"]) {
		return bad("action must carry well-formed verb and resource strings")
	}
	if x, has := o["actor"]; has && !wf(x) {
		return bad("actor must be a well-formed string")
	}
	if withID && !wf(o["id"]) {
		return bad("id must be a well-formed string")
	}
	return nil
}

func vecEventIn(typ any, data any) (StepUpEvent, error) {
	m := vecObj(data)
	merged := map[string]any{}
	for k, x := range m {
		merged[k] = x
	}
	merged["type"] = typ
	if err := vecEventCheck("buildStepUpEvent", merged, false); err != nil {
		return StepUpEvent{}, err
	}
	return vecEventOf(merged), nil
}

func vecEventOf(m map[string]any) StepUpEvent {
	a := vecObj(m["action"])
	at, _ := jsNum(m["at"])
	tier, _ := jsNum(m["tier"])
	t, _ := m["type"].(string)
	e := StepUpEvent{ID: vecStr(m, "id"), Type: t, At: at, GrantRef: vecStr(m, "grant_ref"), Verb: vecStr(a, "verb"), Resource: vecStr(a, "resource"), Tier: int(tier)}
	if s, ok := m["actor"].(string); ok {
		e.Actor = &s
	}
	return e
}

func vecF64Ptr(m map[string]any, k string) *float64 {
	if f, ok := jsNum(m[k]); ok {
		return &f
	}
	if x, has := m[k]; has && x != nil { // `?? default` keeps null / undefined out; any other non-number is not finite
		f := math.NaN()
		return &f
	}
	return nil
}

func vecVerdict(v DeliveryVerdict) map[string]any {
	if v.OK {
		return map[string]any{"ok": true, "event": v.Event.JSON()}
	}
	// the oracle redacts the engine's own texts: a JSON.parse failure is "<json>", a canonicalizer refusal "<canonicalize>"
	reason := v.Reason
	switch {
	case strings.HasPrefix(reason, "parseEvent: not JSON"):
		reason = "<json>"
	case strings.HasPrefix(reason, "canonicalize:"):
		reason = "<canonicalize>"
	}
	return map[string]any{"ok": false, "reason": reason}
}

func TestEventsVectors(t *testing.T) {
	replayVectors(t, "ref-events.json.gz", map[string]vecFn{
		"buildStepUpEvent": func(a []any) (any, error) {
			in, err := vecEventIn(vecArg(a, 0), vecArg(a, 1))
			if err != nil {
				return nil, err
			}
			e, err := BuildStepUpEvent(in)
			return e.JSON(), err
		},
		"serializeEvent": func(a []any) (any, error) {
			if err := vecEventCheck("serializeEvent", vecArg(a, 0), true); err != nil {
				return nil, err
			}
			m := vecObj(vecArg(a, 0))
			if f, ok := jsNum(m["at"]); !ok || math.IsNaN(f) || math.IsInf(f, 0) {
				return nil, errors.New("serializeEvent: at must be a finite number")
			}
			for k := range m { // JSON.stringify keeps the members of the object it is given, unknown ones included, in their own order
				switch k {
				case "type", "at", "grant_ref", "action", "tier", "actor", "id":
				default:
					return vecStringifyRaw(m)
				}
			}
			if a := vecObj(m["action"]); len(a) > 2 {
				return vecStringifyRaw(m)
			}
			return SerializeEvent(vecEventOf(m))
		},
		"minSecretBytes": func([]any) (any, error) { return jsNumber(float64(MinWebhookSecretBytes)), nil },
		"webhookHeaders": func(a []any) (any, error) {
			var ts *int64
			if x, has := vecObj(vecArg(a, 2))["timestamp"]; has {
				n, ok := baseI64(x)
				if !ok {
					return nil, errors.New("timestamp is not an integer")
				}
				ts = &n
			}
			payload, ok := vecArg(a, 1).(string)
			if !ok {
				return nil, errors.New("the payload must be a string")
			}
			return WebhookHeaders(vecSecret(vecArg(a, 0)), payload, ts)
		},
		"deliveryScenario": func(a []any) (any, error) {
			sc := vecObj(vecArg(a, 0))
			var store OnceStore = NewMemoryStateStore()
			switch sc["store"] {
			case "throws":
				store = vecFaultStore{err: errors.New("store down")}
			case "refuses":
				store = vecFaultStore{}
			}
			if sc["noReplay"] == true {
				store = nil
			}
			out := []any{}
			for _, x := range vecList(sc["deliveries"]) {
				d := vecObj(x)
				secret := []byte("whsec_0123456789abcdef0123456789")
				if sv, has := d["secret"]; has {
					secret = vecSecret(sv)
				}
				o := vecObj(d["opts"])
				replay := store
				if _, has := o["replay"]; has || sc["noOpts"] == true {
					replay = nil
				}
				payload, _ := d["payload"].(string)
				header, _ := d["header"].(string)
				out = append(out, vecVerdict(VerifyDelivery(secret, payload, header, replay, WebhookVerifyOptions{ToleranceSec: vecF64Ptr(o, "toleranceSec"), Now: vecF64Ptr(o, "now")})))
			}
			return out, nil
		},
		"parseEvent": func(a []any) (any, error) {
			e, err := ParseEvent(vecStrArg(a, 0))
			return e.JSON(), err
		},
		"signWebhook": func(a []any) (any, error) {
			var ts *int64
			if x, has := vecObj(vecArg(a, 2))["timestamp"]; has {
				n, ok := baseI64(x)
				if !ok {
					return nil, errors.New("timestamp is not an integer")
				}
				ts = &n
			}
			return SignWebhook(vecSecret(a[0]), vecStrArg(a, 1), ts)
		},
		"verifyWebhook": func(a []any) (any, error) {
			m := vecObj(vecArg(a, 3))
			return VerifyWebhook(vecSecret(a[0]), vecStrArg(a, 1), vecStrArg(a, 2), WebhookVerifyOptions{ToleranceSec: vecF64Ptr(m, "toleranceSec"), Now: vecF64Ptr(m, "now")}), nil
		},
	})
}

// A payload that is not JSON: the reference reports the JavaScript SyntaxError text; Go reports its own parse refusal.
func TestEventsDeliveryNotJSON(t *testing.T) {
	ts := int64(1_700_000_000)
	h, _ := SignWebhook([]byte("0123456789abcdef"), "not json", &ts)
	now := float64(ts)
	v := VerifyDelivery([]byte("0123456789abcdef"), "not json", h, NewMemoryStateStore(), WebhookVerifyOptions{Now: &now})
	if v.OK || !strings.HasPrefix(v.Reason, "parseEvent:") {
		t.Fatalf("got %+v", v)
	}
}

// vecFaultStore is a replay store that refuses every claim (err nil: "already seen") or fails with err.
type vecFaultStore struct{ err error }

func (f vecFaultStore) ConsumeOnce(string, int64, int64) (bool, error) { return false, f.err }

func vecList(v any) []any { l, _ := v.([]any); return l }

// vecStringifyRaw is JSON.stringify of a decoded object, members in their own order.
func vecStringifyRaw(m map[string]any) (any, error) {
	var sb strings.Builder
	err := eatStringify(&sb, m)
	return sb.String(), err
}
