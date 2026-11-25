package pca

// Step-up lifecycle events and signed webhooks (port of the TypeScript @atlasauth/pca-events): build a content-addressed
// step_up.created / approved / denied / expired event, HMAC-SHA256 sign a delivery (`PCA-Signature: t=<unix s>,v1=<hex>`,
// Stripe-style) and verify one, including a replay-guarded delivery check. The id is the hash of the event content, so a
// receiver that dedupes on it also refuses an edited event.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// StepUpEventTypes lists the event types.
var StepUpEventTypes = []string{"step_up.created", "step_up.approved", "step_up.denied", "step_up.expired"}

// MinWebhookSecretBytes is the shortest accepted HMAC secret.
const MinWebhookSecretBytes = 16

const webhookMaxHeader = 2048

// StepUpEvent is one step-up lifecycle event. At is epoch milliseconds; Tier is 2 or 3; Actor nil = absent.
type StepUpEvent struct {
	ID       string
	Type     string
	At       float64
	GrantRef string
	Verb     string
	Resource string
	Tier     int
	Actor    *string
}

func (e StepUpEvent) idBody() map[string]any {
	b := map[string]any{"d": "atlas-pca/stepup-event/v1", "type": e.Type, "at": jsNumber(e.At), "grant_ref": e.GrantRef,
		"action": map[string]any{"verb": e.Verb, "resource": e.Resource}, "tier": jsNumber(float64(e.Tier))}
	if e.Actor != nil {
		b["actor"] = *e.Actor
	}
	return b
}

func isStepUpType(t string) bool {
	for _, x := range StepUpEventTypes {
		if t == x {
			return true
		}
	}
	return false
}

// BuildStepUpEvent fills in the content id (e.ID is ignored). Set At (epoch ms) yourself, e.g. time.Now().UnixMilli().
func BuildStepUpEvent(e StepUpEvent) (StepUpEvent, error) {
	if !isStepUpType(e.Type) || (e.Tier != 2 && e.Tier != 3) {
		return StepUpEvent{}, errors.New("buildStepUpEvent: unknown event type or tier")
	}
	if math.IsNaN(e.At) || math.IsInf(e.At, 0) {
		return StepUpEvent{}, errors.New("buildStepUpEvent: at must be a finite number")
	}
	if !utf8.ValidString(e.GrantRef) { // a lone surrogate has no well-formed UTF-8 form
		return StepUpEvent{}, errors.New("buildStepUpEvent: grant_ref must be a well-formed string")
	}
	if !utf8.ValidString(e.Verb) || !utf8.ValidString(e.Resource) {
		return StepUpEvent{}, errors.New("buildStepUpEvent: action must carry well-formed verb and resource strings")
	}
	if e.Actor != nil && !utf8.ValidString(*e.Actor) {
		return StepUpEvent{}, errors.New("buildStepUpEvent: actor must be a well-formed string")
	}
	id, err := HashCanonical(e.idBody())
	if err != nil {
		return StepUpEvent{}, fmt.Errorf("buildStepUpEvent: %w", err)
	}
	e.ID = id
	return e, nil
}

// JSON is the event as a JSON value.
func (e StepUpEvent) JSON() map[string]any {
	m := map[string]any{"id": e.ID, "type": e.Type, "at": jsNumber(e.At), "grant_ref": e.GrantRef,
		"action": map[string]any{"verb": e.Verb, "resource": e.Resource}, "tier": jsNumber(float64(e.Tier))}
	if e.Actor != nil {
		m["actor"] = *e.Actor
	}
	return m
}

// SerializeEvent is the wire text, members in the reference order (type, at, grant_ref, action, tier, actor?, id).
func SerializeEvent(e StepUpEvent) (string, error) {
	str := func(s string) string { c, _ := canonicalLenient(s); return c }
	if math.IsNaN(e.At) || math.IsInf(e.At, 0) || !utf8.ValidString(e.Type+e.GrantRef+e.Verb+e.Resource+e.ID) {
		return "", errors.New("serializeEvent: not serializable")
	}
	var sb strings.Builder
	sb.WriteString(`{"type":` + str(e.Type) + `,"at":` + jsNumberString(e.At) + `,"grant_ref":` + str(e.GrantRef) +
		`,"action":{"verb":` + str(e.Verb) + `,"resource":` + str(e.Resource) + `},"tier":` + strconv.Itoa(e.Tier))
	if e.Actor != nil {
		if !utf8.ValidString(*e.Actor) {
			return "", errors.New("serializeEvent: not serializable")
		}
		sb.WriteString(`,"actor":` + str(*e.Actor))
	}
	sb.WriteString(`,"id":` + str(e.ID) + "}")
	return sb.String(), nil
}

// ParseEvent parses and checks a delivered event: the shape, and that the id is the hash of the content.
func ParseEvent(s string) (StepUpEvent, error) {
	fail := func(m string) (StepUpEvent, error) { return StepUpEvent{}, errors.New("parseEvent: " + m) }
	// the strict canonical profile: a repeated member, an exponent or a trailing-zero fraction in a number, a lone surrogate, a BOM or
	// any non-JSON whitespace is refused (Go's encoding/json would keep the last duplicate and read 1e3 and 1.0)
	raw, err := StrictParse(s)
	if err != nil {
		return StepUpEvent{}, err
	}
	if !isJSObject(raw) {
		return fail("not an object")
	}
	o, _ := raw.(map[string]any)
	id, ok := o["id"].(string)
	if !ok || id == "" {
		return fail("bad id")
	}
	typ, _ := o["type"].(string)
	if !isStepUpType(typ) {
		return fail("bad type")
	}
	at, ok := jsNum(o["at"])
	if !ok || math.IsNaN(at) || math.IsInf(at, 0) {
		return fail("bad at")
	}
	gr, ok := o["grant_ref"].(string)
	if !ok {
		return fail("bad grant_ref")
	}
	if !isJSObject(o["action"]) {
		return fail("bad action")
	}
	a, _ := o["action"].(map[string]any)
	verb, ok1 := a["verb"].(string)
	res, ok2 := a["resource"].(string)
	if !ok1 || !ok2 {
		return fail("bad action fields")
	}
	tf, ok := jsNum(o["tier"])
	if !ok || (tf != 2 && tf != 3) {
		return fail("bad tier")
	}
	e := StepUpEvent{ID: id, Type: typ, At: at, GrantRef: gr, Verb: verb, Resource: res, Tier: int(tf)}
	if x, has := o["actor"]; has {
		s, ok := x.(string)
		if !ok {
			return fail("bad actor")
		}
		e.Actor = &s
	}
	want, err := HashCanonical(e.idBody())
	if err != nil { // the reference's eventId throws the canonicalizer's own error (an out-of-profile number, a lone surrogate)
		return StepUpEvent{}, err
	}
	if want != id {
		return fail("id does not match the event content")
	}
	return e, nil
}

func webhookKey(secret []byte) ([]byte, bool) { return secret, len(secret) >= MinWebhookSecretBytes }

var webhookT = regexp.MustCompile(`^[0-9]{1,15}$`)

func trimJS(s string) string { return strings.TrimFunc(s, isJSSpace) }

func parseSignatureHeader(h string) (t int64, v1 []string, ok bool) {
	if utf16Len(h) > webhookMaxHeader {
		return 0, nil, false
	}
	have := false
	for _, part := range strings.Split(h, ",") {
		eq := strings.IndexByte(part, '=')
		if eq < 0 {
			continue
		}
		key, val := trimJS(part[:eq]), trimJS(part[eq+1:])
		switch key {
		case "t":
			if !webhookT.MatchString(val) {
				return 0, nil, false
			}
			n, _ := strconv.ParseInt(val, 10, 64)
			if have && n != t {
				return 0, nil, false
			}
			t, have = n, true
		case "v1":
			v1 = append(v1, val)
		}
	}
	if !have || len(v1) == 0 {
		return 0, nil, false
	}
	return t, v1, true
}

func webhookMAC(key []byte, t int64, payload string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(strconv.FormatInt(t, 10) + "." + wtfToUTF8(payload))) // a JS string encodes a lone surrogate as U+FFFD
	return m.Sum(nil)
}

// SignWebhook returns the PCA-Signature header value. timestamp nil = now (unix seconds).
func SignWebhook(secret []byte, payload string, timestamp *int64) (string, error) {
	key, ok := webhookKey(secret)
	if !ok {
		return "", fmt.Errorf("signWebhook: the secret must be at least %d bytes", MinWebhookSecretBytes)
	}
	t := time.Now().Unix()
	if timestamp != nil {
		t = *timestamp
	}
	if t < 0 || t > 1<<53-1 {
		return "", errors.New("signWebhook: timestamp must be a non-negative integer (unix seconds)")
	}
	return "t=" + strconv.FormatInt(t, 10) + ",v1=" + hex.EncodeToString(webhookMAC(key, t, payload)), nil
}

// WebhookVerifyOptions: ToleranceSec nil = 300; Now nil = the current unix time in seconds.
type WebhookVerifyOptions struct {
	ToleranceSec *float64
	Now          *float64
}

func (o WebhookVerifyOptions) values() (tol, now float64) {
	tol, now = 300, float64(time.Now().Unix())
	if o.ToleranceSec != nil {
		tol = *o.ToleranceSec
	}
	if o.Now != nil {
		now = *o.Now
	}
	return
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

// VerifyWebhook checks the header against the payload (constant-time over every v1 candidate) and the timestamp tolerance.
func VerifyWebhook(secret []byte, payload, header string, o WebhookVerifyOptions) bool {
	key, ok := webhookKey(secret)
	if !ok {
		return false
	}
	t, v1, ok := parseSignatureHeader(header)
	if !ok {
		return false
	}
	tol, now := o.values()
	if !finite(tol) || tol < 0 || !finite(now) || math.Abs(now-float64(t)) > tol {
		return false
	}
	want := webhookMAC(key, t, payload)
	match := false
	for _, v := range v1 {
		got, err := hex.DecodeString(v)
		if err != nil {
			continue
		}
		if hmac.Equal(want, got) {
			match = true // no early exit: every candidate costs the same
		}
	}
	return match
}

// DeliveryVerdict is the outcome of VerifyDelivery.
type DeliveryVerdict struct {
	OK     bool
	Event  StepUpEvent
	Reason string
}

// VerifyDelivery verifies a webhook delivery end to end: signature and freshness, the event's content id, and a consume-once
// claim on the event id in the replay store (required) retained past the tolerance window.
func VerifyDelivery(secret []byte, payload, header string, replay OnceStore, o WebhookVerifyOptions) DeliveryVerdict {
	if replay == nil {
		return DeliveryVerdict{Reason: "a replay store is required"}
	}
	if !VerifyWebhook(secret, payload, header, o) {
		return DeliveryVerdict{Reason: "bad signature"}
	}
	e, err := ParseEvent(payload)
	if err != nil {
		return DeliveryVerdict{Reason: err.Error()}
	}
	t, _, _ := parseSignatureHeader(header)
	tol, now := o.values()
	key, err := ReplayKey("pca-stepup-event/v1", e.ID)
	if err != nil {
		return DeliveryVerdict{Reason: "replay store unavailable"}
	}
	first, err := replay.ConsumeOnce(key, int64((float64(t)+tol)*1000+1), int64(now*1000))
	if err != nil {
		return DeliveryVerdict{Reason: "replay store unavailable"}
	}
	if !first {
		return DeliveryVerdict{Reason: "replayed delivery"}
	}
	return DeliveryVerdict{OK: true, Event: e}
}

// WebhookHeaders are the headers of a signed delivery.
func WebhookHeaders(secret []byte, payload string, timestamp *int64) (map[string]string, error) {
	sig, err := SignWebhook(secret, payload, timestamp)
	if err != nil {
		return nil, err
	}
	return map[string]string{"PCA-Signature": sig, "content-type": "application/json"}, nil
}

// ReplayKey is the reference replayKey: namespace + ":" + b64url(sha256(each part length-prefixed, u32 big-endian)).
func ReplayKey(namespace string, parts ...string) (string, error) {
	h := sha256.New()
	for _, p := range append([]string{namespace}, parts...) {
		if !utf8.ValidString(p) {
			return "", errors.New("replayKey: every part must be a well-formed string")
		}
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		h.Write(l[:])
		h.Write([]byte(p))
	}
	return namespace + ":" + b64.EncodeToString(h.Sum(nil)), nil
}

// parseJSONLastWins is JSON.parse for a text with repeated members: the last one wins, the first one's position is kept.
func parseJSONLastWins(s string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data")
	}
	return normalizeJSON(v), nil
}
