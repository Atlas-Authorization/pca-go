package pca

// Question delivery over the approval-channel transports (a webhook through an injected fetch, and email / sms / push through an
// injected sender) and the verifier side of the site-signed pca-intent-required body. A delivery only tells the principal's device
// that a question is waiting and hands it the SIGNED question: never a rendered card, agent text, the map or p. Text surfaces use
// one fixed template. With no fetch configured a webhook delivery reports "no fetch available" instead of touching the network.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var walletIRSigMembers = []string{"alg", "kid", "value", "pq_value"}

// walletIRShapeError is the shape check of a SIGNED pca-intent-required v1 body ("" when well formed).
func walletIRShapeError(bv any) string {
	b, ok := bv.(map[string]any)
	if !ok {
		return "not an object"
	}
	for _, k := range sortedKeysStd(b) {
		if !intentRequiredKeys[k] {
			return "unknown member '" + k + "'"
		}
	}
	if v, ok := jsSafeInt(b["v"]); !ok || v != 1 || b["kind"] != "pca-intent-required" {
		return "not a pca-intent-required v1"
	}
	for _, k := range []string{"session", "map_digest", "schema", "pcactn_digest", "action_digest"} {
		if !b64uOK(b[k], 32) {
			return k + " must be canonical base64url (32 bytes)"
		}
	}
	cell, ok := b["cell"].(map[string]any)
	verb, _ := cell["verb"].(string)
	_, hasCoords := cell["coords"]
	if !ok || len(cell) != 2 || !hasCoords || verb == "" {
		return "cell must be {verb, coords}"
	}
	if e := cellCoordsError(cell["coords"]); e != "" {
		return e
	}
	if b["reason"] != "uncertain" {
		return "reason must be 'uncertain'"
	}
	if q, ok := b["question_id"].(string); !ok || !questionIDRe.MatchString(q) {
		return "question_id must match [A-Za-z0-9_-]{1,64}"
	}
	if f, _ := b["friction"].(string); f != "tap" && f != "hold" && f != "typed" && f != "device" {
		return "unknown friction tier"
	}
	if b["delivered_to"] != "wallet" && b["delivered_to"] != "agent" {
		return "delivered_to must be 'wallet' or 'agent'"
	}
	if e, ok := jsSafeInt(b["expires_at"]); !ok || e < 0 {
		return "expires_at must be a non-negative safe integer"
	}
	s, hasSig := b["sig"]
	if sm, isMap := s.(map[string]any); isMap {
		alg, algP := sm["alg"]
		if se := suiteCapability(alg, algP); se != "" {
			return "sig.alg: " + se
		}
		if pv, has := sm["pq_value"]; has {
			if _, isS := pv.(string); !isS {
				return "sig.pq_value must be a string"
			}
		}
	}
	sm, isMap := s.(map[string]any)
	bad := !hasSig || !isMap
	if isMap {
		for k := range sm {
			if walletIndexOf(walletIRSigMembers, k) < 0 {
				bad = true
			}
		}
		alg, algP := sm["alg"]
		if !suiteSupported(alg, algP) {
			bad = true
		}
		if _, isS := sm["kid"].(string); !isS {
			bad = true
		}
		if _, isS := sm["value"].(string); !isS {
			bad = true
		}
	}
	if bad {
		return "sig must be {alg, kid, value, pq_value?}"
	}
	return ""
}

// WalletVerifyIntentRequired verifies a site-signed body against the site's discovery keys (the action schema's key list): the
// shape, the signature under the pinned key suite and the expiry. The clock is required: a now that is not a safe integer is
// refused, never coerced, so expiry can never be skipped. The result is {ok: true} or {ok: false, reason}.
func WalletVerifyIntentRequired(bv any, keys any, now any) map[string]any {
	no := func(r string) map[string]any { return map[string]any{"ok": false, "reason": r} }
	if !jsIsSafeInteger(now) {
		return no("the verifier clock is not a safe integer (fail closed)")
	}
	if e := walletIRShapeError(bv); e != "" {
		return no(e)
	}
	b := bv.(map[string]any)
	list, ok := keys.([]any)
	if !ok {
		return no("the site keys must be an array")
	}
	sig := b["sig"].(map[string]any)
	kid := sig["kid"]
	var key map[string]any
	for _, k := range list {
		if km, isMap := k.(map[string]any); isMap && jsStrictEq(km["kid"], kid) {
			key = km
			break
		}
	}
	if key == nil {
		return no(fmt.Sprintf("no site key with kid '%s'", jsValueString(kid)))
	}
	keyAlg, keyAlgP := key["alg"]
	if se := suiteCapability(keyAlg, keyAlgP); se != "" {
		return no("site key: " + se)
	}
	sigAlg, sigAlgP := sig["alg"]
	if suiteAlgName(keyAlg, keyAlgP) != suiteAlgName(sigAlg, sigAlgP) {
		return no("sig.alg does not match the pinned key suite")
	}
	suite := suiteAlgName(keyAlg, keyAlgP)
	msg, err := walletDomainMessage(intentRequiredDomain, withoutKeys(b, "sig"))
	if err != nil {
		return no("malformed intent_required: " + err.Error())
	}
	pk, pkIsStr := key["pk"].(string)
	var pins map[string]string
	if pqpk, has := key["pq_pk"]; has && pkIsStr {
		s, _ := pqpk.(string)
		pins = map[string]string{pk: s}
	}
	if !pkIsStr || !verifyPinnedSuite(suite, true, pk, key["pq_pk"], msg, sig["value"], sig["pq_value"], pins) {
		return no("site signature invalid")
	}
	if !(jsF(now) <= jsF(b["expires_at"])) {
		return no("the question has expired")
	}
	return map[string]any{"ok": true}
}

// ---- notices ---------------------------------------------------------------------------------------------------------------------

// WalletSiteQuestionNotice is the notice for a site-signed question. It errors when the signature or expiry does not verify
// (nothing unsigned leaves). site is the verified origin; inboxURL "" leaves the link out.
func WalletSiteQuestionNotice(ir any, keys any, site any, now any, inboxURL string) (map[string]any, error) {
	v := WalletVerifyIntentRequired(ir, keys, now)
	if v["ok"] != true {
		return nil, fmt.Errorf("siteQuestionNotice: %v", v["reason"])
	}
	m := ir.(map[string]any)
	out := map[string]any{"type": "pca.intent.question", "session": m["session"], "question_id": m["question_id"], "site": site,
		"friction": m["friction"], "expires_at": m["expires_at"], "intent_required": ir}
	if inboxURL != "" {
		out["inbox_url"] = inboxURL
	}
	return out, nil
}

// WalletClarificationNotice is the notice for a wallet-originated question (a clarification): ids only.
func WalletClarificationNotice(session, questionID, inboxURL string) map[string]any {
	out := map[string]any{"type": "pca.intent.clarification", "session": session, "question_id": questionID}
	if inboxURL != "" {
		out["inbox_url"] = inboxURL
	}
	return out
}

func walletEncodeURIComponent(s string) (string, error) {
	if hasLoneSurrogate(s) {
		return "", errors.New("URI malformed")
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			sb.WriteByte(c)
		} else {
			fmt.Fprintf(&sb, "%%%02X", c)
		}
	}
	return sb.String(), nil
}

// WalletQuestionText is the fixed text of a text-surface notice: {subject, text}.
func WalletQuestionText(notice map[string]any, siteName any) (map[string]string, error) {
	isQ := notice["type"] == "pca.intent.question"
	who := "Your agent"
	if isQ {
		t, err := WalletCleanText(siteName, 64)
		if err != nil {
			return nil, err
		}
		who = t
		if who == "" {
			who = "A site"
		}
	}
	subject := who + " needs a decision about your request"
	if isQ {
		subject = who + " has a question about your request"
	}
	last := "Open your wallet to answer."
	if inbox, ok := notice["inbox_url"].(string); ok && inbox != "" {
		qid, _ := notice["question_id"].(string)
		enc, err := walletEncodeURIComponent(qid)
		if err != nil {
			return nil, err
		}
		sep := "?"
		if strings.Contains(inbox, "?") {
			sep = "&"
		}
		last = "Open your wallet to answer: " + inbox + sep + "question=" + enc
	}
	return map[string]string{"subject": subject, "text": strings.Join([]string{subject, "", last}, "\n")}, nil
}

// WalletFetchInit is the request a webhook delivery sends (the body is the notice as JSON text, keys sorted).
type WalletFetchInit struct {
	Method  string
	Headers map[string]string
	Body    string
}

// WalletFetch is the injected webhook transport: it reports whether the response was ok and its status, or a transport error.
type WalletFetch func(url string, init WalletFetchInit) (ok bool, status int, err error)

// WalletTextSender is the injected email / sms / push sender.
type WalletTextSender func(body map[string]string) error

// WalletQuestionChannel is one delivery channel: its kind, whether it is enabled, and Notify.
type WalletQuestionChannel struct {
	Kind    string
	Enabled bool
	Notify  func(notice map[string]any) map[string]any
}

func walletJSONText(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

// WalletQuestionWebhookChannel is webhook delivery (the principal's own wallet push endpoint): the JSON notice, signed question
// included. A nil fetch reports a failed delivery.
func WalletQuestionWebhookChannel(url string, headers map[string]string, fetch WalletFetch) *WalletQuestionChannel {
	enabled := len(url) > 0
	hdr := map[string]string{"content-type": "application/json"}
	for k, v := range headers {
		hdr[k] = v
	}
	return &WalletQuestionChannel{Kind: "webhook", Enabled: enabled, Notify: func(notice map[string]any) map[string]any {
		base := func() map[string]any {
			return map[string]any{"kind": "webhook", "questionId": notice["question_id"], "payload": notice}
		}
		out := base()
		if !enabled {
			out["delivered"], out["reason"] = false, "webhook channel not configured"
			return out
		}
		body, err := walletJSONText(notice)
		if err == nil {
			if fetch == nil {
				err = errors.New("no fetch available: pass a FetchLike transport")
			} else {
				var ok bool
				var status int
				if ok, status, err = fetch(url, WalletFetchInit{Method: "POST", Headers: hdr, Body: body}); err == nil {
					if ok {
						out["delivered"], out["status"] = true, wN(status)
					} else {
						out["delivered"], out["status"], out["reason"] = false, wN(status), fmt.Sprintf("webhook returned %d", status)
					}
					return out
				}
			}
		}
		out["delivered"], out["reason"] = false, err.Error()
		return out
	}}
}

// WalletQuestionTextChannel is email / sms / push delivery through the per-instance sender (fixed text only). A nil send is a
// disabled channel.
func WalletQuestionTextChannel(kind, siteName string, send WalletTextSender) *WalletQuestionChannel {
	enabled := send != nil
	return &WalletQuestionChannel{Kind: kind, Enabled: enabled, Notify: func(notice map[string]any) map[string]any {
		out := map[string]any{"kind": kind, "questionId": notice["question_id"]}
		body, err := WalletQuestionText(notice, siteName)
		if err != nil {
			out["delivered"], out["reason"] = false, err.Error()
			return out
		}
		out["payload"] = map[string]any{"subject": body["subject"], "text": body["text"]}
		if !enabled {
			out["delivered"], out["reason"] = false, kind+" channel not configured"
			return out
		}
		if err := send(body); err != nil {
			out["delivered"], out["reason"] = false, err.Error()
			return out
		}
		out["delivered"] = true
		return out
	}}
}

// WalletQuestionDispatcher fans a notice out to its channels.
type WalletQuestionDispatcher struct{ Channels []*WalletQuestionChannel }

// NewWalletQuestionDispatcher builds a dispatcher over the channels.
func NewWalletQuestionDispatcher(channels []*WalletQuestionChannel) *WalletQuestionDispatcher {
	return &WalletQuestionDispatcher{Channels: channels}
}

// NotifyAll fans a notice out to every enabled channel (disabled channels are skipped).
func (d *WalletQuestionDispatcher) NotifyAll(notice map[string]any) []map[string]any {
	out := []map[string]any{}
	for _, c := range d.Channels {
		if c.Enabled {
			out = append(out, c.Notify(notice))
		}
	}
	return out
}
