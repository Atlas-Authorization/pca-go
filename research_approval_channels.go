package pca

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// Approval-notification channels for step-ups (the channel layer over the approvals core): each channel FORMATS a human-readable
// notification of a pending step-up request (the action summary, the "because you asked to ..." goal lineage, the canonical render
// with its match words, an approve / deny affordance or an inbox link) and DISPATCHES it over an injected transport.
//
// A channel is gated by its configuration (an unconfigured one reports Enabled() == false and never dispatches), its transport is
// injected (default: net/http), and what it returns never carries the webhook URL, a token or a signing secret. A channel only
// reports a step-up the verifier already produced; it authorizes nothing.
//
// A step-up request is the plain map the approvals core produces ({id, verb, resource, tier, reason, lineage, r, render?, renderDigest?, ...}).

// ApprovalResponse is the part of an HTTP response a channel needs.
type ApprovalResponse struct {
	// OK is true for a 2xx status.
	OK     bool
	Status int
}

// ApprovalFetch is the HTTP surface a channel needs: POST body with headers to url.
type ApprovalFetch func(url string, headers map[string]string, body string) (ApprovalResponse, error)

// ApprovalTextSender delivers a formatted text body and returns a channel-native message id (or ""). A failure is an error.
type ApprovalTextSender func(subject, text string) (string, error)

// NotifyContext is the context of a notification: where the human approves.
type NotifyContext struct {
	// InboxURL is the approval inbox link ("" for none); query parameters are added before any #fragment.
	InboxURL string
	// Now is the notification time in epoch ms (nil: unset).
	Now *int64
}

// ApprovalDelivery is the outcome of one delivery attempt. Payload is the formatted, secret-free message.
type ApprovalDelivery struct {
	Kind      string  `json:"kind"`
	RequestID string  `json:"requestId"`
	Delivered bool    `json:"delivered"`
	Payload   any     `json:"payload"`
	Status    *int    `json:"status,omitempty"`
	Reason    *string `json:"reason,omitempty"`
}

// ApprovalChannel is the common channel contract.
type ApprovalChannel interface {
	// Kind is "slack", "webhook", "email", "push" or "sms".
	Kind() string
	// Enabled is true iff the channel is configured enough to deliver.
	Enabled() bool
	// Notify formats the step-up for this channel and dispatches it. A delivery failure is a not-delivered outcome, not an error; an
	// error is a request that cannot be formatted (no lineage, a malformed render digest).
	Notify(request map[string]any, ctx *NotifyContext) (ApprovalDelivery, error)
}

func approvalStr(request map[string]any, k string) string { return jsMemberString(request, k) }

// DefaultApprovalFetch is the default transport: a JSON POST over net/http with a 10 second timeout.
func DefaultApprovalFetch() ApprovalFetch {
	client := &http.Client{Timeout: 10 * time.Second}
	return func(url string, headers map[string]string, body string) (ApprovalResponse, error) {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
		if err != nil {
			return ApprovalResponse{}, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := client.Do(req)
		if err != nil {
			return ApprovalResponse{}, err
		}
		defer res.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		return ApprovalResponse{OK: res.StatusCode >= 200 && res.StatusCode < 300, Status: res.StatusCode}, nil
	}
}

// ---- human-readable formatting (shared by every channel) -----------------------------------------------------------

// ApprovalActionSummary is the one-line action summary: "verb on resource (tier N, risk R)".
func ApprovalActionSummary(request map[string]any) string {
	risk := "NaN"
	if r, ok := jsNum(request["r"]); ok && !math.IsNaN(r) {
		risk = rsToFixed(r, 2)
	}
	return approvalStr(request, "verb") + " on " + approvalStr(request, "resource") + " (tier " + approvalStr(request, "tier") + ", risk " + risk + ")"
}

// ApprovalLineageLines are the lines a human reads to understand why: the "because" sentence, the goal chain, then the canonical render.
func ApprovalLineageLines(request map[string]any) ([]string, error) {
	lineage, ok := request["lineage"].(map[string]any)
	if !ok {
		return nil, errors.New("lineageLines: the request has no lineage")
	}
	out := []string{jsMemberString(lineage, "because")}
	if cv, has := lineage["chain"]; has && cv != nil {
		if _, isList := cv.([]any); !isList {
			return nil, errors.New("lineage.chain.map is not a function")
		}
	}
	if chain, ok := lineage["chain"].([]any); ok {
		for _, n := range chain {
			if n == nil {
				return nil, errors.New("Cannot read properties of null (reading 'detail')")
			}
			node, _ := n.(map[string]any)
			label := jsMemberString(node, "label")
			if rsTruthy(node["detail"]) {
				label += " — " + jsValueString(node["detail"])
			}
			out = append(out, label)
		}
	}
	rl, err := ApprovalRenderLines(request)
	if err != nil {
		return nil, err
	}
	return append(out, rl...), nil
}

// ApprovalRenderLines are the canonical render, one line per field (nothing omitted), the banner for an unreviewed action and the
// speakable match words of the render digest. Empty when the request carries no render.
func ApprovalRenderLines(request map[string]any) ([]string, error) {
	render, ok := request["render"].(map[string]any)
	if !ok || request["renderDigest"] == nil {
		return []string{}, nil
	}
	out := []string{}
	if render["unreviewed"] == true {
		out = append(out, "UNREVIEWED ACTION: its definition has not been confirmed, so every value is shown raw and one-tap approval is disabled.")
	}
	if fields, ok := render["fields"].([]any); ok {
		for _, fo := range fields {
			f, _ := fo.(map[string]any)
			unit, _ := f["unit"].(map[string]any)
			u := ""
			if unit["kind"] == "money" {
				u = " " + jsMemberString(unit, "ccy") + " (minor units, exponent " + jsMemberString(unit, "exp") + ")"
			}
			out = append(out, jsMemberString(f, "id")+" ["+jsMemberString(f, "class")+"]: "+approvalEscapeControl(approvalJSStringify(f["value"]))+u)
		}
	}
	digest, _ := request["renderDigest"].(string)
	words, err := BindingWords(digest)
	if err != nil {
		return nil, err
	}
	return append(out, "Match code: "+words), nil
}

// approvalEscapeControl replaces control and format characters and U+2028/2029 with \u{hex}, as the reference prints a value.
func approvalEscapeControl(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r == 0x2028 || r == 0x2029 {
			fmt.Fprintf(&sb, "\\u{%x}", r)
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// approvalEncodeURIComponent is encodeURIComponent: everything but A-Za-z0-9 - _ . ! ~ * ' ( ) is percent-encoded.
func approvalEncodeURIComponent(s string) string {
	var sb strings.Builder
	for _, b := range []byte(s) {
		switch {
		case b >= 'A' && b <= 'Z', b >= 'a' && b <= 'z', b >= '0' && b <= '9', strings.IndexByte("-_.!~*'()", b) >= 0:
			sb.WriteByte(b)
		default:
			fmt.Fprintf(&sb, "%%%02X", b)
		}
	}
	return sb.String()
}

// approvalAppendQuery adds query parameters before any #fragment (an approval link may carry its token there, which must stay last).
func approvalAppendQuery(url string, kv ...string) string {
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, approvalEncodeURIComponent(kv[i])+"="+approvalEncodeURIComponent(kv[i+1]))
	}
	base, fragment := url, ""
	if h := strings.IndexByte(url, '#'); h >= 0 {
		base, fragment = url[:h], url[h:]
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + strings.Join(parts, "&") + fragment
}

func approvalHasInbox(ctx *NotifyContext) bool { return ctx != nil && ctx.InboxURL != "" }

// ---- Slack (Block Kit over an incoming webhook) --------------------------------------------------------------------

// BuildSlackMessage is the Block Kit message for a step-up: action summary, goal lineage, approve / deny affordance.
func BuildSlackMessage(request map[string]any, ctx *NotifyContext) (map[string]any, error) {
	lines, err := ApprovalLineageLines(request)
	if err != nil {
		return nil, err
	}
	text := func(kind, s string) map[string]any { return map[string]any{"type": kind, "text": s} }
	plain := func(s string) map[string]any { return map[string]any{"type": "plain_text", "text": s, "emoji": true} }
	blocks := []any{
		map[string]any{"type": "header", "text": plain("Approval needed · tier " + approvalStr(request, "tier"))},
		map[string]any{"type": "section", "text": text("mrkdwn", "*"+approvalStr(request, "verb")+"* on `"+approvalStr(request, "resource")+"`\n_"+approvalStr(request, "reason")+"_")},
	}
	bullets := make([]string, len(lines))
	for i, l := range lines {
		bullets[i] = "• " + l
	}
	blocks = append(blocks, map[string]any{"type": "section", "text": text("mrkdwn", "*Why this is requested*\n"+strings.Join(bullets, "\n"))})
	if approvalHasInbox(ctx) {
		rid := approvalStr(request, "id")
		blocks = append(blocks, map[string]any{"type": "actions", "elements": []any{
			map[string]any{"type": "button", "text": plain("Approve"), "url": approvalAppendQuery(ctx.InboxURL, "stepup", rid, "decision", "approve"), "style": "primary", "action_id": "pca_approve"},
			map[string]any{"type": "button", "text": plain("Deny"), "url": approvalAppendQuery(ctx.InboxURL, "stepup", rid, "decision", "deny"), "style": "danger", "action_id": "pca_deny"},
		}})
	} else {
		blocks = append(blocks, map[string]any{"type": "context", "elements": []any{
			text("mrkdwn", "Approve or deny step-up `"+approvalStr(request, "id")+"` in your Atlas inbox.")}})
	}
	return map[string]any{"text": "Approval needed: " + ApprovalActionSummary(request), "blocks": blocks}, nil
}

func approvalPost(kind string, transport ApprovalFetch, url string, headers map[string]string, request map[string]any, payload any, name string) ApprovalDelivery {
	rid := approvalStr(request, "id")
	res, err := transport(url, headers, approvalJSStringify(payload))
	if err != nil {
		msg := err.Error()
		return ApprovalDelivery{Kind: kind, RequestID: rid, Payload: payload, Reason: &msg}
	}
	st := res.Status
	if res.OK {
		return ApprovalDelivery{Kind: kind, RequestID: rid, Delivered: true, Payload: payload, Status: &st}
	}
	msg := fmt.Sprintf("%s returned %d", name, st)
	return ApprovalDelivery{Kind: kind, RequestID: rid, Payload: payload, Status: &st, Reason: &msg}
}

func approvalNotConfigured(kind, rid string, payload any) ApprovalDelivery {
	msg := kind + " channel not configured"
	return ApprovalDelivery{Kind: kind, RequestID: rid, Payload: payload, Reason: &msg}
}

type approvalSlack struct {
	url       string
	transport ApprovalFetch
}

func (c *approvalSlack) Kind() string  { return "slack" }
func (c *approvalSlack) Enabled() bool { return c.url != "" }
func (c *approvalSlack) Notify(request map[string]any, ctx *NotifyContext) (ApprovalDelivery, error) {
	msg, err := BuildSlackMessage(request, ctx)
	if err != nil {
		return ApprovalDelivery{}, err
	}
	if !c.Enabled() {
		return approvalNotConfigured("slack", approvalStr(request, "id"), msg), nil
	}
	return approvalPost("slack", c.transport, c.url, map[string]string{"content-type": "application/json"}, request, msg, "slack webhook"), nil
}

// SlackApprovalChannel is the Slack approval channel. It is disabled (and a no-op) unless a webhook URL is configured; a nil fetch is
// the net/http client.
func SlackApprovalChannel(webhookURL string, fetch ApprovalFetch) ApprovalChannel {
	if fetch == nil {
		fetch = DefaultApprovalFetch()
	}
	return &approvalSlack{url: webhookURL, transport: fetch}
}

// ---- generic webhook -----------------------------------------------------------------------------------------------

// BuildWebhookBody is the webhook body: the step-up plus its pre-formatted human summary and lineage.
func BuildWebhookBody(request map[string]any, ctx *NotifyContext) (map[string]any, error) {
	lines, err := ApprovalLineageLines(request)
	if err != nil {
		return nil, err
	}
	l := make([]any, len(lines))
	for i, s := range lines {
		l[i] = s
	}
	m := map[string]any{"type": "pca.step_up.created", "stepup": request, "summary": ApprovalActionSummary(request), "lineage": l}
	if approvalHasInbox(ctx) {
		m["inbox_url"] = ctx.InboxURL
	}
	return m, nil
}

type approvalWebhook struct {
	url       string
	transport ApprovalFetch
	headers   map[string]string
}

func (c *approvalWebhook) Kind() string  { return "webhook" }
func (c *approvalWebhook) Enabled() bool { return c.url != "" }
func (c *approvalWebhook) Notify(request map[string]any, ctx *NotifyContext) (ApprovalDelivery, error) {
	body, err := BuildWebhookBody(request, ctx)
	if err != nil {
		return ApprovalDelivery{}, err
	}
	if !c.Enabled() {
		return approvalNotConfigured("webhook", approvalStr(request, "id"), body), nil
	}
	return approvalPost("webhook", c.transport, c.url, c.headers, request, body, "webhook"), nil
}

// WebhookApprovalChannel is the generic webhook approval channel. headers are extra request headers (never logged); it is disabled
// without a URL and a nil fetch is the net/http client.
func WebhookApprovalChannel(url string, fetch ApprovalFetch, headers map[string]string) ApprovalChannel {
	if fetch == nil {
		fetch = DefaultApprovalFetch()
	}
	hs := map[string]string{"content-type": "application/json"}
	for k, v := range headers {
		hs[k] = v
	}
	return &approvalWebhook{url: url, transport: fetch, headers: hs}
}

// ---- text channels (email / sms / push) over an injected sender -----------------------------------------------------

// BuildTextBody is the plain-text body ({subject, text}) shared by the email, sms and push surfaces.
func BuildTextBody(request map[string]any, ctx *NotifyContext) (map[string]any, error) {
	lines, err := ApprovalLineageLines(request)
	if err != nil {
		return nil, err
	}
	all := append([]string{ApprovalActionSummary(request), ""}, lines...)
	if approvalHasInbox(ctx) {
		all = append(all, "", "Approve or deny: "+approvalAppendQuery(ctx.InboxURL, "stepup", approvalStr(request, "id")))
	}
	return map[string]any{"subject": "Approval needed: " + approvalStr(request, "verb") + " on " + approvalStr(request, "resource"), "text": strings.Join(all, "\n")}, nil
}

type approvalText struct {
	kind string
	send ApprovalTextSender
}

func (c *approvalText) Kind() string  { return c.kind }
func (c *approvalText) Enabled() bool { return c.send != nil }
func (c *approvalText) Notify(request map[string]any, ctx *NotifyContext) (ApprovalDelivery, error) {
	body, err := BuildTextBody(request, ctx)
	if err != nil {
		return ApprovalDelivery{}, err
	}
	rid := approvalStr(request, "id")
	if !c.Enabled() {
		return approvalNotConfigured(c.kind, rid, body), nil
	}
	if _, err := c.send(body["subject"].(string), body["text"].(string)); err != nil {
		msg := err.Error()
		return ApprovalDelivery{Kind: c.kind, RequestID: rid, Payload: body, Reason: &msg}, nil
	}
	return ApprovalDelivery{Kind: c.kind, RequestID: rid, Delivered: true, Payload: body}, nil
}

// TextApprovalChannel is a text-formatter channel ("email", "sms" or "push") over an injected sender; it is disabled without one.
func TextApprovalChannel(kind string, send ApprovalTextSender) (ApprovalChannel, error) {
	if kind != "email" && kind != "sms" && kind != "push" {
		return nil, errors.New("textApprovalChannel: kind must be email, sms or push")
	}
	return &approvalText{kind: kind, send: send}, nil
}

// ---- dispatcher ----------------------------------------------------------------------------------------------------

// ApprovalDispatcher is one dispatcher over a set of channels; a disabled channel is skipped at NotifyAll.
type ApprovalDispatcher struct {
	channels []ApprovalChannel
}

// CreateApprovalDispatcher builds a dispatcher over channels.
func CreateApprovalDispatcher(channels []ApprovalChannel) *ApprovalDispatcher {
	return &ApprovalDispatcher{channels: append([]ApprovalChannel(nil), channels...)}
}

// Channels are the dispatcher's channels.
func (d *ApprovalDispatcher) Channels() []ApprovalChannel {
	return append([]ApprovalChannel(nil), d.channels...)
}

// NotifyAll fans a step-up out to every enabled channel; one delivery per channel.
func (d *ApprovalDispatcher) NotifyAll(request map[string]any, ctx *NotifyContext) ([]ApprovalDelivery, error) {
	out := []ApprovalDelivery{}
	for _, c := range d.channels {
		if !c.Enabled() {
			continue
		}
		dv, err := c.Notify(request, ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, dv)
	}
	return out, nil
}
