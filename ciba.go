package pca

// CIBA bridge (OpenID Client-Initiated Backchannel Authentication): turns a tier-2/3 step-up into a CIBA authentication request whose
// binding message states exactly what the person approves (verb, amount, payee, resource; never free text), gates on tier 3, maps a
// decision onto the trust budget, checks PING callbacks, and brokers the approval lifecycle (in memory, or durably over a
// compare-and-swap ApprovalStore). Step-ups are JSON objects (map[string]any) as they travel on the wire.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	cibaDefaultExpirySec   = 300
	cibaDefaultIntervalSec = 5
	cibaMinAuthReqIDLen    = 22
	cibaMaxGoalChars       = 100
	cibaMaxPayeeChars      = 64
	cibaMaxCasTries        = 8
)

var (
	cibaAuthReqIDRE  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	cibaScopeTokenRE = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+$`)
	cibaIdentRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/#@+-]{0,63}$`)
	cibaForgedRE     = regexp.MustCompile(`because[` + jsWS + `]+you[` + jsWS + `]+asked`) // matched on ASCII-lowercased text (JS /i without u)
	cibaWS2RE        = regexp.MustCompile(`[` + jsWS + `]{2,}`)
	cibaAmountRE     = regexp.MustCompile(`^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)
	cibaCurrencyRE   = regexp.MustCompile(`^[A-Za-z]{3}$`)
	cibaPrintableRE  = regexp.MustCompile(`^[\x20-\x7E]*$`)
	cibaTokenRunRE   = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	cibaDashesRE     = regexp.MustCompile(`-{2,}`)
	cibaEdgeRE       = regexp.MustCompile(`^[-.]+|[-.]+$`)
	cibaBearerRE     = regexp.MustCompile(`^(?i:bearer) +([^` + jsWS + `]+)$`)
	cibaPayeeKeys    = []string{"payee", "to", "recipient", "beneficiary", "destination"}
)

func cibaForged(s string) bool {
	return cibaForgedRE.MatchString(strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 32
		}
		return r
	}, s))
}

func cibaPlainText(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf) || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s)
	return jsTrim(jsWSRun.ReplaceAllString(s, " "))
}

func cibaClip(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max < 1 {
		max = 1
	}
	return string(r[:max-1]) + "…"
}

func cibaIdentifier(v any, what string) (string, error) {
	s, ok := v.(string)
	if !ok || !cibaIdentRE.MatchString(s) {
		return "", fmt.Errorf("ciba: the step-up %s must be a plain identifier (letters, digits and . _ : / # @ + -, at most 64 characters); refusing to render free text in the approval message", what)
	}
	if cibaForged(s) {
		return "", fmt.Errorf("ciba: the step-up %s contains an approval-explanation clause", what)
	}
	return s, nil
}

// cibaUndisplayable: control, format, surrogate, private-use, unassigned, line/paragraph separators, U+FFF9..U+FFFD.
// shortcut: "unassigned" follows Go's Unicode tables, which can trail the reference runtime's ICU by a version.
func cibaUndisplayable(r rune) bool {
	if r == 0x2028 || r == 0x2029 || r >= 0xFFF9 && r <= 0xFFFD || unicode.In(r, unicode.Cc, unicode.Cf, unicode.Cs, unicode.Co) {
		return true
	}
	return !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z)
}

var cibaScriptGroups = []struct {
	name   string
	tables []*unicode.RangeTable
}{
	{"latin", []*unicode.RangeTable{unicode.Latin}},
	{"cyrillic", []*unicode.RangeTable{unicode.Cyrillic}},
	{"greek", []*unicode.RangeTable{unicode.Greek}},
	{"armenian", []*unicode.RangeTable{unicode.Armenian}},
	{"hebrew", []*unicode.RangeTable{unicode.Hebrew}},
	{"arabic", []*unicode.RangeTable{unicode.Arabic}},
	{"cjk", []*unicode.RangeTable{unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul, unicode.Bopomofo}},
	{"indic-thai", []*unicode.RangeTable{unicode.Devanagari, unicode.Bengali, unicode.Tamil, unicode.Thai, unicode.Georgian}},
}

func cibaScripts(t string) int {
	found := map[string]bool{}
	for _, r := range t {
		if !unicode.IsLetter(r) {
			continue
		}
		g := "other:" + string(r)
		for _, sg := range cibaScriptGroups {
			if unicode.In(r, sg.tables...) {
				g = sg.name
				break
			}
		}
		found[g] = true
	}
	return len(found)
}

func cibaPayeeText(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", errors.New("ciba: the payee must be a string (a nested value cannot be shown to the approver)")
	}
	t := norm.NFC.String(s)
	if t == "" || jsTrim(t) != t || cibaWS2RE.MatchString(t) {
		return "", errors.New("ciba: the payee must be non-empty without leading, trailing or repeated whitespace")
	}
	for _, r := range t {
		if cibaUndisplayable(r) || r == '\r' || r == '\n' || r == '\t' {
			return "", errors.New("ciba: the payee contains control, bidirectional or invisible characters and cannot be displayed")
		}
	}
	if strings.ContainsAny(t, `"\`) {
		return "", errors.New("ciba: the payee must not contain quote or backslash characters")
	}
	if utf8.RuneCountInString(t) > cibaMaxPayeeChars {
		return "", fmt.Errorf("ciba: the payee is longer than %d characters; refusing to truncate what the person approves", cibaMaxPayeeChars)
	}
	if cibaForged(t) {
		return "", errors.New("ciba: the payee contains an approval-explanation clause")
	}
	for _, r := range t {
		if unicode.Is(unicode.M, r) {
			return "", errors.New("ciba: the payee contains combining marks and cannot be shown unambiguously")
		}
	}
	if norm.NFKC.String(t) != t {
		return "", errors.New("ciba: the payee contains compatibility/fullwidth characters that imitate plain ones")
	}
	if cibaScripts(t) > 1 {
		return "", errors.New("ciba: the payee mixes writing systems (a homograph risk); refusing so the person never approves a look-alike")
	}
	return t, nil
}

// CibaASCIIForm is the payee as the approver can cross-check it in ASCII: each non-ASCII word as its IDNA A-label (or \u{..}
// escapes where it is not a valid domain label).
func CibaASCIIForm(payee string) string {
	if cibaPrintableRE.MatchString(payee) {
		return payee
	}
	words := strings.Split(payee, " ")
	for i, w := range words {
		if cibaPrintableRE.MatchString(w) {
			continue
		}
		if a, err := whatwgDomainHost(w); err == nil && a != "" {
			words[i] = a
			continue
		}
		var b strings.Builder
		for _, r := range w {
			if r > 0x7e {
				fmt.Fprintf(&b, `\u{%x}`, r)
			} else {
				b.WriteRune(r)
			}
		}
		words[i] = b.String()
	}
	return strings.Join(words, " ")
}

// CibaAction is the canonical action a binding message displays.
type CibaAction struct {
	Verb     string `json:"verb"`
	Amount   string `json:"amount,omitempty"`
	Currency string `json:"currency,omitempty"`
	Payee    string `json:"payee,omitempty"`
	Resource string `json:"resource"`
	hasPayee bool
}

func cibaPresent(m map[string]any, k string) bool { v, has := m[k]; return has && v != nil }

// CibaActionFromStepUp extracts the action a CIBA binding message displays. It refuses any params field it would not display, an
// amount without a 3-letter currency and a payee, more than one payee field, and a payee that cannot be shown unambiguously.
func CibaActionFromStepUp(stepUp map[string]any) (CibaAction, error) {
	var a CibaAction
	pv := stepUp["params"]
	if pv == nil {
		pv = map[string]any{}
	}
	params, ok := pv.(map[string]any)
	if !ok {
		return a, errors.New("ciba: step-up params must be an object")
	}
	var unknown []string
	for k := range params {
		if k != "amount" && k != "currency" && !hasStr(cibaPayeeKeys, k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		return a, fmt.Errorf("ciba: step-up params field(s) %s are not displayed in the approval message (displayable: amount, currency, %s); refusing so the person never approves a hidden field",
			strings.Join(unknown, ", "), strings.Join(cibaPayeeKeys, "/"))
	}
	var err error
	if a.Verb, err = cibaIdentifier(stepUp["verb"], "verb"); err != nil {
		return a, err
	}
	if a.Resource, err = cibaIdentifier(stepUp["resource"], "resource"); err != nil {
		return a, err
	}
	var payeeKeys []string
	for _, k := range cibaPayeeKeys {
		if cibaPresent(params, k) {
			payeeKeys = append(payeeKeys, k)
		}
	}
	if len(payeeKeys) > 1 {
		return a, fmt.Errorf("ciba: more than one payee field (%s) in params; the approver would see only one", strings.Join(payeeKeys, ", "))
	}
	if cibaPresent(params, "amount") {
		text := ""
		if f, ok := jsNum(params["amount"]); ok && !math.IsInf(f, 0) && !math.IsNaN(f) {
			text = jsNumberString(f)
		} else if s, ok := params["amount"].(string); ok {
			text = s
		}
		if !cibaAmountRE.MatchString(text) {
			return a, errors.New("ciba: the binding message needs a plain non-negative decimal amount (no sign or exponent)")
		}
		cur, ok := params["currency"].(string)
		if !ok || !cibaCurrencyRE.MatchString(cur) {
			return a, errors.New("ciba: the binding message needs a 3-letter currency code next to the amount")
		}
		if len(payeeKeys) == 0 {
			return a, errors.New("ciba: an amount needs a payee (payee / to / recipient / beneficiary / destination) so the approver sees who receives it")
		}
		a.Amount, a.Currency = text, strings.ToUpper(cur)
	} else if cibaPresent(params, "currency") {
		return a, errors.New("ciba: a currency without an amount cannot be displayed")
	}
	if len(payeeKeys) == 1 {
		if a.Payee, err = cibaPayeeText(params[payeeKeys[0]]); err != nil {
			return a, err
		}
		a.hasPayee = true
	}
	return a, nil
}

func hasStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func cibaTooLong(n int, max float64) error {
	return fmt.Errorf("ciba: the binding message needs %d characters but bindingMessage.maxChars is %s; refusing to truncate what the person approves", n, jsNumberString(max))
}

// cibaBindingMessage: limit +Inf = no maxChars.
func cibaBindingMessage(stepUp map[string]any, actsFor string, limit float64) (string, error) {
	a, err := CibaActionFromStepUp(stepUp)
	if err != nil {
		return "", err
	}
	head := "Approve " + a.Verb
	if a.Amount != "" {
		head += " " + a.Amount + " " + a.Currency
	}
	if a.hasPayee {
		head += ` to "` + a.Payee + `"`
		if !cibaPrintableRE.MatchString(a.Payee) {
			head += " [non-ASCII name; ASCII form: " + CibaASCIIForm(a.Payee) + "]"
		}
	}
	head += " on " + a.Resource
	if n := utf8.RuneCountInString(head); float64(n) > limit {
		return "", cibaTooLong(n, limit)
	}
	plainGoal := ""
	if g, has := stepUp["goal"]; has {
		s, ok := g.(string)
		if !ok {
			return "", errors.New("ciba: the step-up goal must be a string")
		}
		plainGoal = strings.NewReplacer("'", "′", "‘", "′", "’", "′").Replace(cibaPlainText(s))
	}
	goalText := ""
	if plainGoal != "" {
		goalText = cibaClip(plainGoal, cibaMaxGoalChars)
	} else {
		gc, has := stepUp["goalCommit"]
		if !has || gc == nil {
			return "", errors.New("ciba: the step-up goalCommit is missing")
		}
		if s, ok := gc.(string); ok && s != "" {
			u := utf16Units(s)
			if len(u) > 10 {
				u = u[:10]
			}
			goalText = "goal " + string(utf16.Decode(u)) + "…"
		}
	}
	if goalText == "" {
		return head, nil
	}
	prefix := " — because you asked " + actsFor + " to '"
	room := limit - float64(utf8.RuneCountInString(head+prefix)) - 1
	if room >= float64(utf8.RuneCountInString(goalText)) {
		return head + prefix + goalText + "'", nil
	}
	if room >= 8 {
		return head + prefix + cibaClip(goalText, int(room)) + "'", nil
	}
	return head, nil
}

func cibaTokenise(s string) string {
	s = cibaTokenRunRE.ReplaceAllString(s, "-")
	s = cibaDashesRE.ReplaceAllString(s, "-")
	return cibaEdgeRE.ReplaceAllString(s, "")
}

func cibaCompactBindingMessage(stepUp map[string]any, maxChars float64) (string, error) {
	a, err := CibaActionFromStepUp(stepUp)
	if err != nil {
		return "", err
	}
	if a.hasPayee && !cibaPrintableRE.MatchString(a.Payee) {
		return "", errors.New("ciba: tokenOnly binding message needs an ASCII payee (tokenising would drop characters the person must see)")
	}
	raw := []string{"Approve", a.Verb}
	if a.Amount != "" {
		raw = append(raw, a.Amount, a.Currency)
	}
	if a.hasPayee {
		raw = append(raw, "to", a.Payee)
	}
	raw = append(raw, a.Resource)
	for i, p := range raw {
		if raw[i] = cibaTokenise(p); raw[i] == "" {
			return "", errors.New("ciba: tokenOnly binding message cannot represent the verb, payee or resource")
		}
	}
	out := strings.Join(raw, "-")
	if float64(len(out)) > maxChars {
		return "", cibaTooLong(len(out), maxChars)
	}
	return out, nil
}

// CibaBindingMessageOptions: MaxChars nil = 50 for tokenOnly, unbounded for the rich message.
type CibaBindingMessageOptions struct {
	MaxChars  *float64
	TokenOnly bool
}

// CibaRequestOptions: nil fields take the defaults (300 s expiry, 5 s interval, the step-up scope, a derived auth_req_id,
// "your agent").
type CibaRequestOptions struct {
	ExpiresInSec, Interval *float64
	AuthReqID, LoginHint   *string
	StepUpScope            *bool
	BindingMessage         *CibaBindingMessageOptions
	ActsFor                *string
}

// CibaAuthorizationDetail carries the approval render the person sees, with its digest.
type CibaAuthorizationDetail struct {
	Type         string `json:"type"`
	Render       any    `json:"render"`
	RenderDigest string `json:"render_digest"`
}

// CibaAuthRequest is the backchannel authentication request.
type CibaAuthRequest struct {
	AuthReqID            string                    `json:"auth_req_id"`
	BindingMessage       string                    `json:"binding_message"`
	Scope                string                    `json:"scope"`
	RequestedExpiry      float64                   `json:"requested_expiry"`
	Interval             float64                   `json:"interval"`
	LoginHint            *string                   `json:"login_hint,omitempty"`
	StepUpID             any                       `json:"stepUpId,omitempty"`
	Tier                 any                       `json:"tier,omitempty"`
	AuthorizationDetails []CibaAuthorizationDetail `json:"authorization_details,omitempty"`
	RenderDigest         string                    `json:"render_digest,omitempty"`
}

func cibaSafePositive(f float64) bool {
	return f == math.Trunc(f) && math.Abs(f) <= 1<<53-1 && f > 0
}

// ToCibaAuthRequest builds the CIBA request for a step-up. The binding message never truncates what the person approves: it
// refuses instead. A step-up carrying an approval render must carry its matching digest; the match code is appended.
func ToCibaAuthRequest(stepUp map[string]any, o CibaRequestOptions) (CibaAuthRequest, error) {
	var r CibaAuthRequest
	actsFor := "your agent"
	if o.ActsFor != nil && cibaPlainText(*o.ActsFor) != "" {
		actsFor = cibaClip(cibaPlainText(*o.ActsFor), 40)
	}
	r.RequestedExpiry = cibaDefaultExpirySec
	if o.ExpiresInSec != nil {
		r.RequestedExpiry = *o.ExpiresInSec
	}
	if !cibaSafePositive(r.RequestedExpiry) {
		return r, fmt.Errorf("ciba: requested_expiry must be a positive integer number of seconds, got %s", jsNumberString(r.RequestedExpiry))
	}
	scope := "urn:atlas:pca:stepup:" + jsValueString(stepUp["verb"])
	if _, has := stepUp["verb"]; !has {
		scope = "urn:atlas:pca:stepup:undefined"
	}
	if !cibaScopeTokenRE.MatchString(scope) {
		return r, errors.New("ciba: the step-up verb cannot be carried as an OAuth scope-token (RFC 6749 3.3)")
	}
	r.Scope = "openid " + scope
	if o.StepUpScope != nil && !*o.StepUpScope {
		r.Scope = "openid"
	}
	r.Interval = cibaDefaultIntervalSec
	if o.Interval != nil {
		r.Interval = *o.Interval
	}
	if !cibaSafePositive(r.Interval) {
		return r, fmt.Errorf("ciba: interval must be a positive integer number of seconds, got %s", jsNumberString(r.Interval))
	}
	if o.AuthReqID != nil {
		r.AuthReqID = *o.AuthReqID
	} else {
		in := map[string]any{"d": "atlas-pca/ciba/auth_req_id/v1"}
		if id, has := stepUp["id"]; has {
			in["stepUp"] = id
		}
		h, err := HashCanonical(in)
		if err != nil {
			return r, err
		}
		r.AuthReqID = h
	}
	if !cibaAuthReqIDRE.MatchString(r.AuthReqID) || len(r.AuthReqID) < cibaMinAuthReqIDLen || len(r.AuthReqID) > 1024 {
		return r, errors.New("ciba: auth_req_id must use only A-Za-z0-9.-_ and be 22..1024 characters (CIBA Core 7.3)")
	}
	bm := o.BindingMessage
	if bm == nil {
		bm = &CibaBindingMessageOptions{}
	}
	if bm.MaxChars != nil && (!cibaSafePositive(*bm.MaxChars) || *bm.MaxChars < 1) {
		return r, errors.New("ciba: bindingMessage.maxChars must be a positive integer")
	}
	maxChars := 50.0
	if bm.MaxChars != nil {
		maxChars = *bm.MaxChars
	}
	render, hasRender := stepUp["render"]
	rdv, hasDigest := stepUp["renderDigest"]
	words := ""
	if hasRender || hasDigest {
		rd, ok := rdv.(string)
		got, err := ApprovalRenderDigest(render)
		if !hasRender || !hasDigest || !ok || err != nil || got != rd {
			return r, errors.New("ciba: the step-up render and its digest do not agree; refusing to send an approval that commits to something else")
		}
		if words, err = BindingWords(rd); err != nil {
			return r, err
		}
		r.AuthorizationDetails = []CibaAuthorizationDetail{{Type: "pca_approval", Render: render, RenderDigest: rd}}
		r.RenderDigest = rd
	}
	reserve := 0.0
	if hasRender {
		reserve = float64(jsLen(words) + 14)
	}
	var err error
	if bm.TokenOnly {
		r.BindingMessage, err = cibaCompactBindingMessage(stepUp, maxChars-reserve)
	} else {
		limit := math.Inf(1)
		if bm.MaxChars != nil {
			limit = *bm.MaxChars - reserve
		}
		r.BindingMessage, err = cibaBindingMessage(stepUp, actsFor, limit)
	}
	if err != nil {
		return r, err
	}
	if hasRender {
		if bm.TokenOnly {
			r.BindingMessage += "-match-" + words
		} else {
			r.BindingMessage += " [match code " + words + "]"
		}
	}
	r.LoginHint = o.LoginHint
	r.StepUpID, r.Tier = stepUp["id"], stepUp["tier"]
	return r, nil
}

// RequiresCiba: only a tier-3 step-up review goes to the backchannel.
func RequiresCiba(review map[string]any) (bool, error) {
	if review["kind"] != "step_up" {
		return false, nil
	}
	req, has := review["request"]
	if !has || req == nil {
		return false, errors.New("ciba: a step_up review carries no request")
	}
	m, _ := req.(map[string]any)
	t, ok := jsNum(m["tier"])
	return ok && t == 3, nil
}

// CibaDecisionToCosign maps a CIBA decision onto the trust budget: an approval is a human co-sign (recharge, or a full recharge),
// a denial leaves the budget as it was.
func CibaDecisionToCosign(decision string, b TrustBudget, p RiskPolicy, now float64, full bool) (TrustBudget, bool) {
	if decision != "approve" {
		return b, false
	}
	if full {
		return RechargeFull(p.BMax, now), true
	}
	return b.Recharge(p.Rho, p.BMax, now), true
}

// NewClientNotificationToken is a fresh client_notification_token (256 bits, base64url).
func NewClientNotificationToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// CibaPingFlow is what a PING callback is checked against. ClientNotificationToken nil = the flow was not started in ping mode.
type CibaPingFlow struct {
	AuthReqID               string
	ClientNotificationToken *string
}

// VerifyPingCallback checks a PING callback (CIBA Core 10.2): `Authorization: Bearer <client_notification_token>` (constant-time)
// and a body whose auth_req_id is this flow's. It returns the auth_req_id. The callback carries no decision.
func VerifyPingCallback(authorization string, body any, flow CibaPingFlow) (string, error) {
	if flow.ClientNotificationToken == nil {
		return "", errors.New("ciba: flow was not started in ping mode")
	}
	m := cibaBearerRE.FindStringSubmatch(authorization)
	if m == nil {
		return "", errors.New("ciba: ping callback lacks a bearer token")
	}
	a, b := sha256.Sum256([]byte(m[1])), sha256.Sum256([]byte(*flow.ClientNotificationToken))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		return "", errors.New("ciba: ping callback bearer does not match the client_notification_token")
	}
	bm, _ := body.(map[string]any)
	id, ok := bm["auth_req_id"].(string)
	if !ok || id != flow.AuthReqID {
		return "", errors.New("ciba: ping callback auth_req_id does not match this flow")
	}
	return id, nil
}

// ---- brokers ----

// CibaSession is a flow's state as reported to the caller.
type CibaSession struct {
	AuthReqID string          `json:"auth_req_id"`
	Request   CibaAuthRequest `json:"request"`
	Status    string          `json:"status"`
	CreatedAt float64         `json:"createdAt"`
	ExpiresAt float64         `json:"expiresAt"`
	DecidedBy *string         `json:"decidedBy,omitempty"`
	DecidedAt *float64        `json:"decidedAt,omitempty"`
}

// CibaTokenOutcome is a token-endpoint answer: OK with the session (once), or an OAuth error with the interval to wait.
type CibaTokenOutcome struct {
	OK       bool
	Session  *CibaSession
	Error    string
	Interval float64
}

func (t CibaTokenOutcome) MarshalJSON() ([]byte, error) {
	if t.OK {
		return json.Marshal(map[string]any{"ok": true, "session": t.Session})
	}
	return json.Marshal(map[string]any{"ok": false, "error": t.Error, "interval": t.Interval})
}

// CibaBroker runs the approval lifecycle: Start (idempotent while a flow for the step-up is live), Poll (a read), Token
// (single-use redemption with slow_down), Resolve (once, while pending) and Get (nil when unknown). Times are epoch ms.
type CibaBroker interface {
	Start(stepUp map[string]any, opts CibaRequestOptions) (CibaAuthRequest, error)
	Poll(authReqID string) (string, error)
	Token(authReqID string) (CibaTokenOutcome, error)
	Resolve(authReqID, decision, by string) (CibaSession, error)
	Get(authReqID string) (*CibaSession, error)
}

type cibaRec struct {
	Request    CibaAuthRequest `json:"request"`
	CreatedAt  float64         `json:"createdAt"`
	ExpiresAt  float64         `json:"expiresAt"`
	Interval   float64         `json:"interval"`
	Decision   string          `json:"decision,omitempty"`
	DecidedBy  *string         `json:"decidedBy,omitempty"`
	DecidedAt  *float64        `json:"decidedAt,omitempty"`
	LastPollAt *float64        `json:"lastPollAt,omitempty"`
	Consumed   bool            `json:"consumed,omitempty"`
}

func cibaRandomID() string {
	b := make([]byte, 20)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func cibaClock(now func() float64) func() float64 {
	if now != nil {
		return now
	}
	return func() float64 { return float64(time.Now().UnixMilli()) }
}

func (r *cibaRec) snapshot(status string) CibaSession {
	return CibaSession{AuthReqID: r.Request.AuthReqID, Request: r.Request, Status: status, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt, DecidedBy: r.DecidedBy, DecidedAt: r.DecidedAt}
}

// cibaTokenStep is the shared token-endpoint state machine (mutates r).
func cibaTokenStep(r *cibaRec, now float64, status func(*cibaRec, float64) string) CibaTokenOutcome {
	if r.Consumed {
		return CibaTokenOutcome{Error: "invalid_grant", Interval: r.Interval}
	}
	tooSoon := r.LastPollAt != nil && !(finite(now) && now-*r.LastPollAt >= r.Interval*1000)
	r.LastPollAt = &now
	if tooSoon {
		r.Interval += 5
		return CibaTokenOutcome{Error: "slow_down", Interval: r.Interval}
	}
	switch st := status(r, now); st {
	case "pending":
		return CibaTokenOutcome{Error: "authorization_pending", Interval: r.Interval}
	case "denied":
		return CibaTokenOutcome{Error: "access_denied", Interval: r.Interval}
	case "expired":
		return CibaTokenOutcome{Error: "expired_token", Interval: r.Interval}
	}
	r.Consumed = true
	s := r.snapshot(status(r, now))
	return CibaTokenOutcome{OK: true, Session: &s}
}

type memoryCibaBroker struct {
	mu         sync.Mutex
	now        func() float64
	onComplete func(CibaSession)
	sessions   map[string]*cibaRec
	live       map[string]string
}

// NewCibaBroker is an in-memory broker (one process; see NewDurableCibaBroker for a shared store). now nil = the wall clock.
func NewCibaBroker(now func() float64, onComplete func(CibaSession)) CibaBroker {
	return &memoryCibaBroker{now: cibaClock(now), onComplete: onComplete, sessions: map[string]*cibaRec{}, live: map[string]string{}}
}

func cibaMemStatus(r *cibaRec, now float64) string {
	switch {
	case r.Decision == "approve":
		return "approved"
	case r.Decision == "deny":
		return "denied"
	case !(finite(now) && now < r.ExpiresAt):
		return "expired"
	}
	return "pending"
}

func (b *memoryCibaBroker) Start(stepUp map[string]any, opts CibaRequestOptions) (CibaAuthRequest, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	key := jsValueString(stepUp["id"])
	if ex := b.sessions[b.live[key]]; ex != nil {
		if st := cibaMemStatus(ex, now); st == "pending" || st == "approved" {
			return ex.Request, nil
		}
	}
	id := cibaRandomID()
	opts.AuthReqID = &id
	req, err := ToCibaAuthRequest(stepUp, opts)
	if err != nil {
		return req, err
	}
	b.sessions[id] = &cibaRec{Request: req, CreatedAt: now, ExpiresAt: now + req.RequestedExpiry*1000, Interval: req.Interval}
	b.live[key] = id
	return req, nil
}

func (b *memoryCibaBroker) Poll(id string) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[id]
	if s == nil {
		return "", fmt.Errorf("ciba: unknown auth_req_id %s", id)
	}
	return cibaMemStatus(s, b.now()), nil
}

func (b *memoryCibaBroker) Token(id string) (CibaTokenOutcome, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[id]
	if s == nil {
		return CibaTokenOutcome{Error: "invalid_grant", Interval: cibaDefaultIntervalSec}, nil
	}
	return cibaTokenStep(s, b.now(), cibaMemStatus), nil
}

func (b *memoryCibaBroker) Resolve(id, decision, by string) (CibaSession, error) {
	b.mu.Lock()
	s := b.sessions[id]
	if s == nil {
		b.mu.Unlock()
		return CibaSession{}, fmt.Errorf("ciba: unknown auth_req_id %s", id)
	}
	now := b.now()
	if cur := cibaMemStatus(s, now); cur != "pending" {
		b.mu.Unlock()
		return CibaSession{}, fmt.Errorf("ciba: cannot resolve %s — already %s", id, cur)
	}
	s.Decision, s.DecidedBy, s.DecidedAt = decision, &by, &now
	snap := s.snapshot(cibaMemStatus(s, now))
	b.mu.Unlock()
	if b.onComplete != nil {
		b.onComplete(snap)
	}
	return snap, nil
}

func (b *memoryCibaBroker) Get(id string) (*CibaSession, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[id]
	if s == nil {
		return nil, nil
	}
	snap := s.snapshot(cibaMemStatus(s, b.now()))
	return &snap, nil
}

// ApprovalVersioned is a stored value with its version (0 = absent).
type ApprovalVersioned struct {
	Version int `json:"version"`
	Value   any `json:"value"`
}

// ApprovalStore is a compare-and-swap store: Cas writes value at version expected+1 only when the current version is expected.
type ApprovalStore interface {
	Get(key string) (*ApprovalVersioned, error)
	Cas(key string, expectedVersion int, value any) (bool, error)
}

func cibaCloneJSON(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	return out, json.Unmarshal(b, &out)
}

type memoryApprovalStore struct {
	mu sync.Mutex
	m  map[string]ApprovalVersioned
}

// NewMemoryApprovalStore is an in-process ApprovalStore (values are deep-copied in and out).
func NewMemoryApprovalStore() ApprovalStore {
	return &memoryApprovalStore{m: map[string]ApprovalVersioned{}}
}

func (s *memoryApprovalStore) Get(k string) (*ApprovalVersioned, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return nil, nil
	}
	c, err := cibaCloneJSON(v.Value)
	return &ApprovalVersioned{Version: v.Version, Value: c}, err
}

func (s *memoryApprovalStore) Cas(k string, exp int, value any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[k].Version != exp {
		return false, nil
	}
	c, err := cibaCloneJSON(value)
	if err != nil {
		return false, err
	}
	s.m[k] = ApprovalVersioned{Version: exp + 1, Value: c}
	return true, nil
}

type fileApprovalStore struct {
	mu   sync.Mutex
	path string
}

// NewFileApprovalStore is a single-host ApprovalStore in one JSON file (atomic rename, mode 0600). A corrupt file is an error
// (fail closed). The mutex serializes this process; use one store per file per host.
func NewFileApprovalStore(path string) ApprovalStore { return &fileApprovalStore{path: path} }

func (s *fileApprovalStore) load() (map[string]ApprovalVersioned, error) {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]ApprovalVersioned{}, nil
	}
	if err != nil {
		return nil, err
	}
	var all map[string]ApprovalVersioned
	if err := json.Unmarshal(b, &all); err != nil || all == nil {
		return nil, errors.New("ciba: approval store file is corrupt")
	}
	return all, nil
}

func (s *fileApprovalStore) Get(k string) (*ApprovalVersioned, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return nil, err
	}
	v, ok := all[k]
	if !ok {
		return nil, nil
	}
	return &v, nil
}

func (s *fileApprovalStore) Cas(k string, exp int, value any) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all, err := s.load()
	if err != nil {
		return false, err
	}
	if all[k].Version != exp {
		return false, nil
	}
	all[k] = ApprovalVersioned{Version: exp + 1, Value: value}
	b, err := json.Marshal(all)
	if err != nil {
		return false, err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", s.path, os.Getpid())
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return false, err
	}
	if err := RestrictToOwner(tmp); err != nil { // the access list travels with the rename
		os.Remove(tmp)
		return false, err
	}
	return true, os.Rename(tmp, s.path)
}

type durableCibaBroker struct {
	store      ApprovalStore
	now        func() float64
	ttlMs      float64
	onComplete func(CibaSession)
}

// NewDurableCibaBroker is a broker over an ApprovalStore, safe across processes sharing the store. decisionTtlSec nil = 300: an
// approval not redeemed within it expires. onComplete runs after a decision is recorded; its panic or failure cannot undo it.
func NewDurableCibaBroker(store ApprovalStore, now func() float64, decisionTtlSec *float64, onComplete func(CibaSession)) (CibaBroker, error) {
	if store == nil {
		return nil, errors.New("createDurableCibaBroker: `store` is required")
	}
	ttl := 300.0
	if decisionTtlSec != nil {
		ttl = *decisionTtlSec
	}
	ttlMs := ttl * 1000
	if math.IsNaN(ttlMs) || math.IsInf(ttlMs, 0) || ttlMs <= 0 {
		return nil, errors.New("createDurableCibaBroker: decisionTtlSec must be a positive number")
	}
	return &durableCibaBroker{store: store, now: cibaClock(now), ttlMs: ttlMs, onComplete: onComplete}, nil
}

func (b *durableCibaBroker) status(r *cibaRec, now float64) string {
	switch {
	case r.Decision == "deny":
		return "denied"
	case r.Decision == "approve":
		if r.DecidedAt == nil || !(finite(now) && now < *r.DecidedAt+b.ttlMs) {
			return "expired"
		}
		return "approved"
	case !(finite(now) && now < r.ExpiresAt):
		return "expired"
	}
	return "pending"
}

func cibaAsRec(v any) (*cibaRec, error) {
	bad := errors.New("ciba: stored approval record is malformed")
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad
	}
	req, _ := m["request"].(map[string]any)
	if _, ok := req["auth_req_id"].(string); !ok {
		return nil, bad
	}
	for _, k := range []string{"createdAt", "expiresAt", "interval"} {
		if f, ok := jsNum(m[k]); !ok || math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, bad
		}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, bad
	}
	var r cibaRec
	if json.Unmarshal(raw, &r) != nil {
		return nil, bad
	}
	return &r, nil
}

func (b *durableCibaBroker) load(id string) (*cibaRec, int, error) {
	v, err := b.store.Get("a:" + id)
	if err != nil || v == nil {
		return nil, 0, err
	}
	r, err := cibaAsRec(v.Value)
	return r, v.Version, err
}

// mutate applies fn to a fresh copy of the record under compare-and-swap; fn returns write=false to leave the store untouched.
func (b *durableCibaBroker) mutate(id string, fn func(r *cibaRec, now float64) (write bool, err error)) error {
	for i := 0; i < cibaMaxCasTries; i++ {
		r, ver, err := b.load(id)
		if err != nil {
			return err
		}
		write, err := fn(r, b.now())
		if err != nil || !write {
			return err
		}
		if ok, err := b.store.Cas("a:"+id, ver, r); err != nil || ok {
			return err
		}
	}
	return errors.New("ciba: approval store contention, gave up")
}

func (b *durableCibaBroker) Start(stepUp map[string]any, opts CibaRequestOptions) (CibaAuthRequest, error) {
	liveKey := "s:" + jsValueString(stepUp["id"])
	for i := 0; i < cibaMaxCasTries; i++ {
		now := b.now()
		idx, err := b.store.Get(liveKey)
		if err != nil {
			return CibaAuthRequest{}, err
		}
		if idx != nil {
			ex, _, err := b.load(jsValueString(idx.Value))
			if err != nil {
				return CibaAuthRequest{}, err
			}
			if ex != nil && !ex.Consumed {
				if st := b.status(ex, now); st == "pending" || st == "approved" {
					return ex.Request, nil
				}
			}
		}
		id := cibaRandomID()
		opts.AuthReqID = &id
		req, err := ToCibaAuthRequest(stepUp, opts)
		if err != nil {
			return req, err
		}
		rec := &cibaRec{Request: req, CreatedAt: now, ExpiresAt: now + req.RequestedExpiry*1000, Interval: req.Interval}
		if ok, err := b.store.Cas("a:"+id, 0, rec); err != nil {
			return req, err
		} else if !ok {
			continue
		}
		ver := 0
		if idx != nil {
			ver = idx.Version
		}
		if ok, err := b.store.Cas(liveKey, ver, id); err != nil || ok {
			return req, err
		}
	}
	return CibaAuthRequest{}, errors.New("ciba: approval store contention, gave up")
}

func (b *durableCibaBroker) Poll(id string) (string, error) {
	r, _, err := b.load(id)
	if err != nil {
		return "", err
	}
	if r == nil {
		return "", fmt.Errorf("ciba: unknown auth_req_id %s", id)
	}
	return b.status(r, b.now()), nil
}

func (b *durableCibaBroker) Token(id string) (CibaTokenOutcome, error) {
	var out CibaTokenOutcome
	err := b.mutate(id, func(r *cibaRec, now float64) (bool, error) {
		if r == nil {
			out = CibaTokenOutcome{Error: "invalid_grant", Interval: cibaDefaultIntervalSec}
			return false, nil
		}
		if r.Consumed {
			out = CibaTokenOutcome{Error: "invalid_grant", Interval: r.Interval}
			return false, nil
		}
		out = cibaTokenStep(r, now, b.status)
		return true, nil
	})
	return out, err
}

func (b *durableCibaBroker) Resolve(id, decision, by string) (CibaSession, error) {
	if decision != "approve" && decision != "deny" {
		return CibaSession{}, errors.New(`ciba: decision must be "approve" or "deny"`)
	}
	if by == "" {
		return CibaSession{}, errors.New("ciba: `by` (the authenticated decider) is required")
	}
	var snap CibaSession
	err := b.mutate(id, func(r *cibaRec, now float64) (bool, error) {
		if r == nil {
			return false, fmt.Errorf("ciba: unknown auth_req_id %s", id)
		}
		if cur := b.status(r, now); cur != "pending" {
			return false, fmt.Errorf("ciba: cannot resolve %s — already %s", id, cur)
		}
		r.Decision, r.DecidedBy, r.DecidedAt = decision, &by, &now
		snap = r.snapshot(b.status(r, now))
		return true, nil
	})
	if err != nil {
		return CibaSession{}, err
	}
	if b.onComplete != nil {
		func() {
			defer func() { _ = recover() }() // the decision is recorded; a failing notifier must not undo or hide it
			b.onComplete(snap)
		}()
	}
	return snap, nil
}

func (b *durableCibaBroker) Get(id string) (*CibaSession, error) {
	r, _, err := b.load(id)
	if err != nil || r == nil {
		return nil, err
	}
	s := r.snapshot(b.status(r, b.now()))
	return &s, nil
}
