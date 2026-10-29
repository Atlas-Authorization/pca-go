package pca

// UNDO WINDOWS (0.5), the pure layer (port of the TypeScript reference undo.ts): reversible actions execute at once and the
// principal gets a veto window in which they can undo them. This file lets a Go service verify what the undo coordinator
// (the TypeScript coordinator or the hosted ledger) produces: the compensation digest, the signed one-click undo token, the
// signed and hash-chained audit receipts, the record state machine and the window clamp. Admission, the durable ledger,
// compensation and notification stay with the coordinator; Authorize only takes its admission through AuthorizeInput.Undo.
//
//	open --veto (now <= window_end)--> vetoed --compensated--> compensated
//	  |                                  |  \--compensation_failed--> compensation_failed --retry--> vetoed
//	  |                                  |                                   \--compensated--> compensated
//	  +--finalize (now > window_end)--> finalized
//	  +--abort (the effect never ran)--> finalized
//
// Signatures are plain Ed25519 over UTF-8(domain) || strict canonical JSON of the body. Every function is total.

import (
	"fmt"
	"math"
	"unicode/utf8"
)

const (
	UndoTokenDomain        = "atlas-pca/undo-token/v1\x00"
	UndoReceiptDomain      = "atlas-pca/undo-receipt/v1\x00"
	UndoCompensationDomain = "atlas-pca/undo-compensation/v1"
	UndoReceiptRefDomain   = "atlas-pca/undo-receipt-ref/v1"
	UndoTokenRefDomain     = "atlas-pca/undo-token-ref/v1"
	UndoTokenKind          = "pca-undo-token"
	UndoReceiptKind        = "pca-undo-receipt"
	// UndoMinWindowMs is the realistic floor of a veto window: a human must be able to react.
	UndoMinWindowMs     = 30000
	UndoDefaultWindowMs = 900000
	UndoMaxWindowMs     = 86400000
)

var (
	undoStates = []string{"open", "vetoed", "compensated", "compensation_failed", "finalized"}
	undoEvents = []string{"opened", "vetoed", "compensated", "compensation_failed", "finalized", "aborted", "retried", "effect"}
	vetoVias   = []string{"token", "operator", "fraud_proof", "revocation"}
)

// UndoCompensation is the compensating action of an undo record, decided BEFORE the original effect runs. TargetParam "" =
// none (the compensating definition's resource-id parameter, filled at execution from the original's result).
type UndoCompensation struct {
	Verb        string
	Resource    string
	Params      map[string]any
	UndoOf      string
	DefDigest   string
	TargetParam string
}

// CompensationDigest = hashCanonical({d: "atlas-pca/undo-compensation/v1", verb, resource, params, undo_of, def_digest,
// target_param?}).
func CompensationDigest(c UndoCompensation) (string, error) {
	params, ok := jsonValue(c.Params, 1)
	if !ok {
		return "", fmt.Errorf("undo: the compensation params are not JSON")
	}
	body := map[string]any{"d": UndoCompensationDomain, "verb": c.Verb, "resource": c.Resource, "params": params, "undo_of": c.UndoOf, "def_digest": c.DefDigest}
	if c.TargetParam != "" {
		body["target_param"] = c.TargetParam
	}
	return HashCanonical(body)
}

// undoIDOk: a record id is a string of 1..256 UTF-16 code units without control characters (U+0000..U+001F).
func undoIDOk(v any) bool {
	s, ok := v.(string)
	if !ok || s == "" || jsLen(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 {
			return false
		}
	}
	return true
}

func undoDomainVerify(domain, signer string, body map[string]any, sig string) bool {
	msg, ok := domainMessage(domain, normalizeJSON(body))
	return ok && verifyB64u(signer, msg, sig)
}

func undoSign(domain string, body map[string]any, key *KeyPair) (map[string]any, error) {
	if key == nil {
		return nil, fmt.Errorf("signer_missing: the undo service key is required")
	}
	b, err := normObj(body)
	if err != nil {
		return nil, err
	}
	cb, err := canonBytes(b)
	if err != nil {
		return nil, err
	}
	b["sig"] = b64.EncodeToString(key.Sign(append([]byte(domain), cb...)))
	return b, nil
}

// ---- the one-click undo token -----------------------------------------------------------------------------------------------

// UndoTokenRecord is the part of an undo record a token binds. RenderDigest "" = the record carries none.
type UndoTokenRecord struct {
	ID                 string
	Aud                string
	Principal          string
	CompensationDigest string
	RenderDigest       string
	WindowEnd          int64
}

// SignUndoToken signs the one-click undo token of a record under the undo service key (exactly 10 members; exp = window_end).
func SignUndoToken(rec UndoTokenRecord, key *KeyPair) (map[string]any, error) {
	if key == nil {
		return nil, fmt.Errorf("signer_missing: the undo service key is required")
	}
	return undoSign(UndoTokenDomain, map[string]any{"v": 1, "kind": UndoTokenKind, "record": rec.ID, "aud": rec.Aud, "principal": rec.Principal,
		"compensation_digest": rec.CompensationDigest, "render_digest": rec.RenderDigest, "exp": rec.WindowEnd, "signer": key.Public}, key)
}

var undoTokenMembers = []string{"v", "kind", "record", "aud", "principal", "compensation_digest", "render_digest", "exp", "signer", "sig"}

// UndoTokenCheck checks a token against the pinned undo service key and the stored record at now (epoch ms). It returns the
// FIRST failing check, in order: "malformed", "signer", "signature", "record", "binding", "expired" (valid THROUGH exp
// inclusive), else "ok". Never panics.
func UndoTokenCheck(token any, expectedSigner string, rec UndoTokenRecord, now int64) (code string) {
	defer func() {
		if recover() != nil {
			code = "malformed"
		}
	}()
	t, ok := token.(map[string]any)
	if !ok || len(t) != len(undoTokenMembers) {
		return "malformed"
	}
	for _, k := range undoTokenMembers {
		if _, has := t[k]; !has {
			return "malformed"
		}
	}
	_, audOK := t["aud"].(string)
	_, prOK := t["principal"].(string)
	_, cdOK := t["compensation_digest"].(string)
	_, rdOK := t["render_digest"].(string)
	signer, sgOK := t["signer"].(string)
	sig, sigOK := t["sig"].(string)
	if v, isNum := jsNum(t["v"]); !isNum || v != 1 || t["kind"] != UndoTokenKind || !undoIDOk(t["record"]) || !audOK || !prOK || !cdOK || !rdOK ||
		!jsIsInt(t["exp"]) || !sgOK || !sigOK {
		return "malformed"
	}
	if _, ok := DecodeB64uStrict(sig, sigLen); !ok {
		return "malformed"
	}
	if signer != expectedSigner {
		return "signer"
	}
	if !undoDomainVerify(UndoTokenDomain, expectedSigner, withoutKeys(t, "sig"), sig) {
		return "signature"
	}
	if t["record"] != any(rec.ID) {
		return "record"
	}
	exp, _ := jsNum(t["exp"])
	if t["aud"] != any(rec.Aud) || t["principal"] != any(rec.Principal) || t["compensation_digest"] != any(rec.CompensationDigest) ||
		t["render_digest"] != any(rec.RenderDigest) || exp != float64(rec.WindowEnd) {
		return "binding"
	}
	if now > maxSafeInt || now < -maxSafeInt || float64(now) > exp {
		return "expired"
	}
	return "ok"
}

// EncodeUndoToken is the token as a URL-safe string: base64url of its strict canonical JSON.
func EncodeUndoToken(t map[string]any) (string, error) {
	b, err := canonBytes(normalizeJSON(t))
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(b), nil
}

// DecodeUndoToken is the inverse of EncodeUndoToken: nil for anything that is not a non-empty string of at most 4096
// characters holding strict base64url of UTF-8 JSON of an object.
func DecodeUndoToken(s string) map[string]any {
	if s == "" || jsLen(s) > 4096 {
		return nil
	}
	b, ok := DecodeB64uStrict(s, -1)
	if !ok || !utf8.Valid(b) {
		return nil
	}
	v, err := ParseJSONLenient(b)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

// UndoTokenDigest = hashCanonical({d: "atlas-pca/undo-token-ref/v1", t}).
func UndoTokenDigest(t map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": UndoTokenRefDomain, "t": normalizeJSON(t)})
}

// ---- receipts ---------------------------------------------------------------------------------------------------------------

// UndoReceiptBody is what a receipt of one transition says: State is the state AFTER the event, Prev the previous receipt's
// digest ("" for the first), Note a short machine reason ("" when none).
type UndoReceiptBody struct {
	Record             string
	Event              string
	State              string
	At                 int64
	CompensationDigest string
	Prev               string
	Note               string
}

// SignUndoReceipt signs a receipt (exactly 11 members) under the undo service key.
func SignUndoReceipt(b UndoReceiptBody, key *KeyPair) (map[string]any, error) {
	if key == nil {
		return nil, fmt.Errorf("signer_missing: the undo service key is required")
	}
	return undoSign(UndoReceiptDomain, map[string]any{"v": 1, "kind": UndoReceiptKind, "record": b.Record, "event": b.Event, "state": b.State,
		"at": b.At, "compensation_digest": b.CompensationDigest, "prev": b.Prev, "note": b.Note, "signer": key.Public}, key)
}

// VerifyUndoReceipt is true iff r is well formed (known event and state, a valid record id, exactly 11 members, signer ==
// expectedSigner, a canonical 64-byte signature) and signed by expectedSigner over exactly its content. Never panics.
func VerifyUndoReceipt(r any, expectedSigner string) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	x, isObj := r.(map[string]any)
	if !isObj {
		return false
	}
	ev, _ := x["event"].(string)
	st, _ := x["state"].(string)
	_, cdOK := x["compensation_digest"].(string)
	_, prevOK := x["prev"].(string)
	_, noteOK := x["note"].(string)
	sig, sigOK := x["sig"].(string)
	if v, isNum := jsNum(x["v"]); !isNum || v != 1 || x["kind"] != UndoReceiptKind || !undoIDOk(x["record"]) || !contains(undoEvents, ev) ||
		!contains(undoStates, st) || !jsIsInt(x["at"]) || !cdOK || !prevOK || !noteOK || x["signer"] != any(expectedSigner) || !sigOK {
		return false
	}
	if _, ok := DecodeB64uStrict(sig, sigLen); !ok || len(x) != 11 {
		return false
	}
	return undoDomainVerify(UndoReceiptDomain, expectedSigner, withoutKeys(x, "sig"), sig)
}

// UndoReceiptDigest = hashCanonical({d: "atlas-pca/undo-receipt-ref/v1", r}) (r with its signature): the next receipt's prev.
func UndoReceiptDigest(r map[string]any) (string, error) {
	return HashCanonical(map[string]any{"d": UndoReceiptRefDomain, "r": normalizeJSON(r)})
}

// UndoChainRecord is the part of an undo record its receipt chain is checked against.
type UndoChainRecord struct {
	ID                 string
	CompensationDigest string
	State              string
	Receipts           []any
}

// UndoReceiptChainError verifies a record's receipt chain: "" iff the list is non-empty, every receipt verifies under signer,
// names this record and its compensation digest, links prev to the previous receipt's digest ("" first), the first event is
// `opened`, `at` never decreases, and the last receipt's state is the record's state. Otherwise the reason.
func UndoReceiptChainError(rec UndoChainRecord, signer string) string {
	if len(rec.Receipts) == 0 {
		return "no receipts"
	}
	prev := ""
	at := math.Inf(-1)
	var last map[string]any
	for i, x := range rec.Receipts {
		if !VerifyUndoReceipt(x, signer) {
			return fmt.Sprintf("receipt %d does not verify", i)
		}
		r := x.(map[string]any)
		if r["record"] != any(rec.ID) || r["compensation_digest"] != any(rec.CompensationDigest) {
			return fmt.Sprintf("receipt %d is for another record", i)
		}
		if r["prev"] != any(prev) {
			return fmt.Sprintf("receipt %d does not link to the previous one", i)
		}
		if i == 0 && r["event"] != "opened" {
			return "the first receipt is not opened"
		}
		ra, _ := jsNum(r["at"])
		if ra < at {
			return fmt.Sprintf("receipt %d goes back in time", i)
		}
		d, err := UndoReceiptDigest(r)
		if err != nil {
			return fmt.Sprintf("receipt %d is not canonical", i)
		}
		prev, at, last = d, ra, r
	}
	if last["state"] != any(rec.State) {
		return "the last receipt does not state the record state"
	}
	return ""
}

// ---- the pure transitions -----------------------------------------------------------------------------------------------------

// UndoTransitionResult is the outcome of UndoTransition. Outcome "applied": Record is the next record (ver + 1; the receipt
// NOT yet appended: Event and Note are what the store layer signs and links). "replayed": the same transition already happened
// (Record is the record unchanged; nothing to write). "refused": Code ("window_closed", "window_open", "finalized",
// "not_vetoed", "vetoed", "effect_recorded", "not_failed", "invalid") and Reason.
type UndoTransitionResult struct {
	Outcome string
	Code    string
	Reason  string
	Record  map[string]any
	Event   string
	Note    string
}

func undoRefused(code, reason string) UndoTransitionResult {
	return UndoTransitionResult{Outcome: "refused", Code: code, Reason: reason}
}

// undoReasonText is String(reason) of the reference for the values a reason can be (absent: "undefined").
func undoReasonText(ev map[string]any) string {
	v, has := ev["reason"]
	if !has {
		return "undefined"
	}
	if s, ok := v.(string); ok {
		return s
	}
	// shortcut: a non-string reason is printed as its lenient canonical JSON (JavaScript String() differs for objects);
	// the reason is a free-text note, never decided on
	s, _ := canonicalLenient(v)
	return s
}

// UndoTransition is the record state machine, pure: record (JSON: state, window_end, ver, attempt, effect?, outcome?.status)
// is not modified; event is {kind: veto {veto: {at, via, by}} | finalize | abort {reason} | effect {result?} | compensated
// {result?} | compensation_failed {reason} | retry}; now is the trusted server clock (epoch ms; anything but a safe integer
// is refused). Never panics.
func UndoTransition(record any, event any, now float64) (res UndoTransitionResult) {
	defer func() {
		if recover() != nil {
			res = undoRefused("invalid", "evaluation error (fail closed)")
		}
	}()
	rec, ok := record.(map[string]any)
	st, _ := rec["state"].(string)
	if !ok || !contains(undoStates, st) || !jsIsInt(rec["window_end"]) || !jsIsInt(rec["ver"]) {
		return undoRefused("invalid", "malformed record")
	}
	if !jsIsInt(now) {
		return undoRefused("invalid", "now must be a safe integer")
	}
	windowEnd, _ := jsNum(rec["window_end"])
	ver, _ := jsNum(rec["ver"])
	next := func(patch map[string]any, ev, note string) UndoTransitionResult {
		n := normalizeJSON(rec).(map[string]any)
		for k, v := range patch {
			n[k] = v
		}
		n["ver"] = jsNumber(ver + 1)
		return UndoTransitionResult{Outcome: "applied", Record: n, Event: ev, Note: note}
	}
	replayed := UndoTransitionResult{Outcome: "replayed", Record: rec}
	at := jsNumber(now)
	ev, _ := event.(map[string]any)
	_, hasEffect := rec["effect"]
	switch ev["kind"] {
	case "veto":
		v, isObj := ev["veto"].(map[string]any)
		via, _ := v["via"].(string)
		by, _ := v["by"].(string)
		if !isObj || !jsIsInt(v["at"]) || !contains(vetoVias, via) || by == "" {
			return undoRefused("invalid", "malformed veto")
		}
		switch {
		case st == "vetoed" || st == "compensated" || st == "compensation_failed":
			return replayed
		case st == "finalized":
			return undoRefused("finalized", "the window is closed and the action is final")
		case now > windowEnd:
			return undoRefused("window_closed", "the veto window closed at "+jsNumberString(windowEnd))
		}
		return next(map[string]any{"state": "vetoed", "veto": normalizeJSON(v)}, "vetoed", via)
	case "finalize":
		switch {
		case st == "finalized":
			return replayed
		case st != "open":
			return undoRefused("vetoed", "a "+st+" record is not finalized")
		case now <= windowEnd:
			return undoRefused("window_open", "the veto window is open until "+jsNumberString(windowEnd))
		}
		return next(map[string]any{"state": "finalized", "outcome": map[string]any{"at": at, "status": "finalized"}}, "finalized", "")
	case "abort":
		outcome, _ := rec["outcome"].(map[string]any)
		switch {
		case st == "finalized" && outcome["status"] == "aborted":
			return replayed
		case st != "open" && st != "vetoed":
			return undoRefused("finalized", "a "+st+" record cannot be aborted")
		case hasEffect:
			return undoRefused("effect_recorded", "the effect ran: it can only be compensated or finalized")
		}
		why := undoReasonText(ev)
		return next(map[string]any{"state": "finalized", "outcome": map[string]any{"at": at, "status": "aborted", "reason": truncUnits(why, 512)}},
			"aborted", truncUnits(why, 128))
	case "effect":
		switch {
		case hasEffect:
			return replayed
		case st != "open" && st != "vetoed":
			return undoRefused("finalized", "a "+st+" record takes no effect report")
		}
		eff := map[string]any{"at": at}
		if r, has := ev["result"]; has {
			eff["result"] = normalizeJSON(r)
		}
		return next(map[string]any{"effect": eff}, "effect", "")
	case "compensated":
		switch {
		case st == "compensated":
			return replayed
		case st != "vetoed" && st != "compensation_failed":
			return undoRefused("not_vetoed", "a "+st+" record is not being compensated")
		}
		out := map[string]any{"at": at, "status": "compensated"}
		if r, has := ev["result"]; has {
			out["result"] = normalizeJSON(r)
		}
		return next(map[string]any{"state": "compensated", "outcome": out}, "compensated", "")
	case "compensation_failed":
		switch {
		case st == "compensation_failed":
			return replayed
		case st != "vetoed":
			return undoRefused("not_vetoed", "a "+st+" record is not being compensated")
		}
		why := undoReasonText(ev)
		return next(map[string]any{"state": "compensation_failed", "outcome": map[string]any{"at": at, "status": "compensation_failed", "reason": truncUnits(why, 512)}},
			"compensation_failed", truncUnits(why, 128))
	case "retry":
		if st != "compensation_failed" {
			return undoRefused("not_failed", "a "+st+" record is not retried")
		}
		attempt, isNum := jsNum(rec["attempt"])
		if !isNum {
			return undoRefused("invalid", "malformed record")
		}
		return next(map[string]any{"state": "vetoed", "attempt": jsNumber(attempt + 1)}, "retried", "")
	}
	return undoRefused("invalid", "unknown event")
}

// ---- the window ----------------------------------------------------------------------------------------------------------------

// UndoWindowPolicy is the host's window policy; nil members take the defaults (min 30 s, max 24 h, default 15 min).
type UndoWindowPolicy struct {
	MinMs     *float64
	MaxMs     *float64
	DefaultMs *float64
}

// ResolveUndoWindow clamps a requested window (nil, NaN or infinite = the default) into [max(30000, MinMs), min(MaxMs, 24 h)]
// (a max below the min is the min) and floors it.
func ResolveUndoWindow(requested *float64, p UndoWindowPolicy) int64 {
	or := func(v *float64, d float64) float64 {
		if v == nil {
			return d
		}
		return *v
	}
	min := math.Max(UndoMinWindowMs, or(p.MinMs, UndoMinWindowMs))
	max := math.Max(min, math.Min(or(p.MaxMs, UndoMaxWindowMs), UndoMaxWindowMs))
	want := or(p.DefaultMs, UndoDefaultWindowMs)
	if requested != nil && !math.IsNaN(*requested) && !math.IsInf(*requested, 0) {
		want = *requested
	}
	return int64(math.Floor(math.Min(max, math.Max(min, want))))
}

// undoWindowObligation is the `undo_window` obligation of an admission: {kind, params: {id, window_end}, due: window_end}.
func undoWindowObligation(a *UndoAdmission) (map[string]any, bool) {
	we, ok := safeIntNumber(a.WindowEnd)
	if !ok {
		return nil, false
	}
	o := map[string]any{"kind": "undo_window", "params": map[string]any{"id": a.ID, "window_end": we}, "due": we}
	return o, ObligationError(o) == ""
}

// ---- the admission hook (Authorize) --------------------------------------------------------------------------------------------

// UndoAdmitInput is what an undo admission hook decides on: the verified PCActn, the grant and the bound operation.
type UndoAdmitInput struct {
	PCActn    map[string]any
	Grant     map[string]any
	Operation Operation
}

// UndoAdmission is a veto window opened for an escalated action: ID is the undo record id (the operation id), WindowEnd the
// epoch ms the window closes, Compensation the compensating action (at least Verb and Resource).
//
// CONTRACT: the hook (AuthorizeInput.Undo) returns an admission ONLY after the window's record is durably opened by the
// caller's undo coordinator (the TypeScript coordinator or the hosted ledger). An error or a panic from the hook is no
// admission: the escalation stands.
type UndoAdmission struct {
	ID           string
	WindowEnd    int64
	Compensation UndoCompensation
}

// callUndoAdmit runs the hook; an error, a panic, nil or an admission whose obligation would be malformed is no admission.
func callUndoAdmit(f func(UndoAdmitInput) (*UndoAdmission, error), a UndoAdmitInput) (adm *UndoAdmission, obligation map[string]any) {
	defer func() {
		if recover() != nil {
			adm, obligation = nil, nil
		}
	}()
	got, err := f(a)
	if err != nil || got == nil {
		return nil, nil
	}
	c := *got
	o, ok := undoWindowObligation(&c)
	if !ok {
		return nil, nil
	}
	return &c, o
}
