package pca

// K5 read-side authorization, verification side: what an agent may SEE (RedactRead) and where the data may go next (CheckSink,
// ReadChainLabels). A line-by-line port of packages/pca/src/readside.ts; replays packages/pca/conformance/readside-vectors.json.
// TIGHTEN-ONLY: a caller may ask for a STRICTER mode than the grant gives; a weaker request is ignored. Pure and total: anything
// malformed, unsigned, unknown or out of scope DENIES. Integers only. Inputs are decoded JSON (ParseJSONLenient).

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	k5ReadGrantDomain   = "atlas-pca/read-grant/v1\x00"
	k5ReadReceiptDomain = "atlas-pca/read-receipt/v1\x00"
	k5RgRef             = "atlas-pca/read-grant-ref/v1"
	k5RrRef             = "atlas-pca/read-receipt-ref/v1"
	k5RH                = "atlas-pca/read-hash/v1"
	k5RT                = "atlas-pca/read-token/v1"
	k5RV                = "atlas-pca/read-value/v1"
	k5SaltMin           = 16
)

var k5ModeRe = regexp.MustCompile(`^(show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})$`)

func k5IsMode(x any) bool { s, ok := x.(string); return ok && k5ModeRe.MatchString(s) }

var k5Rank = map[string]int{"show": 0, "last4": 1, "bucket": 2, "token": 3, "hash": 4, "drop": 5}

func k5ModeRank(m string) int {
	if strings.HasPrefix(m, "bucket:") {
		return k5Rank["bucket"]
	}
	return k5Rank[m]
}

func k5ValidEntry(x any) bool {
	e, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(e, "verb", "resource_prefix", "purposes", "modes", "default_mode") || !k3Str(e["verb"], 128) || !k3Str(e["resource_prefix"], 512) || !k5SortedUnique(e["purposes"], k5ID, 16) || len(e["purposes"].([]any)) == 0 {
		return false
	}
	modes, ok := k5Obj(e["modes"])
	if !ok || len(modes) > 32 || !k5IsMode(e["default_mode"]) {
		return false
	}
	for k, v := range modes {
		if !k5Label.ok(k) || !k5IsMode(v) {
			return false
		}
	}
	return true
}

func k5ValidReadGrantBody(x any) bool {
	b, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(b, "v", "id", "principal", "issued_at", "expires_at", "reads", "caps", "sinks") {
		return false
	}
	if f, isNum := jsNum(b["v"]); !isNum || f != 1 {
		return false
	}
	if !k5Id(b["id"]) || !k5IsB32(b["principal"]) || !k5IsUint(b["issued_at"]) || !k5IsUint(b["expires_at"]) {
		return false
	}
	reads, ok := b["reads"].([]any)
	if !ok || len(reads) == 0 || len(reads) > 32 {
		return false
	}
	for _, e := range reads {
		if !k5ValidEntry(e) {
			return false
		}
	}
	caps, ok := k5Obj(b["caps"])
	if !ok || len(caps) > 32 {
		return false
	}
	for k, v := range caps {
		if !k5Label.ok(k) || !k5IsUint(v) {
			return false
		}
	}
	sinks, ok := k5Obj(b["sinks"])
	if !ok || len(sinks) > 16 {
		return false
	}
	for k, x := range sinks {
		v, ok := k5Obj(x)
		if !k5ID.ok(k) || !ok || !k5OnlyKeys(v, "allow", "escalate") || !k5SortedUnique(v["allow"], k5Label, 16) || !k5SortedUnique(v["escalate"], k5Label, 16) {
			return false
		}
		esc := k5Strs(v["escalate"])
		for _, l := range k5Strs(v["allow"]) {
			if k5Has(esc, l) {
				return false
			}
		}
	}
	return true
}

// ReadGrantDigest is the content address of a read grant body (what read receipts cite as `grant`).
func ReadGrantDigest(body map[string]any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": k5RgRef, "g": body})
}

// ReadReceiptRef is the digest the next read receipt cites as `prev`.
func ReadReceiptRef(r map[string]any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": k5RrRef, "r": r})
}

func k5ReadReceiptBody(r map[string]any) map[string]any {
	b, _ := extPick(r, "v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer")
	return b
}

// ReadField is what happened to one field: Kind is "" for null; Vd is the salted value digest.
type ReadField struct {
	Class  string
	Action string // shown | masked | dropped
	Kind   string
	Vd     string
}

// ReadResult is the outcome of RedactRead. Counts is the per-class tally (the input counts on a refusal after validation).
type ReadResult struct {
	Decision string // allow | deny | escalate
	Code     string // "" for null
	View     map[string]any
	Fields   map[string]ReadField
	Labels   []string
	Counts   map[string]int64
}

// ReadInput: Grant, Schema ({fields, required}), Record, Tighten and Counts are decoded JSON values; Now is unix ms. Salt is a
// per-read secret of at least 16 characters (UTF-16 units, as the reference counts).
type ReadInput struct {
	Grant     any
	Principal string
	Now       any // unix ms; anything but an unsigned safe integer denies bad_request
	Verb      string
	Resource  string
	Purpose   string
	Schema    any
	Record    any
	Tighten   any
	Salt      string
	Counts    any
}

func k5Out(decision, code string, counts map[string]int64) ReadResult {
	if counts == nil {
		counts = map[string]int64{}
	}
	return ReadResult{decision, code, map[string]any{}, map[string]ReadField{}, []string{}, counts}
}

// k5CountsOf copies validated counts; nil when the input is not (yet) a valid counts object.
func k5CountsOf(x any) map[string]int64 {
	m, _ := k5Obj(x)
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = int64(k5F(v))
	}
	return out
}

func k5GradeGrant(g any, principal string, nowV any) (map[string]any, string) {
	if !k5IsB32(principal) || !k5IsUint(nowV) {
		return nil, "bad_request"
	}
	now := int64(k5F(nowV))
	sg, ok := k5Obj(g)
	if !ok || !k5OnlyKeys(sg, "body", "sig") || !k5ValidReadGrantBody(sg["body"]) {
		return nil, "bad_grant"
	}
	b := sg["body"].(map[string]any)
	if b["principal"] != principal || !k5VerifyBody(k5ReadGrantDomain, b, principal, sg["sig"]) {
		return nil, "bad_signature"
	}
	if float64(now) < k5F(b["issued_at"]) {
		return nil, "not_yet"
	}
	if float64(now) >= k5F(b["expires_at"]) {
		return nil, "expired"
	}
	return b, ""
}

func k5SortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks) // keys are ASCII, so bytewise == the reference's UTF-16 order
	return ks
}

func k5IsBMP(s string) bool {
	for _, r := range s {
		if r >= 0x10000 {
			return false
		}
	}
	return true
}

// RedactRead applies a read grant to one response. Never panics.
func RedactRead(inp ReadInput) (res ReadResult) {
	defer func() {
		if recover() != nil {
			res = k5Out("deny", "bad_request", nil)
		}
	}()
	g, code := k5GradeGrant(inp.Grant, inp.Principal, inp.Now)
	if code != "" {
		return k5Out("deny", code, nil)
	}
	sc, scOK := k5Obj(inp.Schema)
	if !k3Str(inp.Verb, 128) || !k3Str(inp.Resource, 512) || !k5ID.ok(inp.Purpose) || jsLen(inp.Salt) < k5SaltMin {
		return k5Out("deny", "bad_request", nil)
	}
	var fieldsM map[string]any
	if scOK {
		fieldsM, _ = k5Obj(sc["fields"])
	}
	req, reqOK := sc["required"].([]any)
	if !scOK || fieldsM == nil || !reqOK {
		return k5Out("deny", "bad_request", nil)
	}
	for k, v := range fieldsM {
		if !k5Name.ok(k) || !k5Label.ok(v) {
			return k5Out("deny", "bad_request", nil)
		}
	}
	for _, p := range req {
		s, isStr := p.(string)
		if _, has := fieldsM[s]; !isStr || !has {
			return k5Out("deny", "bad_request", nil)
		}
	}
	record, recOK := k5Obj(inp.Record)
	tighten, tOK := k5Obj(inp.Tighten)
	if !k5IsScalarMap(inp.Record) || !recOK || !tOK {
		return k5Out("deny", "bad_request", nil)
	}
	for k, v := range tighten {
		if !k5Label.ok(k) || !k5IsMode(v) {
			return k5Out("deny", "bad_request", nil)
		}
	}
	cm, cOK := k5Obj(inp.Counts)
	if !cOK {
		return k5Out("deny", "bad_request", nil)
	}
	for k, v := range cm {
		if !k5Label.ok(k) || !k5IsUint(v) {
			return k5Out("deny", "bad_request", nil)
		}
	}
	in := k5CountsOf(inp.Counts)
	var entry map[string]any
	for _, x := range g["reads"].([]any) {
		e := x.(map[string]any)
		if e["verb"] == inp.Verb && strings.HasPrefix(inp.Resource, e["resource_prefix"].(string)) && k5Has(k5Strs(e["purposes"]), inp.Purpose) {
			entry = e
			break
		}
	}
	if entry == nil {
		return k5Out("deny", "no_read_scope", in)
	}
	modes := entry["modes"].(map[string]any)
	fields := map[string]ReadField{}
	view := map[string]any{}
	used := map[string]int64{}
	for _, path := range k5SortedKeys(record) {
		v := record[path]
		cls, classified := fieldsM[path].(string)
		// a field the schema does not classify is never shown
		vd := k5Hash(map[string]any{"d": k5RV, "salt": inp.Salt, "p": path, "v": v})
		if !classified {
			fields[path] = ReadField{"unclassified", "dropped", "", vd}
			continue
		}
		mode, _ := entry["default_mode"].(string)
		if m, has := modes[cls].(string); has {
			mode = m
		}
		if t, has := tighten[cls].(string); has && k5ModeRank(t) > k5ModeRank(mode) {
			mode = t
		}
		var shown any
		hasShown := false
		action := "masked"
		kind := mode
		if strings.HasPrefix(mode, "bucket:") {
			kind = "bucket"
		}
		switch {
		case mode == "show":
			shown, hasShown, action, kind = v, true, "shown", ""
		case mode == "last4":
			// the BMP check and the last four count Unicode scalar values, never bytes or UTF-16 units
			if s, isStr := v.(string); isStr && k5IsBMP(s) && utf8.RuneCountInString(s) > 4 {
				rs := []rune(s)
				shown, hasShown = "****"+string(rs[len(rs)-4:]), true
			}
		case strings.HasPrefix(mode, "bucket:"):
			n, _ := strconv.ParseInt(mode[7:], 10, 64)
			if f, isNum := jsNum(v); isNum && f >= 0 {
				iv := int64(f)
				shown, hasShown = json.Number(strconv.FormatInt(iv-iv%n, 10)), true
			}
		case mode == "hash":
			shown, hasShown = k5Hash(map[string]any{"d": k5RH, "salt": inp.Salt, "c": cls, "v": v}), true
		case mode == "token":
			shown, hasShown = "tok_"+k5Hash(map[string]any{"d": k5RT, "salt": inp.Salt, "c": cls, "v": v})[:22], true
		}
		if !hasShown {
			fields[path] = ReadField{cls, "dropped", "", vd}
			continue
		}
		fields[path] = ReadField{cls, action, kind, vd}
		view[path] = shown
		used[cls]++
	}
	counts := make(map[string]int64, len(in))
	for k, v := range in {
		counts[k] = v
	}
	for c, n := range used {
		counts[c] += n
		if cap, has := g["caps"].(map[string]any)[c]; has && float64(counts[c]) > k5F(cap) {
			return k5Out("deny", "read_cap", in)
		}
	}
	for _, p := range req {
		if _, has := view[p.(string)]; !has {
			return k5Out("escalate", "required_dropped", in)
		}
	}
	set := map[string]bool{}
	for _, f := range fields {
		if f.Action != "dropped" {
			set[f.Class] = true
		}
	}
	return ReadResult{"allow", "", view, fields, k5SortedKeys(set), counts}
}

func k5ValidReadReceipt(x any) bool {
	r, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(r, "v", "grant", "verb", "resource", "purpose", "seq", "prev", "fields", "labels", "issued_at", "signer", "sig") {
		return false
	}
	if f, isNum := jsNum(r["v"]); !isNum || f != 1 {
		return false
	}
	if !k5IsB32(r["grant"]) || !k3Str(r["verb"], 128) || !k3Str(r["resource"], 512) || !k5ID.ok(r["purpose"]) || !k5IsUint(r["seq"]) || !k5NullOr(r["prev"], k5Sfx) || (k5F(r["seq"]) == 0) != (r["prev"] == nil) {
		return false
	}
	if !k5IsUint(r["issued_at"]) || !k5IsB32(r["signer"]) || !k5SortedUnique(r["labels"], k5Label, 32) {
		return false
	}
	if _, isStr := r["sig"].(string); !isStr {
		return false
	}
	fs, ok := k5Obj(r["fields"])
	if !ok || len(fs) > 64 {
		return false
	}
	for k, x := range fs {
		f, ok := k5Obj(x)
		if !k5Name.ok(k) || !ok || !k5OnlyKeys(f, "class", "action", "kind", "vd") {
			return false
		}
		cls, isStr := f["class"].(string)
		act, _ := f["action"].(string)
		_, kindStr := f["kind"].(string)
		if !isStr || !(cls == "unclassified" || k5Label.ok(cls)) || (act != "shown" && act != "masked" && act != "dropped") || !(f["kind"] == nil || kindStr) || !k5IsB32(f["vd"]) {
			return false
		}
	}
	return true
}

// ReadChainLabels returns the labels carried by a verified, unbroken chain of read receipts; otherwise code is set and at is the
// offending index.
func ReadChainLabels(receipts any, rsSigner, grantDigest string, now int64) (labels []string, code string, at int) {
	list, ok := receipts.([]any)
	if !ok {
		return nil, "bad_receipt", 0
	}
	all := map[string]bool{}
	var prev map[string]any
	for i, x := range list {
		if !k5ValidReadReceipt(x) {
			return nil, "bad_receipt", i
		}
		r := x.(map[string]any)
		if r["signer"] != rsSigner || r["grant"] != grantDigest || k5F(r["seq"]) != float64(i) || k5F(r["issued_at"]) > float64(now) {
			return nil, "bad_receipt", i
		}
		if prev == nil {
			if r["prev"] != nil {
				return nil, "bad_receipt", i
			}
		} else if ref, ok := ReadReceiptRef(prev); !ok || r["prev"] != ref {
			return nil, "bad_receipt", i
		}
		if !k5VerifyBody(k5ReadReceiptDomain, k5ReadReceiptBody(r), rsSigner, r["sig"]) {
			return nil, "bad_receipt", i
		}
		// the receipt's labels must be exactly the classes of its non-dropped fields: an understated label list would launder data
		want := map[string]bool{}
		for _, f := range r["fields"].(map[string]any) {
			fm := f.(map[string]any)
			if fm["action"] != "dropped" {
				want[fm["class"].(string)] = true
			}
		}
		wl, have := k5SortedKeys(want), k5Strs(r["labels"])
		if len(wl) != len(have) {
			return nil, "bad_receipt", i
		}
		for j := range wl {
			if wl[j] != have[j] {
				return nil, "bad_receipt", i
			}
		}
		for _, l := range have {
			all[l] = true
		}
		prev = r
	}
	return k5SortedKeys(all), "", -1
}

// SinkInput: Grant and Receipts are decoded JSON values.
type SinkInput struct {
	Grant     any
	Principal string
	RsSigner  string
	Now       any
	Sink      string
	Receipts  any
}

// SinkResult is the outcome of CheckSink (Code "" for null).
type SinkResult struct {
	Decision string
	Code     string
	Labels   []string
}

// CheckSink: may data read under these receipts reach Sink? Deny on any label the grant does not allow; escalate on an "ask"
// label. Never panics.
func CheckSink(inp SinkInput) (res SinkResult) {
	no := func(code string) SinkResult { return SinkResult{"deny", code, []string{}} }
	defer func() {
		if recover() != nil {
			res = no("bad_request")
		}
	}()
	g, code := k5GradeGrant(inp.Grant, inp.Principal, inp.Now)
	if code != "" {
		return no(code)
	}
	if !k5IsB32(inp.RsSigner) {
		return no("bad_request")
	}
	now := int64(k5F(inp.Now))
	rule, has := g["sinks"].(map[string]any)[inp.Sink].(map[string]any)
	if !has {
		return no("unknown_sink")
	}
	gd, ok := ReadGrantDigest(g)
	if !ok {
		return no("bad_request")
	}
	labels, ccode, _ := ReadChainLabels(inp.Receipts, inp.RsSigner, gd, now)
	if ccode != "" {
		return no(ccode)
	}
	allow, esc := k5Strs(rule["allow"]), k5Strs(rule["escalate"])
	for _, l := range labels {
		if !k5Has(allow, l) && !k5Has(esc, l) {
			return SinkResult{"deny", "label_flow", labels}
		}
	}
	for _, l := range labels {
		if k5Has(esc, l) {
			return SinkResult{"escalate", "label_escalate", labels}
		}
	}
	return SinkResult{"allow", "", labels}
}
