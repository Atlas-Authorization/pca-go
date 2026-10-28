package pca

// What you see is what you sign (track K7): a port of packages/pca/src/approval-render.ts (render shape, H(R), the approval
// challenge, the speakable match code) and packages/pca-actions/src/approval-render.ts + approval-profiles.ts (the canonical render of an
// action, the PSD2 RTS Art. 5 linking view, the batch commitment). Errors are "<code>: <reason>" like the action kit's.

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
)

const (
	// ApprovalRenderDomain separates H(R) from every other digest.
	ApprovalRenderDomain = "atlas-pca/approval-render/v1"
	// ApprovalChallengeDomain prefixes the approval challenge preimage.
	ApprovalChallengeDomain = "atlas-pca/approval-challenge/v1\x00"
	// ApprovalBatchDomain separates the batch summary digest.
	ApprovalBatchDomain = "atlas-pca/approval-batch/v1"
	approvalItemDomain  = "atlas-pca/approval-batch-item/v1"
	approvalPayeeDomain = "atlas-pca/approval-payee/v1"
	maxRenderFields     = 64
	maxParamPathDepth   = 3
)

var bindingWords = [256]string{
	"able", "acid", "aged", "also", "area", "army", "atom", "aunt",
	"away", "baby", "back", "ball", "band", "bank", "base", "bath",
	"bear", "beat", "beef", "bell", "belt", "bend", "bird", "blue",
	"boat", "body", "bold", "bone", "book", "boot", "born", "both",
	"bowl", "bulb", "burn", "bush", "busy", "cafe", "cake", "calm",
	"camp", "card", "care", "cart", "case", "cash", "cast", "cave",
	"cell", "chat", "chef", "chip", "city", "clay", "clip", "club",
	"coal", "coat", "code", "coin", "cold", "cook", "cool", "cope",
	"copy", "cord", "core", "cost", "crew", "crop", "dark", "data",
	"date", "dawn", "deal", "dear", "deck", "deep", "deer", "desk",
	"dial", "dice", "diet", "dish", "dive", "door", "dose", "down",
	"draw", "drop", "drum", "duck", "dust", "duty", "each", "earn",
	"east", "easy", "edge", "echo", "else", "even", "ever", "exit",
	"face", "fact", "fair", "fall", "farm", "fast", "fate", "fern",
	"file", "fill", "film", "find", "fine", "fire", "firm", "fish",
	"five", "flag", "flat", "flow", "foam", "fold", "folk", "food",
	"foot", "fork", "form", "fort", "four", "free", "frog", "fuel",
	"full", "fund", "gain", "game", "gate", "gear", "gift", "girl",
	"glad", "glow", "goat", "gold", "golf", "good", "grab", "gray",
	"grid", "grip", "grow", "gulf", "hair", "half", "hall", "hand",
	"hard", "harp", "hawk", "head", "heat", "help", "herb", "hill",
	"hint", "hold", "hole", "home", "hood", "hook", "hope", "horn",
	"host", "hour", "huge", "hunt", "idea", "inch", "iron", "isle",
	"item", "jade", "jazz", "join", "joke", "jump", "jury", "just",
	"keen", "keep", "kind", "king", "kite", "knee", "knot", "lake",
	"lamp", "land", "lane", "last", "late", "lawn", "lead", "leaf",
	"lean", "left", "lens", "less", "lift", "lime", "line", "link",
	"lion", "list", "live", "load", "loan", "lock", "logo", "long",
	"loop", "lord", "loud", "love", "luck", "lung", "made", "mail",
	"main", "mask", "mass", "mate", "meal", "melt", "menu", "mild",
	"milk", "mind", "mint", "mole", "moon", "more", "moss", "move",
	"much", "nail", "navy", "neat", "neck", "nest", "news", "nice",
}

func renderDigestOK(v any) bool { return b64uOK(v, 32) }

func renderU16less(a, b string) bool { return compareUnits(utf16Units(a), utf16Units(b)) < 0 }

func renderBoundedStr(v any, n int) bool {
	s, ok := v.(string)
	return ok && len(s) > 0 && len(s) <= n
}

func renderClosedKeys(m map[string]any, required []string, optional []string, where string) string {
	for k := range m {
		ok := false
		for _, r := range required {
			ok = ok || r == k
		}
		for _, o := range optional {
			ok = ok || o == k
		}
		if !ok {
			return "unknown member '" + where + "." + k + "'"
		}
	}
	for _, r := range required {
		if _, has := m[r]; !has {
			return "missing member '" + where + "." + r + "'"
		}
	}
	return ""
}

// ApprovalRenderShapeError is "" for a well-formed render (closed members, sorted unique ids, bounded), else the reason.
func ApprovalRenderShapeError(rv any) string {
	r, ok := normalizeJSON(rv).(map[string]any)
	if !ok {
		return "render must be an object"
	}
	if e := renderClosedKeys(r, []string{"v", "kind", "verb", "def_digest", "unreviewed", "fields"}, nil, "render"); e != "" {
		return e
	}
	if v, ok := safeInt(r["v"]); !ok || v != 1 || r["kind"] != "pca-approval-render" {
		return "not a pca-approval-render v1"
	}
	if !renderBoundedStr(r["verb"], 128) {
		return "verb must be a bounded string"
	}
	if !renderDigestOK(r["def_digest"]) {
		return "def_digest must be canonical base64url (32 bytes)"
	}
	if _, ok := r["unreviewed"].(bool); !ok {
		return "unreviewed must be a boolean"
	}
	fs, ok := r["fields"].([]any)
	if !ok || len(fs) > maxRenderFields {
		return fmt.Sprintf("fields must be an array of at most %d", maxRenderFields)
	}
	prev := ""
	for i, fv := range fs {
		f, ok := fv.(map[string]any)
		if !ok {
			return "a field must be an object"
		}
		if e := renderClosedKeys(f, []string{"id", "class", "value"}, []string{"unit"}, "field"); e != "" {
			return e
		}
		if !renderBoundedStr(f["id"], 192) || !renderBoundedStr(f["class"], 128) {
			return "field id and class must be bounded strings"
		}
		id := f["id"].(string)
		if i > 0 && !renderU16less(prev, id) {
			return "fields must be sorted by id and unique"
		}
		prev = id
		if uv, has := f["unit"]; has {
			u, ok := uv.(map[string]any)
			if !ok {
				return "unit must be an object"
			}
			switch u["kind"] {
			case "money":
				exp, eok := safeInt(u["exp"])
				if renderClosedKeys(u, []string{"kind", "ccy", "exp"}, nil, "unit") != "" || !renderBoundedStr(u["ccy"], 16) || !eok || exp < 0 || exp > 18 {
					return "a money unit needs ccy and exp"
				}
			case "count", "bytes", "duration", "ratio":
				if renderClosedKeys(u, []string{"kind"}, nil, "unit") != "" {
					return "unknown unit"
				}
			default:
				return "unknown unit"
			}
		}
	}
	return ""
}

// ApprovalRenderDigest is H(R). A malformed render is an error (a digest is never made over a shapeless value).
func ApprovalRenderDigest(render any) (string, error) {
	if e := ApprovalRenderShapeError(render); e != "" {
		return "", fmt.Errorf("approvalRenderDigest: %s", e)
	}
	return HashCanonical(map[string]any{"d": ApprovalRenderDomain, "render": render})
}

// ApprovalChallenge is b64u(SHA-256(domain || action_digest || H(R))); both digests must be canonical 32-byte values.
func ApprovalChallenge(actionDigest, renderDigest string) (string, error) {
	a, ok1 := DecodeB64uStrict(actionDigest, 32)
	r, ok2 := DecodeB64uStrict(renderDigest, 32)
	if !ok1 || !ok2 {
		return "", fmt.Errorf("approvalChallenge: both digests must be canonical 32-byte values")
	}
	buf := append(append([]byte(ApprovalChallengeDomain), a...), r...)
	h := sha256.Sum256(buf)
	return b64.EncodeToString(h[:]), nil
}

// BindingWords is the speakable match code of a render digest (six words).
func BindingWords(renderDigest string) (string, error) {
	r, ok := DecodeB64uStrict(renderDigest, 32)
	if !ok {
		return "", fmt.Errorf("bindingWords: render digest must be a canonical 32-byte value")
	}
	w := make([]string, 6)
	for i := range w {
		w[i] = bindingWords[r[i]]
	}
	return strings.Join(w, "-"), nil
}

// ---- the render --------------------------------------------------------------------------------------------------------

func flattenForRender(params map[string]any) (map[string]any, error) {
	out := map[string]any{}
	var walk func(prefix string, depth int, v any) error
	walk = func(prefix string, depth int, v any) error {
		if m, ok := v.(map[string]any); ok && depth < maxParamPathDepth && len(m) > 0 {
			for k, x := range m {
				if strings.Contains(k, ".") {
					return fmt.Errorf("render_bad_params: the parameter key '%s' contains a dot", k)
				}
				np := k
				if prefix != "" {
					np = prefix + "." + k
				}
				if err := walk(np, depth+1, x); err != nil {
					return err
				}
			}
			return nil
		}
		out[prefix] = v
		return nil
	}
	for k, v := range params {
		if strings.Contains(k, ".") {
			return nil, fmt.Errorf("render_bad_params: the parameter key '%s' contains a dot", k)
		}
		if err := walk(k, 1, v); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func renderLeafOK(v any) bool {
	switch t := v.(type) {
	case string:
		return !hasLoneSurrogate(t)
	case bool:
		return true
	case []any:
		for _, x := range t {
			if !renderLeafOK(x) {
				return false
			}
		}
		return true
	}
	return jsIsInt(v)
}

func renderValueOK(typ string, v any) bool {
	switch typ {
	case "integer", "duration":
		return jsIsInt(v)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "string", "date", "datetime", "object_ref":
		s, ok := v.(string)
		return ok && !hasLoneSurrogate(s)
	case "set", "array":
		a, ok := v.([]any)
		if !ok {
			return false
		}
		for _, x := range a {
			if !renderLeafOK(x) {
				return false
			}
		}
		return true
	}
	return false
}

// RenderApproval is the canonical approval render of def for params. confirmed is whether the definition carries a valid signed
// confirmation (the caller decides, as for effective); an unconfirmed render carries unreviewed: true. Errors: render_bad_params,
// render_undeclared_param, render_missing_param, render_bad_value, render_unresolved_currency.
func RenderApproval(def map[string]any, paramsAny any, confirmed bool) (map[string]any, error) {
	params, ok := normalizeJSON(paramsAny).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("render_bad_params: params must be an object")
	}
	n := normalizeDef(def)
	np := n["params"].(map[string]any)
	flat, err := flattenForRender(params)
	if err != nil {
		return nil, err
	}
	for k := range flat {
		if _, has := np[k]; !has {
			return nil, fmt.Errorf("render_undeclared_param: '%s' is not a parameter of %v", k, n["verb"])
		}
	}
	for k, pv := range np {
		if req, _ := pv.(map[string]any)["required"].(bool); req {
			if _, has := flat[k]; !has {
				return nil, fmt.Errorf("render_missing_param: required parameter '%s' of %v is missing", k, n["verb"])
			}
		}
	}
	ids := make([]string, 0, len(flat))
	for k := range flat {
		ids = append(ids, k)
	}
	sort.Slice(ids, func(i, j int) bool { return renderU16less(ids[i], ids[j]) })
	fields := make([]any, 0, len(ids))
	for _, id := range ids {
		p := np[id].(map[string]any)
		if !renderValueOK(p["type"].(string), flat[id]) {
			return nil, fmt.Errorf("render_bad_value: '%s' is not a %v in the canonical domain", id, p["type"])
		}
		class := "param"
		if r, ok := p["role"].(string); ok {
			class = r
		}
		f := map[string]any{"id": id, "class": class, "value": flat[id]}
		if u, ok := p["unit"].(map[string]any); ok {
			if u["kind"] == "money" {
				var ccy any
				if s, ok := u["ccy"].(string); ok {
					ccy = s
				} else if ref, ok := u["ccy"].(map[string]any); ok {
					ccy = flat[fmt.Sprint(ref["from"])]
				}
				cs, ok := ccy.(string)
				if !ok || cs == "" {
					return nil, fmt.Errorf("render_unresolved_currency: the currency of '%s' is not a string", id)
				}
				f["unit"] = map[string]any{"kind": "money", "ccy": cs, "exp": u["exp"]}
			} else {
				f["unit"] = map[string]any{"kind": u["kind"]}
			}
		}
		fields = append(fields, f)
	}
	dd, err := defDigest(def)
	if err != nil {
		return nil, err
	}
	return map[string]any{"v": 1, "kind": "pca-approval-render", "verb": n["verb"], "def_digest": dd, "unreviewed": !confirmed, "fields": fields}, nil
}

// ---- PSD2 RTS Art. 5 ---------------------------------------------------------------------------------------------------------

// Psd2Linking extracts the amount and the payee of a payment render (Art. 5(1)). Error code psd2_unlinkable.
func Psd2Linking(r map[string]any) (map[string]any, error) {
	bad := func(m string) (map[string]any, error) { return nil, fmt.Errorf("psd2_unlinkable: %s", m) }
	if u, _ := r["unreviewed"].(bool); u {
		return bad("an unreviewed definition cannot be a payment approval")
	}
	fs, _ := r["fields"].([]any)
	var amts, payees []map[string]any
	for _, fv := range fs {
		f := fv.(map[string]any)
		switch f["class"] {
		case "money.amount":
			amts = append(amts, f)
		case "party.payee":
			payees = append(payees, f)
		}
	}
	if len(amts) != 1 {
		return bad("a payment approval needs exactly one money.amount parameter")
	}
	a := amts[0]
	u, _ := a["unit"].(map[string]any)
	if u == nil || u["kind"] != "money" {
		return bad("the money.amount parameter has no money unit")
	}
	if !jsIsInt(a["value"]) || jsF(a["value"]) < 0 {
		return bad("the amount must be a non-negative integer in minor units")
	}
	if len(payees) != 1 {
		return bad("a payment approval needs exactly one non-empty party.payee parameter")
	}
	if s, ok := payees[0]["value"].(string); !ok || s == "" {
		return bad("a payment approval needs exactly one non-empty party.payee parameter")
	}
	return map[string]any{"amount_minor": a["value"], "currency": u["ccy"], "exp": u["exp"], "payee": payees[0]["value"]}, nil
}

// MinorToDecimal formats minor units as a decimal string of the major unit without floating point.
func MinorToDecimal(minor, exp int64) (string, error) {
	if minor < 0 || exp < 0 || exp > 18 {
		return "", fmt.Errorf("psd2_unlinkable: minor units must be a non-negative safe integer")
	}
	s := fmt.Sprint(minor)
	if exp == 0 {
		return s, nil
	}
	for int64(len(s)) < exp+1 {
		s = "0" + s
	}
	return s[:int64(len(s))-exp] + "." + s[int64(len(s))-exp:], nil
}

// ApprovalBatch commits one approval over N payments: per-currency totals, the payee set and every item (Art. 5(3)(b)).
func ApprovalBatch(itemsAny []any) (map[string]any, error) {
	if len(itemsAny) == 0 {
		return nil, fmt.Errorf("psd2_unlinkable: a batch needs at least one payment")
	}
	type tot struct{ exp, minor int64 }
	totals := map[string]*tot{}
	payees := map[string]bool{}
	itemLeaves := make([]any, 0, len(itemsAny))
	for _, iv := range itemsAny {
		it, _ := iv.(map[string]any)
		render, _ := it["render"].(map[string]any)
		link, err := Psd2Linking(render)
		if err != nil {
			return nil, err
		}
		ccy := link["currency"].(string)
		exp, _ := safeInt(link["exp"])
		amt, _ := safeInt(link["amount_minor"])
		t := totals[ccy]
		if t != nil && t.exp != exp {
			return nil, fmt.Errorf("psd2_unlinkable: currency %s appears with two exponents", ccy)
		}
		var cur int64
		if t != nil {
			cur = t.minor
		}
		if amt > maxSafeInt-cur {
			return nil, fmt.Errorf("psd2_unlinkable: the batch total exceeds the safe integer range")
		}
		totals[ccy] = &tot{exp: exp, minor: cur + amt}
		payees[link["payee"].(string)] = true
		rd, err := ApprovalRenderDigest(render)
		if err != nil {
			return nil, err
		}
		itemLeaves = append(itemLeaves, map[string]any{"d": approvalItemDomain, "a": it["action_digest"], "r": rd})
	}
	ccys := make([]string, 0, len(totals))
	for c := range totals {
		ccys = append(ccys, c)
	}
	sort.Slice(ccys, func(i, j int) bool { return renderU16less(ccys[i], ccys[j]) })
	tl := make([]any, 0, len(ccys))
	for _, c := range ccys {
		tl = append(tl, map[string]any{"ccy": c, "exp": jsonNumberOf(totals[c].exp), "minor": jsonNumberOf(totals[c].minor)})
	}
	pl := make([]string, 0, len(payees))
	for p := range payees {
		pl = append(pl, p)
	}
	sort.Slice(pl, func(i, j int) bool { return renderU16less(pl[i], pl[j]) })
	pleaves := make([]any, len(pl))
	for i, p := range pl {
		pleaves[i] = map[string]any{"d": approvalPayeeDomain, "payee": p}
	}
	pr, err := MerkleRoot(pleaves)
	if err != nil {
		return nil, err
	}
	ir, err := MerkleRoot(itemLeaves)
	if err != nil {
		return nil, err
	}
	batch := map[string]any{"v": 1, "kind": "pca-approval-batch", "n": jsonNumberOf(int64(len(itemsAny))), "totals": tl, "payees_root": pr, "items_root": ir}
	rd, err := HashCanonical(map[string]any{"d": ApprovalBatchDomain, "batch": batch})
	if err != nil {
		return nil, err
	}
	ch, err := ApprovalChallenge(ir, rd)
	if err != nil {
		return nil, err
	}
	w, err := BindingWords(rd)
	if err != nil {
		return nil, err
	}
	return map[string]any{"batch": batch, "action_digest": ir, "render_digest": rd, "challenge": ch, "words": w}, nil
}
