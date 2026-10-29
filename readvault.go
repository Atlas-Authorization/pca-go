package pca

// K5 tokenisation vault and aggregate read limits (C-315..C-319), verification side. A port of packages/pca/src/read-vault.ts;
// replays packages/pca/conformance/vault-aggregate-vectors.json. Verification only: grants are signed elsewhere. Pure and
// total (no entry point panics): anything malformed, unsigned, unknown or out of scope DENIES. Integers only; the noise sampler
// is integer-exact (Canonne-Kamath-Steinke) over 48-bit draws from SHA-256 blocks, with int64 arithmetic (all values < 2^53).

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const (
	k5AggregateDomain = "atlas-pca/aggregate-grant/v1\x00"
	k5AgRef           = "atlas-pca/aggregate-grant-ref/v1"
	k5AgQ             = "atlas-pca/aggregate-query/v1"
	k5AgN             = "atlas-pca/aggregate-noise/v1"
	k5DpStream        = "atlas-pca/dp-stream/v1"
	k5Two48           = int64(1) << 48
	k5MaxSteps        = 100000
)

// ---- vault -----------------------------------------------------------------------------------------------------------------

// VaultEntry is what a minted token stands for: its class, the value, the grant digest it was minted under and that grant's expiry.
type VaultEntry struct {
	Cls   string
	Value any // string | number | bool, as decoded from the record
	Grant string
	Exp   int64
}

// VaultStore holds minted tokens.
type VaultStore interface {
	Put(token string, e VaultEntry)
	Get(token string) (VaultEntry, bool)
}

type memVault struct {
	mu sync.Mutex
	m  map[string]VaultEntry
}

// NewMemoryVault is an in-process VaultStore.
func NewMemoryVault() VaultStore { return &memVault{m: map[string]VaultEntry{}} }

func (v *memVault) Put(t string, e VaultEntry) { v.mu.Lock(); v.m[t] = e; v.mu.Unlock() }
func (v *memVault) Get(t string) (VaultEntry, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	e, ok := v.m[t]
	return e, ok
}

// RedactReadWithVault is RedactRead that also records every token it minted in store. Never panics.
func RedactReadWithVault(inp ReadInput, store VaultStore) (res ReadResult) {
	defer func() {
		if recover() != nil {
			res = k5Out("deny", "bad_request", nil)
		}
	}()
	r := RedactRead(inp)
	if r.Decision != "allow" || store == nil {
		return r
	}
	g := inp.Grant.(map[string]any)["body"].(map[string]any)
	digest, ok := ReadGrantDigest(g)
	if !ok {
		return k5Out("deny", "bad_request", nil)
	}
	rec := inp.Record.(map[string]any)
	for path, f := range r.Fields {
		if f.Action == "masked" && f.Kind == "token" {
			tok, _ := r.View[path].(string)
			store.Put(tok, VaultEntry{Cls: f.Class, Value: rec[path], Grant: digest, Exp: int64(k5F(g["expires_at"]))})
		}
	}
	return r
}

// DetokenizeInput: Grant and Now are decoded JSON values (Now: unix ms).
type DetokenizeInput struct {
	Grant     any
	Principal string
	Now       any
	Sink      string
	Token     string
	Store     VaultStore
}

// DetokenizeResult: Code is "" for null; Value is nil unless Decision is allow.
type DetokenizeResult struct {
	Decision string
	Code     string
	Value    any
}

// Detokenize turns a token back into its value, only for a sink the grant allows that token's class to reach. Never panics.
func Detokenize(inp DetokenizeInput) (res DetokenizeResult) {
	no := func(code string) DetokenizeResult { return DetokenizeResult{"deny", code, nil} }
	defer func() {
		if recover() != nil {
			res = no("bad_request")
		}
	}()
	g, code := k5GradeGrant(inp.Grant, inp.Principal, inp.Now)
	if code != "" {
		return no(code)
	}
	if inp.Store == nil {
		return no("bad_request")
	}
	gd, ok := ReadGrantDigest(g)
	if !ok {
		return no("bad_request")
	}
	e, has := inp.Store.Get(inp.Token)
	if !has || e.Grant != gd {
		return no("unknown_token")
	}
	if float64(int64(k5F(inp.Now))) >= float64(e.Exp) {
		return no("expired")
	}
	rule, has := g["sinks"].(map[string]any)[inp.Sink].(map[string]any)
	if !has {
		return no("unknown_sink")
	}
	if k5Has(k5Strs(rule["allow"]), e.Cls) {
		return DetokenizeResult{"allow", "", e.Value}
	}
	if k5Has(k5Strs(rule["escalate"]), e.Cls) {
		return DetokenizeResult{"escalate", "label_escalate", nil}
	}
	return no("label_flow")
}

// ---- aggregates ------------------------------------------------------------------------------------------------------------

var k5FnRe = k5Re{regexp.MustCompile(`^(count|sum)$`), false}

func k5ValidAggRule(x any) bool {
	r, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(r, "verb", "resource_prefix", "purposes", "fns", "min_group", "clamp", "epsilon_micro", "dp") ||
		!k3Str(r["verb"], 128) || !k3Str(r["resource_prefix"], 512) || !k5SortedUnique(r["purposes"], k5ID, 16) || len(r["purposes"].([]any)) == 0 ||
		!k5SortedUnique(r["fns"], k5FnRe, 2) || len(r["fns"].([]any)) == 0 || !k5IsUint(r["min_group"]) || k5F(r["min_group"]) < 1 ||
		!k5IsUint(r["clamp"]) || k5F(r["clamp"]) > 1000000 || !k5IsUint(r["epsilon_micro"]) || k5F(r["epsilon_micro"]) > 1073741824 {
		return false
	}
	dp, isBool := r["dp"].(bool)
	return isBool && (!dp || k5F(r["epsilon_micro"]) >= 1)
}

func k5ValidAggGrantBody(x any) bool {
	b, ok := k5Obj(x)
	if !ok || !k5OnlyKeys(b, "v", "id", "principal", "issued_at", "expires_at", "rules", "epsilon_budget_micro", "max_queries") || !k5IsUint(b["v"]) || k5F(b["v"]) != 1 ||
		!k5ID.ok(b["id"]) || !k5IsB32(b["principal"]) || !k5IsUint(b["issued_at"]) || !k5IsUint(b["expires_at"]) || !k5IsUint(b["epsilon_budget_micro"]) || !k5IsUint(b["max_queries"]) {
		return false
	}
	rules, ok := b["rules"].([]any)
	if !ok || len(rules) < 1 || len(rules) > 16 {
		return false
	}
	for _, r := range rules {
		if !k5ValidAggRule(r) {
			return false
		}
	}
	return true
}

// AggregateGrantDigest is the content address of an aggregate grant body.
func AggregateGrantDigest(body map[string]any) (string, bool) {
	return hashCanonicalV(map[string]any{"d": k5AgRef, "g": body})
}

// AggregateState is the explicit state threaded through aggregate reads. A nil Answered is an empty one.
type AggregateState struct {
	SpentMicro int64
	Queries    int64
	Answered   map[string]int64
}

func (s AggregateState) clone() AggregateState {
	a := make(map[string]int64, len(s.Answered)+1)
	for k, v := range s.Answered {
		a[k] = v
	}
	return AggregateState{s.SpentMicro, s.Queries, a}
}

// AggregateInput: Grant, Now and Values are decoded JSON values (Values: one integer per row; for count only the number matters).
// Salt has at least 16 characters. Noise is "seeded" (deterministic from salt and query: vectors, tests, audits) or "secure"
// (PRODUCTION: a fresh seed from the OS CSPRNG per answered query; not reproducible, the salt need not stay secret).
type AggregateInput struct {
	Grant     any
	Principal string
	Now       any
	Verb      string
	Resource  string
	Purpose   string
	Fn        string // count | sum
	Values    any
	Salt      string
	Noise     string // seeded | secure
	State     AggregateState
}

// AggregateResult: Code is "" for null; Value is meaningful only when Decision is allow.
type AggregateResult struct {
	Decision     string
	Code         string
	Value        int64
	State        AggregateState
	ChargedMicro int64
}

type k5RangeError string

func k5Clamp(v, c int64) int64 {
	if v > c {
		return c
	}
	if v < -c {
		return -c
	}
	return v
}

// AggregateRead answers one aggregate under the grant, or refuses. The input state is never mutated. Never panics; a sampler
// RangeError (the reference throws) is the catch-all: deny bad_request with an EMPTY state.
func AggregateRead(inp AggregateInput) (res AggregateResult) {
	empty := AggregateState{0, 0, map[string]int64{}}
	fail := func(code string, s AggregateState) AggregateResult { return AggregateResult{"deny", code, 0, s, 0} }
	defer func() {
		if recover() != nil {
			res = fail("bad_request", empty)
		}
	}()
	st := inp.State
	if st.SpentMicro < 0 || st.SpentMicro > maxSafeIntI || st.Queries < 0 || st.Queries > maxSafeIntI {
		return fail("bad_request", empty)
	}
	for _, v := range st.Answered {
		if v > maxSafeIntI || v < -maxSafeIntI {
			return fail("bad_request", empty)
		}
	}
	st = st.clone()
	keep := func(code string) AggregateResult { return fail(code, st) }
	if !k5IsB32(inp.Principal) || !k5IsUint(inp.Now) {
		return keep("bad_request")
	}
	now := k5F(inp.Now)
	sg, ok := k5Obj(inp.Grant)
	if !ok || !k5OnlyKeys(sg, "body", "sig") || !k5ValidAggGrantBody(sg["body"]) {
		return keep("bad_grant")
	}
	g := sg["body"].(map[string]any)
	if g["principal"] != inp.Principal || !k5VerifyBody(k5AggregateDomain, g, inp.Principal, sg["sig"]) {
		return keep("bad_signature")
	}
	if now < k5F(g["issued_at"]) {
		return keep("not_yet")
	}
	if now >= k5F(g["expires_at"]) {
		return keep("expired")
	}
	vals, isList := inp.Values.([]any)
	if !k3Str(inp.Verb, 128) || !k3Str(inp.Resource, 512) || !k5ID.ok(inp.Purpose) || (inp.Fn != "count" && inp.Fn != "sum") || (inp.Noise != "seeded" && inp.Noise != "secure") ||
		jsLen(inp.Salt) < 16 || !isList || len(vals) > 1000000 {
		return keep("bad_request")
	}
	ints := make([]int64, len(vals))
	for i, v := range vals {
		if !jsIsSafeInteger(v) {
			return keep("bad_request")
		}
		ints[i] = int64(k5F(v))
	}
	var rule map[string]any
	for _, x := range g["rules"].([]any) {
		r := x.(map[string]any)
		if r["verb"] == inp.Verb && strings.HasPrefix(inp.Resource, r["resource_prefix"].(string)) && k5Has(k5Strs(r["purposes"]), inp.Purpose) {
			rule = r
			break
		}
	}
	if rule == nil || !k5Has(k5Strs(rule["fns"]), inp.Fn) {
		return keep("no_read_scope")
	}
	if int64(len(ints)) < int64(k5F(rule["min_group"])) {
		return keep("group_too_small")
	}
	clamp := int64(k5F(rule["clamp"]))
	var clamped int64
	for _, v := range ints {
		clamped += k5Clamp(v, clamp)
	}
	gd, ok := AggregateGrantDigest(g)
	if !ok {
		return fail("bad_request", empty)
	}
	n := func(i int64) json.Number { return json.Number(strconv.FormatInt(i, 10)) }
	qd, ok := hashCanonicalV(map[string]any{"d": k5AgQ, "g": gd, "verb": inp.Verb, "resource": inp.Resource, "purpose": inp.Purpose, "fn": inp.Fn, "n": n(int64(len(ints))), "s": n(clamped)})
	if !ok {
		return fail("bad_request", empty)
	}
	if prior, has := st.Answered[qd]; has {
		return AggregateResult{"allow", "", prior, st, 0}
	}
	if st.Queries+1 > int64(k5F(g["max_queries"])) {
		return keep("query_cap")
	}
	dp, _ := rule["dp"].(bool)
	eps := int64(k5F(rule["epsilon_micro"]))
	var cost int64
	if dp {
		cost = eps
	}
	if st.SpentMicro+cost > int64(k5F(g["epsilon_budget_micro"])) {
		return keep("epsilon_exhausted")
	}
	exact := int64(len(ints))
	if inp.Fn == "sum" {
		exact = clamped
	}
	if dp {
		sens := int64(1)
		if inp.Fn == "sum" {
			sens = clamp
		}
		var d *k5Draws
		if inp.Noise == "secure" {
			d = k5SecureDraws()
		} else {
			seed, ok := hashCanonicalV(map[string]any{"d": k5AgN, "salt": inp.Salt, "q": qd})
			if !ok {
				return fail("bad_request", empty)
			}
			d = k5SeededDraws(seed)
		}
		exact += k5DiscreteLaplace(d, eps, sens*1000000)
	}
	next := st.clone()
	next.SpentMicro += cost
	next.Queries++
	next.Answered[qd] = exact
	return AggregateResult{"allow", "", exact, next, cost}
}

const maxSafeIntI = int64(1)<<53 - 1

// ---- integer-exact discrete Laplace sampler (CKS 2020, Alg. 1-2) -----------------------------------------------------------

// k5Draws: block i is the decoded SHA-256 of canonical {d, seed, i}; each block yields five 48-bit big-endian values (bytes 0-5, 6-11, ...).
type k5Draws struct {
	seed  string
	block int64
	buf   []int64 // pending values, in consumption order
}

func k5SeededDraws(seed string) *k5Draws { return &k5Draws{seed: seed} }

// k5SecureDraws is the PRODUCTION noise source: a fresh 32-byte seed from the OS CSPRNG (base64url, unpadded), same sampler.
func k5SecureDraws() *k5Draws {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(k5RangeError("secure: no entropy"))
	}
	return k5SeededDraws(base64.RawURLEncoding.EncodeToString(b))
}

func (d *k5Draws) next48() int64 {
	if len(d.buf) == 0 {
		h, ok := hashCanonicalV(map[string]any{"d": k5DpStream, "seed": d.seed, "i": json.Number(strconv.FormatInt(d.block, 10))})
		d.block++
		raw, ok2 := DecodeB64uStrict(h, 32)
		if !ok || !ok2 {
			panic(k5RangeError("draws: bad block"))
		}
		for k := 0; k < 5; k++ {
			var v int64
			for j := 0; j < 6; j++ {
				v = v*256 + int64(raw[k*6+j])
			}
			d.buf = append(d.buf, v)
		}
	}
	v := d.buf[0]
	d.buf = d.buf[1:]
	return v
}

func (d *k5Draws) uniform(n int64) int64 {
	if n < 1 || n > int64(1)<<47 {
		panic(k5RangeError("uniform: bad bound"))
	}
	limit := k5Two48 - (k5Two48 % n)
	for i := 0; i < k5MaxSteps; i++ {
		if r := d.next48(); r < limit {
			return r % n
		}
	}
	panic(k5RangeError("uniform: no draw"))
}

func (d *k5Draws) bern(num, den int64) bool { return d.uniform(den) < num }

// bernExpSmall is Bernoulli(exp(-num/den)) for 0 <= num/den <= 1.
func (d *k5Draws) bernExpSmall(num, den int64) bool {
	for k := int64(1); k <= k5MaxSteps; k++ {
		if !d.bern(num, den*k) {
			return k%2 == 1
		}
	}
	panic(k5RangeError("bernoulli: no termination"))
}

// k5DiscreteLaplace: P[x] proportional to exp(-|x| s / t) (CKS Alg. 2).
func k5DiscreteLaplace(d *k5Draws, s, t int64) int64 {
	if s < 1 {
		panic(k5RangeError("laplace: bad rate"))
	}
	for outer := 0; outer < k5MaxSteps; outer++ {
		u := d.uniform(t)
		if !d.bernExpSmall(u, t) {
			continue
		}
		var v int64
		for d.bernExpSmall(1, 1) {
			v++
			if v > k5MaxSteps {
				panic(k5RangeError("laplace: no termination"))
			}
		}
		y := (u + t*v) / s
		negative := d.uniform(2) == 1
		if negative && y == 0 {
			continue
		}
		if negative {
			return -y
		}
		return y
	}
	panic(k5RangeError("laplace: no sample"))
}
