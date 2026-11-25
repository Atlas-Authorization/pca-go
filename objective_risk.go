package pca

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Objective risk functional. Every input of the heuristic r is a pure function of COMMITTED facts and of the CANONICAL ACTION
// (verb + resource + params); nothing the agent merely asserts is read. Agent and verifier recompute the same r; the grant commits
// the registry, graph, embedder and goal, and a mismatch fails closed (r = 1, valid false). The result feeds RiskScore, so the
// decision sees the unchanged RiskInputs shape. Digests here are SERVER-ONLY and use the lenient canonical hash (any finite
// double, printed like ECMAScript Number-to-string); they are never protocol digests. Sorting uses two orders: registry verbs,
// trusted verifiers, reachable ids, graph digest rows and authorized kinds by UTF-16 code unit; param leaf keys and canonical
// JSON keys by UTF-8 byte. Embedders, goals and descriptors are JSON-shaped values (maps) so that the committed identity hashes
// exactly what was given.

const (
	// ObjMetric is the only distance metric.
	ObjMetric = "half-chord-v1"
	// NativeScheme names the native n-gram feature-hashing embedder.
	NativeScheme = "pca-native-hash-ngram-v1"
	// DefaultMaxParamLeaves caps the flattened param leaves an embedder accepts when its config omits maxParamLeaves.
	DefaultMaxParamLeaves = 256
	// ByoInputEncoding is the only input encoding of a customer model.
	ByoInputEncoding = "pca-canonical-action-json-v1"
)

// ObjDefaultEpsilon is the default distance grid, 1/4096.
const ObjDefaultEpsilon = 1.0 / 4096

// DefaultNativeConfig is a fresh copy of the default native embedder config.
func DefaultNativeConfig() map[string]any {
	return map[string]any{
		"dims": 256.0, "ngramMin": 2.0, "ngramMax": 4.0, "seed": "pca-native-v1",
		"fieldWeights": map[string]any{"verb": 4.0, "resource": 2.0, "param": 1.0},
	}
}

func objErr(format string, a ...any) error { return fmt.Errorf(format, a...) }

func objClamp01(x float64) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return 1
	}
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func objFinite(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) }

func objSafeInt(x float64) bool {
	return objFinite(x) && x == math.Trunc(x) && math.Abs(x) <= 9007199254740991
}

// objCanon is the lenient canonical text, or the reference's refusal.
func objCanon(v any) (string, error) {
	s, ok := canonicalLenient(v)
	if !ok {
		return "", errors.New("canonicalize: non-finite number")
	}
	return s, nil
}

func objHash(v any) (string, error) {
	s, err := objCanon(v)
	if err != nil {
		return "", err
	}
	return B64u(sha256Sum([]byte(s))), nil
}

// objToNumber is JavaScript ToNumber for the JSON value shapes (an array or object is NaN here).
func objToNumber(v any) float64 {
	switch t := v.(type) {
	case nil:
		return 0
	case bool:
		if t {
			return 1
		}
		return 0
	case string:
		return jsStringToNumber(t)
	}
	if f, ok := jsNum(v); ok {
		return f
	}
	return math.NaN()
}

func objFloats(v []float64) []any {
	out := make([]any, len(v))
	for i, x := range v {
		out[i] = x
	}
	return out
}

func objStringsAny(v []string) []any {
	out := make([]any, len(v))
	for i, x := range v {
		out[i] = x
	}
	return out
}

func objSortedUniq(v []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(v))
	for _, s := range v {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sortUtf16(out)
	return out
}

// ---- canonical action --------------------------------------------------------------------

// ObjAction is what the agent submits; only these three fields are ever read. Params is a JSON object (map[string]any), nil for none.
type ObjAction struct {
	Verb     string
	Resource string
	Params   any
}

// CanonicalAction: verb trimmed and lowercased, every string and key Unicode-NFC, params validated.
type CanonicalAction struct {
	Verb     string
	Resource string
	Params   map[string]any
}

func (c CanonicalAction) value() map[string]any {
	p := c.Params
	if p == nil {
		p = map[string]any{}
	}
	return map[string]any{"verb": c.Verb, "resource": c.Resource, "params": p}
}

// Value is the canonical action as a JSON object.
func (c CanonicalAction) Value() map[string]any { return c.value() }

func objNormValue(v any) (any, error) {
	switch t := v.(type) {
	case string:
		return norm.NFC.String(t), nil
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			n, err := objNormValue(x)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(t))
		for _, k := range jsKeys(t) {
			nk := norm.NFC.String(k)
			if _, dup := out[nk]; dup {
				return nil, errors.New("canonicalAction: duplicate key after NFC normalization")
			}
			n, err := objNormValue(t[k])
			if err != nil {
				return nil, err
			}
			out[nk] = n
		}
		return out, nil
	}
	return v, nil
}

func objCased(r rune) bool {
	return unicode.IsUpper(r) || unicode.IsLower(r) || unicode.IsTitle(r) || unicode.Is(unicode.Other_Lowercase, r) || unicode.Is(unicode.Other_Uppercase, r)
}

func objCaseIgnorable(r rune) bool {
	switch r {
	case '\'', '.', ':', 0xB7, 0x2018, 0x2019, 0x2024, 0x2027, 0xFE13, 0xFE52, 0xFE55, 0xFF07, 0xFF0E, 0xFF1A:
		return true
	}
	return unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf, unicode.Lm, unicode.Sk)
}

func objFinalSigma(rs []rune, i int) bool {
	before := false
	for j := i - 1; j >= 0; j-- {
		if objCaseIgnorable(rs[j]) {
			continue
		}
		before = objCased(rs[j])
		break
	}
	if !before {
		return false
	}
	for j := i + 1; j < len(rs); j++ {
		if objCaseIgnorable(rs[j]) {
			continue
		}
		return !objCased(rs[j])
	}
	return true
}

// objLower is String.prototype.toLowerCase: the locale-independent full mapping (U+0130 becomes "i" + U+0307, and the final
// sigma rule applies).
func objLower(s string) string {
	rs := []rune(s)
	var b strings.Builder
	for i, r := range rs {
		switch r {
		case 0x130:
			b.WriteString("i̇")
		case 0x3A3:
			if objFinalSigma(rs, i) {
				b.WriteRune(0x3C2)
			} else {
				b.WriteRune(0x3C3)
			}
		default:
			b.WriteRune(unicode.ToLower(r))
		}
	}
	return b.String()
}

// CanonicalizeAction is the canonical form of a submission (an ObjAction or its JSON object). Re-encodings that do not change the
// action (key order, NFC / NFD, verb case) collapse to one form. It refuses anything without a stable encoding.
func CanonicalizeAction(a any) (CanonicalAction, error) {
	var verb, resource string
	var params any
	switch t := a.(type) {
	case ObjAction:
		verb, resource, params = t.Verb, t.Resource, t.Params
	case *ObjAction:
		if t == nil {
			return CanonicalAction{}, errors.New("canonicalAction: verb/resource must be strings")
		}
		verb, resource, params = t.Verb, t.Resource, t.Params
	case map[string]any:
		v, vok := t["verb"].(string)
		r, rok := t["resource"].(string)
		if !vok || !rok {
			return CanonicalAction{}, errors.New("canonicalAction: verb/resource must be strings")
		}
		verb, resource, params = v, r, t["params"]
	default:
		return CanonicalAction{}, errors.New("canonicalAction: verb/resource must be strings")
	}
	verb = objLower(jsTrim(norm.NFC.String(verb)))
	resource = jsTrim(norm.NFC.String(resource))
	if verb == "" || resource == "" {
		return CanonicalAction{}, errors.New("canonicalAction: empty verb/resource")
	}
	if params == nil {
		params = map[string]any{}
	}
	np, err := objNormValue(params)
	if err != nil {
		return CanonicalAction{}, err
	}
	pm, ok := np.(map[string]any)
	if !ok {
		return CanonicalAction{}, errors.New("canonicalAction: params must be an object")
	}
	c := CanonicalAction{Verb: verb, Resource: resource, Params: pm}
	if _, err := objCanon(c.value()); err != nil {
		return CanonicalAction{}, err
	}
	return c, nil
}

// CanonicalActionJSON is the canonical text of c.
func CanonicalActionJSON(c CanonicalAction) (string, error) { return objCanon(c.value()) }

// CanonicalActionDigest is the lenient canonical hash of c.
func CanonicalActionDigest(c CanonicalAction) (string, error) { return objHash(c.value()) }

// ---- 1. reversibility: a committed registry of verified inverses -------------------------

// InverseVerification: who verified an inverse (must be in the registry's committed trusted set) and the evidence digest.
type InverseVerification struct {
	VerifierID     string
	EvidenceDigest string
}

// InverseEntry: the inverse kind, "exact" (undo) or "partial" (compensation), and its verification, if any.
type InverseEntry struct {
	InverseKind  string
	Fidelity     string
	Verification *InverseVerification
}

// InverseRegistry is a committed set of inverses.
type InverseRegistry interface {
	Lookup(verb string) (InverseEntry, bool)
	// TrustedVerifiers are the verifier ids whose verification counts; committed as part of the digest.
	TrustedVerifiers() []string
	// Digest is the canonical digest of ALL contents; the grant commits this.
	Digest() string
}

// InMemoryInverseRegistry is the map-backed registry.
type InMemoryInverseRegistry struct {
	m       map[string]InverseEntry
	trusted []string
}

// NewInMemoryInverseRegistry de-duplicates and sorts the trusted verifier ids.
func NewInMemoryInverseRegistry(trusted ...string) *InMemoryInverseRegistry {
	return &InMemoryInverseRegistry{m: map[string]InverseEntry{}, trusted: objSortedUniq(trusted)}
}

// Register adds the inverse of verb; a later entry for the same verb replaces the earlier.
func (r *InMemoryInverseRegistry) Register(verb string, e InverseEntry) *InMemoryInverseRegistry {
	if e.Verification != nil {
		v := *e.Verification
		e.Verification = &v
	}
	r.m[verb] = e
	return r
}

// Lookup returns a copy of the entry.
func (r *InMemoryInverseRegistry) Lookup(verb string) (InverseEntry, bool) {
	e, ok := r.m[verb]
	if ok && e.Verification != nil {
		v := *e.Verification
		e.Verification = &v
	}
	return e, ok
}

// TrustedVerifiers returns the sorted trusted ids.
func (r *InMemoryInverseRegistry) TrustedVerifiers() []string { return r.trusted }

// Digest commits the trusted set and every entry, sorted by verb.
func (r *InMemoryInverseRegistry) Digest() string {
	verbs := make([]string, 0, len(r.m))
	for v := range r.m {
		verbs = append(verbs, v)
	}
	sortUtf16(verbs)
	entries := make([]any, 0, len(verbs))
	for _, v := range verbs {
		e := r.m[v]
		var ver any
		if e.Verification != nil {
			ver = map[string]any{"verifierId": e.Verification.VerifierID, "evidenceDigest": e.Verification.EvidenceDigest}
		}
		entries = append(entries, map[string]any{"verb": v, "inverseKind": e.InverseKind, "fidelity": e.Fidelity, "verification": ver})
	}
	h, _ := objHash(map[string]any{"v": 1.0, "trusted": objStringsAny(r.trusted), "entries": entries})
	return h
}

// ReversibilityResult: class reversible / compensable / irreversible and its value (1, 0.5, 0) that feeds RiskInputs.Reversibility.
type ReversibilityResult struct {
	Class       string
	Value       float64
	InverseKind string // empty for irreversible
}

// ObjectiveReversibility: reversible iff the registry holds an inverse whose verification came from a TRUSTED verifier AND the
// inverse verb is itself authorized by the capability. The verb is looked up exactly as given. Inverses of inverses are not chased.
func ObjectiveReversibility(verb string, registry InverseRegistry, authorizedKinds []string) ReversibilityResult {
	e, found := registry.Lookup(verb)
	trusted := false
	if found && e.Verification != nil {
		for _, t := range registry.TrustedVerifiers() {
			if t == e.Verification.VerifierID {
				trusted = true
			}
		}
	}
	authorized := false
	if found {
		for _, k := range authorizedKinds {
			if k == e.InverseKind {
				authorized = true
			}
		}
	}
	if !found || !trusted || !authorized {
		return ReversibilityResult{Class: "irreversible", Value: 0}
	}
	if e.Fidelity == "exact" {
		return ReversibilityResult{Class: "reversible", Value: 1, InverseKind: e.InverseKind}
	}
	return ReversibilityResult{Class: "compensable", Value: 0.5, InverseKind: e.InverseKind}
}

// ---- 2. blast radius: reachability over a committed resource graph -----------------------

// ResourceNode: a resource and the harm if it is destroyed or exposed, per denomination.
type ResourceNode struct {
	ID   string
	Harm map[string]float64
}

// ResourceEdge links two nodes.
type ResourceEdge struct{ From, To, Kind string }

// ObjScope is the capability's scope; it comes from the grant, never from the agent's action. EdgeKinds nil is absent (no filter);
// MaxDepth nil is unbounded.
type ObjScope struct {
	EdgeKinds []string
	MaxDepth  *float64
}

// ObjResourceGraph is the adjacency model with the content digest the grant commits.
type ObjResourceGraph struct {
	nodes map[string]ResourceNode
	out   map[string][]ResourceEdge
}

// NewObjResourceGraph is an empty graph.
func NewObjResourceGraph() *ObjResourceGraph {
	return &ObjResourceGraph{nodes: map[string]ResourceNode{}, out: map[string][]ResourceEdge{}}
}

// AddNode adds a node; an existing id replaces the node and keeps its edges.
func (g *ObjResourceGraph) AddNode(n ResourceNode) *ObjResourceGraph {
	g.nodes[n.ID] = n
	if _, ok := g.out[n.ID]; !ok {
		g.out[n.ID] = nil
	}
	return g
}

// AddEdge refuses an edge whose endpoint is not a node.
func (g *ObjResourceGraph) AddEdge(e ResourceEdge) error {
	_, a := g.nodes[e.From]
	_, b := g.nodes[e.To]
	if !a || !b {
		return errors.New("edge endpoints must exist")
	}
	g.out[e.From] = append(g.out[e.From], e)
	return nil
}

// Size is the node count.
func (g *ObjResourceGraph) Size() int { return len(g.nodes) }

// Node returns the node with id.
func (g *ObjResourceGraph) Node(id string) (ResourceNode, bool) {
	n, ok := g.nodes[id]
	return n, ok
}

// Reachable is the BFS reachable set (including start), edge-kind and depth restricted, sorted; an unknown start is empty.
func (g *ObjResourceGraph) Reachable(start string, scope *ObjScope) []string {
	if _, ok := g.nodes[start]; !ok {
		return []string{}
	}
	var kinds map[string]bool
	maxDepth := math.Inf(1)
	if scope != nil {
		if scope.EdgeKinds != nil {
			kinds = map[string]bool{}
			for _, k := range scope.EdgeKinds {
				kinds[k] = true
			}
		}
		if scope.MaxDepth != nil {
			maxDepth = *scope.MaxDepth
		}
	}
	seen := map[string]bool{start: true}
	frontier := []string{start}
	for d := 0.0; d < maxDepth && len(frontier) > 0; d++ {
		var next []string
		for _, u := range frontier {
			for _, e := range g.out[u] {
				if (kinds == nil || kinds[e.Kind]) && !seen[e.To] {
					seen[e.To] = true
					next = append(next, e.To)
				}
			}
		}
		frontier = next
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sortUtf16(out)
	return out
}

// Digest commits every node (id and harm) and every edge; it refuses a non-finite harm weight.
func (g *ObjResourceGraph) Digest() (string, error) {
	ids := make([]string, 0, len(g.nodes))
	for id := range g.nodes {
		ids = append(ids, id)
	}
	sortUtf16(ids)
	nodes := make([]any, 0, len(ids))
	for _, id := range ids {
		h := map[string]any{}
		for k, v := range g.nodes[id].Harm {
			h[k] = v
		}
		nodes = append(nodes, map[string]any{"id": id, "harm": h})
	}
	var edges []ResourceEdge
	for _, es := range g.out {
		edges = append(edges, es...)
	}
	key := func(e ResourceEdge) []uint16 { return utf16Units(e.From + "\u0000" + e.To + "\u0000" + e.Kind) }
	sort.SliceStable(edges, func(i, j int) bool { return compareUnits(key(edges[i]), key(edges[j])) < 0 })
	es := make([]any, 0, len(edges))
	for _, e := range edges {
		es = append(es, map[string]any{"from": e.From, "to": e.To, "kind": e.Kind})
	}
	return objHash(map[string]any{"v": 1.0, "n": nodes, "e": es})
}

// BlastRadiusResult: count of reachable resources, the ids, count / |graph| (an unknown resource is 1, fail closed) and the summed
// harm per denomination.
type BlastRadiusResult struct {
	Count      int
	Reachable  []string
	Normalized float64
	Harm       map[string]float64
}

// ComputeBlastRadius is the blast radius of acting on resource.
func ComputeBlastRadius(resource string, graph *ObjResourceGraph, scope *ObjScope) BlastRadiusResult {
	reachable := graph.Reachable(resource, scope)
	if len(reachable) == 0 || graph.Size() == 0 {
		return BlastRadiusResult{Count: 0, Reachable: reachable, Normalized: 1, Harm: map[string]float64{}}
	}
	harm := map[string]float64{}
	for _, id := range reachable {
		for d, v := range graph.nodes[id].Harm {
			if objFinite(v) && v > 0 {
				harm[d] = harm[d] + v
			}
		}
	}
	return BlastRadiusResult{Count: len(reachable), Reachable: reachable, Normalized: float64(len(reachable)) / float64(graph.Size()), Harm: harm}
}

// ---- 3. committed embeddings -------------------------------------------------------------

// Embedder maps the CANONICAL ACTION to an integer vector; it never sees agent-supplied features. ModelID is a committed identity:
// a hash of Config (native) or of the model descriptor (BYO), so two embedders with different behaviour cannot share an id.
type Embedder interface {
	ModelID() string
	// Config is the committed descriptor behind ModelID.
	Config() any
	Dims() int
	// Embed MUST return Dims() safe integers, deterministic for equal canonical actions. It may fail.
	Embed(a CanonicalAction) ([]float64, error)
}

// EmbeddingError is a refused vector.
type EmbeddingError struct{ Msg string }

func (e *EmbeddingError) Error() string { return e.Msg }

func objMaxComponent(dims int) float64 {
	d := dims
	if d < 1 {
		d = 1
	}
	return math.Floor(math.Sqrt(9007199254740991.0 / float64(2*d)))
}

// ValidateVector checks the exact length, safe integers and |x| <= floor(sqrt((2^53-1) / (2 * max(1, dims)))), so dot products of
// two vectors stay exact in a double; negative zero becomes zero.
func ValidateVector(v []float64, dims int) ([]float64, error) {
	if len(v) != dims {
		return nil, &EmbeddingError{fmt.Sprintf("vector must have exactly %d components", dims)}
	}
	lim := objMaxComponent(dims)
	out := make([]float64, len(v))
	for i, x := range v {
		if !objSafeInt(x) {
			return nil, &EmbeddingError{"vector components must be safe integers"}
		}
		if !(math.Abs(x) <= lim) {
			return nil, &EmbeddingError{"vector component out of range"}
		}
		if x == 0 {
			x = 0 // -0 becomes +0
		}
		out[i] = x
	}
	return out, nil
}

// objVecOf reads a JSON vector; a non-list is refused with the length message, a non-number component is NaN (not a safe integer).
func objVecOf(v any, dims int) []float64 {
	switch t := v.(type) {
	case []float64:
		return t
	case []any:
		out := make([]float64, len(t))
		for i, x := range t {
			f, ok := jsNum(x)
			if !ok {
				f = math.NaN()
			}
			out[i] = f
		}
		return out
	}
	return nil
}

// NativeEmbedderConfig is the committed native embedder description (a JSON object): dims, ngramMin, ngramMax, seed,
// fieldWeights {verb, resource, param}, and optionally maxParamLeaves and paramMode ("leaves" or "digest"). Everything given is
// committed into the model id, extra members included.
type NativeEmbedderConfig = map[string]any

// NativeEmbedder is integer feature hashing over code-point n-grams of the canonical action. For each field (verb, resource, each
// param leaf) it emits n-grams of U+0002 + text + U+0003 and word tokens; each feature f is hashed as
// SHA-256(seed 0x1F f): bucket = big-endian u32(h[0..4]) mod dims, sign = low bit of h[4]; the bucket accumulates +-fieldWeight.
type NativeEmbedder struct {
	modelID                  string
	committed                map[string]any
	dims, ngramMin, ngramMax int
	seed                     string
	wVerb, wRes, wParam      int
	maxLeaves                int
	digestMode               bool
}

func objOkInt(v any, lo, hi float64) (int, bool) {
	f, ok := jsNum(v)
	if !ok || !objSafeInt(f) || f < lo || f > hi {
		return 0, false
	}
	return int(f), true
}

// NativeHashEmbedder validates config (every bound) and commits it: modelId = "native:" + hash({scheme, ...config}). An absent
// maxParamLeaves or paramMode stays absent in the committed config.
func NativeHashEmbedder(config NativeEmbedderConfig) (*NativeEmbedder, error) {
	e := &NativeEmbedder{}
	var ok bool
	if e.dims, ok = objOkInt(config["dims"], 8, 65536); !ok {
		return nil, errors.New("native config: dims must be an integer in [8, 65536]")
	}
	nmin, ok1 := objOkInt(config["ngramMin"], 1, 8)
	nmax := 0
	ok2 := false
	if ok1 {
		nmax, ok2 = objOkInt(config["ngramMax"], float64(nmin), 8)
	}
	if !ok1 || !ok2 {
		return nil, errors.New("native config: need 1 <= ngramMin <= ngramMax <= 8")
	}
	e.ngramMin, e.ngramMax = nmin, nmax
	seed, isStr := config["seed"].(string)
	if !isStr || seed == "" {
		return nil, errors.New("native config: seed required")
	}
	e.seed = seed
	fw, _ := config["fieldWeights"].(map[string]any)
	for _, k := range []string{"verb", "resource", "param"} {
		w, ok := objOkInt(fw[k], 0, 1000)
		if !ok {
			return nil, objErr("native config: fieldWeights.%s must be an integer in [0, 1000]", k)
		}
		switch k {
		case "verb":
			e.wVerb = w
		case "resource":
			e.wRes = w
		default:
			e.wParam = w
		}
	}
	e.maxLeaves = DefaultMaxParamLeaves
	if v, has := config["maxParamLeaves"]; has {
		n, ok := objOkInt(v, 1, 1000000)
		if !ok {
			return nil, errors.New("native config: maxParamLeaves must be an integer in [1, 1000000]")
		}
		e.maxLeaves = n
	}
	if v, has := config["paramMode"]; has {
		s, _ := v.(string)
		if s != "leaves" && s != "digest" {
			return nil, errors.New("native config: paramMode must be 'leaves' or 'digest'")
		}
		e.digestMode = s == "digest"
	}
	committed := map[string]any{"scheme": NativeScheme}
	for k, v := range config {
		committed[k] = v
	}
	if m, isMap := config["fieldWeights"].(map[string]any); isMap {
		cp := make(map[string]any, len(m))
		for k, v := range m {
			cp[k] = v
		}
		committed["fieldWeights"] = cp
	}
	e.committed = committed
	h, err := objHash(committed)
	if err != nil {
		return nil, err
	}
	e.modelID = "native:" + h
	return e, nil
}

// ModelID is the committed identity.
func (e *NativeEmbedder) ModelID() string { return e.modelID }

// Config is the committed {scheme, ...config}.
func (e *NativeEmbedder) Config() any { return e.committed }

// Dims is the vector length.
func (e *NativeEmbedder) Dims() int { return e.dims }

func objParamLeaves(v any, path string, out *[]string) error {
	switch t := v.(type) {
	case []any:
		for i, x := range t {
			if err := objParamLeaves(x, path+"["+strconv.Itoa(i)+"]", out); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, k := range sortedKeysUtf8(t) {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if err := objParamLeaves(t[k], p, out); err != nil {
				return err
			}
		}
		return nil
	}
	s, err := objCanon(v)
	if err != nil {
		return err
	}
	*out = append(*out, path+"="+s)
	return nil
}

func objTextFeatures(prefix, text string, nmin, nmax int) []string {
	var out []string
	cps := []rune("\u0002" + text + "\u0003")
	for n := nmin; n <= nmax; n++ {
		for i := 0; i+n <= len(cps); i++ {
			out = append(out, prefix+"c"+strconv.Itoa(n)+":"+string(cps[i:i+n]))
		}
	}
	var word []rune
	flush := func() {
		if len(word) > 0 {
			out = append(out, prefix+"w:"+objLower(string(word)))
			word = word[:0]
		}
	}
	for _, r := range text {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			word = append(word, r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// Embed is the integer vector of a canonical action. More param leaves than the cap refuses (the embed fails closed, so
// ObjectiveRisk is 1): an action cannot dilute or inflate its distance by stuffing params.
func (e *NativeEmbedder) Embed(a CanonicalAction) ([]float64, error) {
	v := make([]float64, e.dims)
	prefix := []byte(e.seed + "\u001f")
	add := func(feat string, w int) {
		if w == 0 {
			return
		}
		buf := make([]byte, 0, len(prefix)+len(feat))
		buf = append(buf, prefix...)
		buf = append(buf, feat...)
		h := sha256Sum(buf)
		bucket := (uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])) % uint32(e.dims)
		if h[4]&1 == 0 {
			v[bucket] += float64(w)
		} else {
			v[bucket] -= float64(w)
		}
	}
	for _, f := range objTextFeatures("v:", a.Verb, e.ngramMin, e.ngramMax) {
		add(f, e.wVerb)
	}
	for _, f := range objTextFeatures("r:", a.Resource, e.ngramMin, e.ngramMax) {
		add(f, e.wRes)
	}
	params := a.Params
	if params == nil {
		params = map[string]any{}
	}
	var leaves []string
	if err := objParamLeaves(params, "", &leaves); err != nil {
		return nil, err
	}
	if len(leaves) > e.maxLeaves {
		return nil, &EmbeddingError{fmt.Sprintf("param leaf count %d exceeds cap %d", len(leaves), e.maxLeaves)}
	}
	if e.digestMode {
		h, err := objHash(map[string]any{"t": "pca-objrisk-params-v1", "params": params})
		if err != nil {
			return nil, err
		}
		add("p#:"+h, e.wParam)
	} else {
		for _, leaf := range leaves {
			for _, f := range objTextFeatures("p:", leaf, e.ngramMin, e.ngramMax) {
				add(f, e.wParam)
			}
		}
	}
	return v, nil
}

// ByoDescriptor is the descriptor a customer commits (a JSON object): name, version, weightsDigest, runtime, dims,
// quantization {bits, scale}, inputEncoding "pca-canonical-action-json-v1". Contract: pinned weights, fixed-point inference with
// no floating-point reduction-order dependence, input = the canonical action JSON bytes, output = safe integers within the
// quantization range.
type ByoDescriptor = map[string]any

// ByoModelID is "byo:" + the hash of the descriptor.
func ByoModelID(d ByoDescriptor) (string, error) {
	h, err := objHash(d)
	if err != nil {
		return "", err
	}
	return "byo:" + h, nil
}

// ByoEmbedder runs a customer model that meets the determinism contract.
type ByoEmbedder struct {
	modelID string
	desc    ByoDescriptor
	dims    int
	qmax    float64
	infer   func(canonicalJSON string) ([]float64, error)
}

// NewByoEmbedder validates the descriptor. infer receives the canonical action JSON and returns the integer vector. A claimed
// model id (nil for none) must equal the descriptor hash, so a customer cannot claim someone else's id.
func NewByoEmbedder(d ByoDescriptor, infer func(canonicalJSON string) ([]float64, error), claimedModelID *string) (*ByoEmbedder, error) {
	dims, ok := objOkInt(d["dims"], 1, 9007199254740991)
	if !ok {
		return nil, errors.New("byo: dims must be a positive integer")
	}
	q, isMap := d["quantization"].(map[string]any)
	if !isMap {
		return nil, errors.New("byo: invalid quantization")
	}
	bits, okBits := objOkInt(q["bits"], 2, 31)
	if !okBits || !(objToNumber(q["scale"]) > 0) {
		return nil, errors.New("byo: invalid quantization")
	}
	if d["inputEncoding"] != ByoInputEncoding {
		return nil, errors.New("byo: unsupported inputEncoding")
	}
	id, err := ByoModelID(d)
	if err != nil {
		return nil, err
	}
	if claimedModelID != nil && *claimedModelID != id {
		return nil, errors.New("byo: modelId does not match the committed descriptor")
	}
	return &ByoEmbedder{modelID: id, desc: d, dims: dims, qmax: math.Pow(2, float64(bits-1)) - 1, infer: infer}, nil
}

// ModelID is "byo:" + the descriptor hash.
func (e *ByoEmbedder) ModelID() string { return e.modelID }

// Config is the descriptor.
func (e *ByoEmbedder) Config() any { return e.desc }

// Dims is the vector length.
func (e *ByoEmbedder) Dims() int { return e.dims }

// Embed validates the model's vector and its quantization range.
func (e *ByoEmbedder) Embed(a CanonicalAction) ([]float64, error) {
	j, err := CanonicalActionJSON(a)
	if err != nil {
		return nil, err
	}
	raw, err := e.infer(j)
	if err != nil {
		return nil, err
	}
	v, err := ValidateVector(raw, e.dims)
	if err != nil {
		return nil, err
	}
	for _, x := range v {
		if !(math.Abs(x) <= e.qmax) {
			return nil, &EmbeddingError{"byo: component exceeds declared quantization range"}
		}
	}
	return v, nil
}

// ConformanceCase is one {action, vector} shipped with a model.
type ConformanceCase struct {
	Action any
	Vector []float64
}

// EmbedderConformanceCheck runs the cases shipped with a model; true iff every one reproduces exactly (any failure is false).
func EmbedderConformanceCheck(e Embedder, cases []ConformanceCase) bool {
	for _, c := range cases {
		a, err := CanonicalizeAction(c.Action)
		if err != nil {
			return false
		}
		v, err := e.Embed(a)
		if err != nil || len(v) != len(c.Vector) {
			return false
		}
		for i := range v {
			if v[i] != c.Vector[i] {
				return false
			}
		}
	}
	return true
}

// ---- goal commitment and distance --------------------------------------------------------

// ObjGoalCommitment binds the goal's canonical embedding to one embedder: embedderModelId, config, goalVector ([]any of numbers),
// metric, epsilon (distances are rounded UP to a multiple of epsilon: conservative, absorbs last-bit noise) and commit =
// hash({embedderModelId, config, goalVector, metric, epsilon}) made at grant time. It is a JSON object, so a decoded one verifies.
type ObjGoalCommitment = map[string]any

func objGoalInput(g map[string]any) (map[string]any, error) {
	in := map[string]any{}
	for _, k := range []string{"embedderModelId", "config", "goalVector", "metric", "epsilon"} {
		v, has := g[k]
		if !has {
			return nil, errors.New("canonicalize: unsupported type undefined")
		}
		in[k] = v
	}
	return in, nil
}

// CommitGoal embeds the goal's CANONICAL action and binds it to this embedder; epsilon (optional) must satisfy 0 < eps <= 1.
func CommitGoal(e Embedder, goalAction any, epsilon ...float64) (ObjGoalCommitment, error) {
	eps := ObjDefaultEpsilon
	if len(epsilon) > 0 {
		eps = epsilon[0]
	}
	if !(eps > 0 && eps <= 1) {
		return nil, errors.New("epsilon must be in (0, 1]")
	}
	ca, err := CanonicalizeAction(goalAction)
	if err != nil {
		return nil, err
	}
	raw, err := e.Embed(ca)
	if err != nil {
		return nil, err
	}
	gv, err := ValidateVector(raw, e.Dims())
	if err != nil {
		return nil, err
	}
	g := ObjGoalCommitment{"embedderModelId": e.ModelID(), "config": e.Config(), "goalVector": objFloats(gv), "metric": ObjMetric, "epsilon": eps}
	in, err := objGoalInput(g)
	if err != nil {
		return nil, err
	}
	h, err := objHash(in)
	if err != nil {
		return nil, err
	}
	g["commit"] = h
	return g, nil
}

// VerifyGoalCommitment verifies the commitment hash AND that it is bound to exactly this embedder (id, config, dims). It returns ""
// when valid, else the FIRST failing reason (metric, epsilon, commit hash, model id, config hash, vector); a refusal text is the
// reason. goal is a ObjGoalCommitment or any decoded JSON value.
func VerifyGoalCommitment(goal any, e Embedder) string {
	if goal == nil {
		return "Cannot read properties of null (reading 'metric')"
	}
	g, _ := goal.(map[string]any) // any other value reads as an object without members
	if g["metric"] != ObjMetric {
		return "unknown metric"
	}
	if x := objToNumber(g["epsilon"]); !(x > 0 && x <= 1) {
		return "bad epsilon"
	}
	in, err := objGoalInput(g)
	if err != nil {
		return err.Error()
	}
	h, err := objHash(in)
	if err != nil {
		return err.Error()
	}
	if c, isStr := g["commit"].(string); !isStr || c != h {
		return "goal commitment hash mismatch"
	}
	if id, isStr := g["embedderModelId"].(string); !isStr || id != e.ModelID() {
		return "embedder modelId mismatch"
	}
	a, err := objHash(g["config"])
	if err != nil {
		return err.Error()
	}
	b, err := objHash(e.Config())
	if err != nil {
		return err.Error()
	}
	if a != b {
		return "embedder config mismatch"
	}
	if _, err := ValidateVector(objVecOf(g["goalVector"], e.Dims()), e.Dims()); err != nil {
		return err.Error()
	}
	return ""
}

// VectorDistance maps integer vectors to sin(theta/2) = sqrt((1-cos)/2), rounded up to the epsilon grid and clamped to [0, 1]. Only
// IEEE `*`, `+`, `/` and sqrt are used, in this order (no fused multiply-add). Different lengths and zero vectors are 1; identical
// vectors 0; the noise floor 1e-9 is 0. epsilon is not validated (a NaN result clamps to 1).
func VectorDistance(a, b []float64, epsilon ...float64) float64 {
	eps := ObjDefaultEpsilon
	if len(epsilon) > 0 {
		eps = epsilon[0]
	}
	if len(a) != len(b) {
		return 1
	}
	dot, na, nb, same := 0.0, 0.0, 0.0, true
	for i := range a {
		dot += float64(a[i] * b[i])
		na += float64(a[i] * a[i])
		nb += float64(b[i] * b[i])
		if a[i] != b[i] {
			same = false
		}
	}
	if na == 0 || nb == 0 {
		return 1
	}
	if same {
		return 0
	}
	cos := math.Max(-1, math.Min(1, dot/math.Sqrt(float64(na*nb))))
	d := math.Sqrt((1 - cos) / 2)
	if d < 1e-9 {
		return 0
	}
	return objClamp01(float64(math.Ceil(d/eps) * eps))
}

// Checked is a value or the reason it could not be computed.
type Checked struct {
	OK     bool
	Value  float64
	Reason string
}

// CommittedDistanceChecked is the distance to the committed goal; OK false (distance 1) on any commitment or embedding failure.
func CommittedDistanceChecked(action CanonicalAction, goal any, e Embedder) Checked {
	if bad := VerifyGoalCommitment(goal, e); bad != "" {
		return Checked{Reason: bad}
	}
	g, _ := goal.(map[string]any)
	raw, err := e.Embed(action)
	if err != nil {
		return Checked{Reason: err.Error()}
	}
	v, err := ValidateVector(raw, e.Dims())
	if err != nil {
		return Checked{Reason: err.Error()}
	}
	return Checked{OK: true, Value: VectorDistance(v, objVecOf(g["goalVector"], e.Dims()), objToNumber(g["epsilon"]))}
}

// CommittedDistance accepts an agent submission, canonicalizes it and returns the distance (1 on any failure).
func CommittedDistance(action any, goal any, e Embedder) float64 {
	ca, err := CanonicalizeAction(action)
	if err != nil {
		return 1
	}
	r := CommittedDistanceChecked(ca, goal, e)
	if !r.OK {
		return 1
	}
	return r.Value
}

// ---- 4. split-conformal calibration ------------------------------------------------------

// Calibrate: scores are the raw scores of acceptable actions, held out from tuning. For a fresh benign action exchangeable with
// them p = (1 + #{s >= raw})/(n+1); calibrated r = 1 - p, so flagging r > 1-a has false-alarm rate <= a on benign traffic.
// Non-decreasing in raw. An empty set or a non-finite raw is 1.
func Calibrate(raw float64, benignScores []float64) float64 {
	n := len(benignScores)
	if n == 0 || !objFinite(raw) {
		return 1
	}
	ge := 0
	for _, s := range benignScores {
		if s >= raw {
			ge++
		}
	}
	return 1 - float64(1+ge)/float64(n+1)
}

func objSortedNumeric(v []float64) []float64 {
	out := append([]float64(nil), v...)
	// shortcut: a NaN score keeps its place (V8 insertion-sorts short arrays the same way), exact for the sizes the digests see
	sort.SliceStable(out, func(i, j int) bool { return out[i]-out[j] < 0 })
	return out
}

// ConformalThreshold is the split-conformal quantile: benign raw <= q with probability >= 1 - alpha. +Inf if n is too small. ok is
// false where the reference yields no value (alpha >= 1 indexes below the sorted scores, a NaN alpha).
func ConformalThreshold(benignScores []float64, alpha float64) (q float64, ok bool) {
	n := len(benignScores)
	k := math.Ceil(float64(n+1) * (1 - alpha))
	if n == 0 || k > float64(n) {
		return math.Inf(1), true
	}
	if math.IsNaN(k) || k < 1 {
		return 0, false
	}
	return objSortedNumeric(benignScores)[int(k)-1], true
}

// CalibrationDigest is the digest of a calibration set (sorted numerically), committed by the grant; it refuses a non-finite score.
func CalibrationDigest(scores []float64) (string, error) {
	return objHash(map[string]any{"v": 1.0, "scores": objFloats(objSortedNumeric(scores))})
}

// ---- 5. harm currency --------------------------------------------------------------------

// Denomination: a harm unit, the amount that saturates it to 1.0, and its weight.
type Denomination struct {
	ID      string
	Ceiling float64
	Weight  float64
}

// HarmReport: the units as given and the weighted saturating normalization in [0, 1].
type HarmReport struct {
	Units      map[string]any
	Normalized float64
}

// ComputeHarmReport reads OWN members of units only (a missing denomination is 0); denominations with a weight or ceiling that is
// not > 0 are skipped; no denomination is normalized 1 (fail closed).
func ComputeHarmReport(units map[string]any, denoms []Denomination) HarmReport {
	num, den := 0.0, 0.0
	for _, d := range denoms {
		if !(d.Weight > 0) || !(d.Ceiling > 0) {
			continue
		}
		u := 0.0
		if v, has := units[d.ID]; has {
			u = objToNumber(v)
		}
		num += float64(d.Weight * math.Min(1, float64(math.Max(0, u)/d.Ceiling)))
		den += d.Weight
	}
	n := 1.0
	if den != 0 {
		n = objClamp01(num / den)
	}
	return HarmReport{Units: units, Normalized: n}
}

// ---- composition -------------------------------------------------------------------------

// RiskCommitments are the digests the grant committed; the verifier supplies the same ones it holds. CalibrationDigest is
// required when a calibration set is used (nil for none).
type RiskCommitments struct {
	RegistryDigest    string
	GraphDigest       string
	CalibrationDigest *string
}

// ObjectiveRiskContext is everything the objective risk is computed from.
type ObjectiveRiskContext struct {
	Registry        InverseRegistry
	AuthorizedKinds []string
	Graph           *ObjResourceGraph
	Scope           *ObjScope
	Embedder        Embedder
	Goal            ObjGoalCommitment
	Commitments     RiskCommitments
	Denominations   []Denomination
	Weights         RiskWeights
	// Taint is the verifier-computed L4 information-flow taint; Age is ageSinceTouch(...). A non-finite value is the worst, 1.
	Taint, Age float64
	// AttestedUncertainty comes from the separate uncertainty-attestation primitive (higher = more uncertain), in [0, 1]; it can
	// only RAISE r. Agent-declared confidence is deliberately not an input. nil is 0.
	AttestedUncertainty *float64
	// Calibration is the committed set of benign raw scores; non-nil makes r the conformal-calibrated value (nil for none).
	Calibration []float64
}

// ObjectiveRiskResult is the objective risk: R in [0, 1] (exactly 1 when Valid is false), why it was rejected, the raw score, the
// RiskInputs, reversibility, blast radius, harm and the digest committing every fact the number was computed from.
type ObjectiveRiskResult struct {
	R              float64
	Valid          bool
	Reasons        []string
	Raw            float64
	Inputs         RiskInputs
	Reversibility  ReversibilityResult
	Blast          BlastRadiusResult
	Harm           HarmReport
	EvidenceDigest string
}

func objReject(reasons []string) ObjectiveRiskResult {
	return ObjectiveRiskResult{
		R: 1, Valid: false, Reasons: reasons, Raw: 1,
		Inputs:        RiskInputs{SemanticDistance: 1, Reversibility: 0, BlastRadius: 1, Taint: 1, Confidence: 0, Age: 1},
		Reversibility: ReversibilityResult{Class: "irreversible", Value: 0},
		Blast:         BlastRadiusResult{Count: 0, Reachable: []string{}, Normalized: 1, Harm: map[string]float64{}},
		Harm:          HarmReport{Units: map[string]any{}, Normalized: 1},
	}
}

// ObjectiveRisk is a pure function of (canonical action, committed context). Any commitment mismatch (registry, graph, goal /
// embedder binding, calibration set) or an un-encodable action is the fail-closed r = 1 with Valid false. The error is only the
// recorded quirk: a graph with a non-finite harm weight, or a calibration set with a non-finite score, has no digest (the
// reference throws there). The blast input is max(count-normalized, harm-normalized).
func ObjectiveRisk(submitted any, ctx *ObjectiveRiskContext) (ObjectiveRiskResult, error) {
	action, err := CanonicalizeAction(submitted)
	if err != nil {
		return objReject([]string{"action: " + err.Error()}), nil
	}
	reasons := []string{}
	if ctx.Registry.Digest() != ctx.Commitments.RegistryDigest {
		reasons = append(reasons, "registry digest does not match the committed digest")
	}
	gd, err := ctx.Graph.Digest()
	if err != nil {
		return ObjectiveRiskResult{}, err
	}
	if gd != ctx.Commitments.GraphDigest {
		reasons = append(reasons, "graph digest does not match the committed digest")
	}
	if ctx.Calibration != nil {
		if ctx.Commitments.CalibrationDigest == nil {
			reasons = append(reasons, "calibration set used without a committed digest")
		} else {
			cd, err := CalibrationDigest(ctx.Calibration)
			if err != nil {
				return ObjectiveRiskResult{}, err
			}
			if cd != *ctx.Commitments.CalibrationDigest {
				reasons = append(reasons, "calibration digest does not match the committed digest")
			}
		}
	}
	dist := CommittedDistanceChecked(action, ctx.Goal, ctx.Embedder)
	if !dist.OK {
		reasons = append(reasons, "goal/embedder: "+dist.Reason)
	}
	if len(reasons) > 0 {
		return objReject(reasons), nil
	}

	rev := ObjectiveReversibility(action.Verb, ctx.Registry, ctx.AuthorizedKinds)
	blast := ComputeBlastRadius(action.Resource, ctx.Graph, ctx.Scope)
	units := make(map[string]any, len(blast.Harm))
	for k, v := range blast.Harm {
		units[k] = v
	}
	harm := ComputeHarmReport(units, ctx.Denominations)
	uncertainty := 0.0
	if ctx.AttestedUncertainty != nil {
		uncertainty = objClamp01(*ctx.AttestedUncertainty)
	}
	harmIn := 0.0
	if len(ctx.Denominations) > 0 && len(blast.Harm) > 0 {
		harmIn = harm.Normalized
	}
	taint, age := 1.0, 1.0
	if objFinite(ctx.Taint) {
		taint = ctx.Taint
	}
	if objFinite(ctx.Age) {
		age = ctx.Age
	}
	inputs := RiskInputs{
		SemanticDistance: dist.Value,
		Reversibility:    rev.Value,
		BlastRadius:      math.Max(blast.Normalized, harmIn),
		Taint:            taint,
		Confidence:       1 - uncertainty,
		Age:              age,
	}
	raw := RiskScore(inputs, ctx.Weights)
	r := raw
	if ctx.Calibration != nil {
		r = Calibrate(raw, ctx.Calibration)
	}
	ad, err := CanonicalActionDigest(action)
	if err != nil {
		return ObjectiveRiskResult{}, err
	}
	var edgeKinds, maxDepth any
	if ctx.Scope != nil {
		if ctx.Scope.EdgeKinds != nil {
			edgeKinds = objStringsAny(objSortedCopy(ctx.Scope.EdgeKinds))
		}
		if ctx.Scope.MaxDepth != nil {
			maxDepth = *ctx.Scope.MaxDepth
		}
	}
	var calib any
	if ctx.Commitments.CalibrationDigest != nil {
		calib = *ctx.Commitments.CalibrationDigest
	}
	ed, err := objHash(map[string]any{
		"action":      ad,
		"scope":       map[string]any{"edgeKinds": edgeKinds, "maxDepth": maxDepth},
		"authorized":  objStringsAny(objSortedUniq(ctx.AuthorizedKinds)),
		"registry":    ctx.Commitments.RegistryDigest,
		"graph":       ctx.Commitments.GraphDigest,
		"goal":        ctx.Goal["commit"],
		"calibration": calib,
		"inputs": map[string]any{
			"semanticDistance": inputs.SemanticDistance, "reversibility": inputs.Reversibility, "blastRadius": inputs.BlastRadius,
			"taint": inputs.Taint, "confidence": inputs.Confidence, "age": inputs.Age,
		},
	})
	if err != nil {
		return ObjectiveRiskResult{}, err
	}
	return ObjectiveRiskResult{R: r, Valid: true, Reasons: []string{}, Raw: raw, Inputs: inputs, Reversibility: rev, Blast: blast, Harm: harm, EvidenceDigest: ed}, nil
}

func objSortedCopy(v []string) []string {
	out := append([]string(nil), v...)
	sortUtf16(out)
	return out
}

// ---- dispute-game oracle -----------------------------------------------------------------

// ObjectiveRiskResolve resolves one disputed input (reversibility_class, reversibility, blastRadius or semanticDistance; any
// other value is unknown) for a frozen open-time snapshot ({action: {action: {verb, resource, params?}}}). It recomputes the input
// from the COMMITTED facts in ctx over the snapshot's canonical action, nothing the agent asserted, and fails CLOSED: any
// commitment mismatch or un-encodable action is valid:false (the dispute is indeterminate and slashes no one). It never fails.
func ObjectiveRiskResolve(ctx *ObjectiveRiskContext, input any, snapshot any) map[string]any {
	bad := func(reason string) map[string]any {
		return map[string]any{"input": input, "valid": false, "reason": reason}
	}
	s, _ := snapshot.(map[string]any)
	outer, _ := s["action"].(map[string]any)
	a, _ := outer["action"].(map[string]any)
	verb, vok := a["verb"].(string)
	resource, rok := a["resource"].(string)
	if !vok || !rok {
		return bad("snapshot action is missing a canonical verb/resource")
	}
	params, isObj := a["params"].(map[string]any)
	if !isObj {
		params = map[string]any{}
	}
	res, err := ObjectiveRisk(ObjAction{Verb: verb, Resource: resource, Params: params}, ctx)
	if err != nil {
		return bad("objective oracle error (fail closed): " + err.Error())
	}
	if !res.Valid {
		reason := strings.Join(res.Reasons, "; ")
		if reason == "" {
			reason = "objective risk could not be reproduced"
		}
		return bad(reason)
	}
	switch input {
	case "reversibility_class":
		return map[string]any{"input": input, "class": res.Reversibility.Class, "valid": true}
	case "reversibility":
		return map[string]any{"input": input, "value": res.Inputs.Reversibility, "valid": true}
	case "blastRadius":
		return map[string]any{"input": input, "value": res.Inputs.BlastRadius, "valid": true}
	case "semanticDistance":
		return map[string]any{"input": input, "value": res.Inputs.SemanticDistance, "valid": true}
	}
	return bad("unknown disputed input: " + jsValueString(input))
}

// ObjectiveRiskOracle is the ObjectiveOracle of the contestable dispute game backed by the objective risk functional.
func ObjectiveRiskOracle(ctx *ObjectiveRiskContext) ObjectiveOracle {
	return func(input string, snapshot map[string]any) map[string]any {
		return ObjectiveRiskResolve(ctx, input, snapshot)
	}
}
