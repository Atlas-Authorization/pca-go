package pca

// Testing kit for Proof-Carrying Authority: a fake verifier that runs the REAL core verifier against a PCActn, assertion helpers,
// a tamper helper, an in-memory state store and the adapter acceptance constants and route mapping. Nothing here authorizes
// anything. FakeVerify stands in for the resource server by rooting the check at the PCActn's own grant and accepting the PCActn's
// own audience by default, so a clean round trip verifies; it is the real verifier, not a weakened one, so tampering is caught
// exactly as in production. A grant lifted from the artifact is never trusted for a post-quantum root (no pin exists).

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// AdapterAcceptanceAudience is the audience of the adapter acceptance matrix.
const AdapterAcceptanceAudience = "payments-rs"

// AdapterAcceptanceExpected is the outcome every adapter must produce per scenario: status, whether the handler ran, whether the
// attached operation matches.
func AdapterAcceptanceExpected() map[string]any {
	outcome := func(status int, ran, bound bool) map[string]any {
		return map[string]any{"status": status, "handlerRan": ran, "bound": bound}
	}
	out := map[string]any{"valid_first": outcome(200, true, true), "replay_second": outcome(403, false, false)}
	for _, k := range []string{"over_limit_predicate", "over_limit_max_spend", "body_differs", "other_operation", "escalate_unanswered", "missing_revocation", "missing_store"} {
		out[k] = outcome(403, false, false)
	}
	return out
}

// ---- fake verifier ---------------------------------------------------------------------------------------------------------------------

var tkNoGrant = errors.New("fakeVerify: PCActn has an empty cap_chain and no grant was supplied via opts.grant")

// tkLiftGrant is pcactn.cap_chain[0] as JavaScript reads it; an error where JavaScript would find nothing.
func tkLiftGrant(pcactn any) (any, error) {
	m, ok := pcactn.(map[string]any)
	if !ok {
		return nil, tkNoGrant
	}
	var first any
	switch c := m["cap_chain"].(type) {
	case []any:
		if len(c) > 0 {
			first = c[0]
		}
	case string:
		if c != "" {
			first = string([]rune(c)[:1])
		}
	case map[string]any:
		first = c["0"]
	}
	if !sbxTruthy(first, first != nil) {
		return nil, tkNoGrant
	}
	return first, nil
}

// FakeVerifyOptions: Audience nil = the PCActn's own audience (also what an explicit JSON null means: opt out, accept the own
// audience); a non-nil string forces that audience. Now is epoch ms. Grant nil = the PCActn's own chain root.
type FakeVerifyOptions struct {
	Audience *string
	Now      int64
	Grant    map[string]any
}

// FakeVerify runs the real core verifier against pcactn, rooting the check at opts.Grant or the PCActn's own chain root and
// defaulting the verifier audience to the PCActn's own `aud`. It fails when there is no grant to root at.
func FakeVerify(pcactn any, opts FakeVerifyOptions) (Verdict, error) {
	var root any
	lifted := opts.Grant == nil
	if lifted {
		g, err := tkLiftGrant(pcactn)
		if err != nil {
			return Verdict{}, err
		}
		root = g
	} else {
		root = opts.Grant
	}
	pm, _ := pcactn.(map[string]any)
	aud := ""
	if opts.Audience != nil {
		aud = *opts.Audience
	} else if own, ok := pm["aud"].(string); ok {
		aud = own // a non-string audience stays "" and fails the wire check
	}
	rm, isMap := root.(map[string]any)
	if !isMap {
		return Verdict{Allow: false, Checks: map[string]bool{"wire": false}, Reason: "wire: the grant is not an object"}, nil
	}
	if alg, has := rm["alg"]; lifted && has && alg != "ed25519" {
		return Verdict{Allow: false, Checks: map[string]bool{"cap_chain": false},
			Reason: "cap_chain: root suite needs a verifier-side PQ pin; a grant lifted from the artifact is never trusted for it"}, nil
	}
	if pm == nil {
		return Verdict{Allow: false, Checks: map[string]bool{"wire": false}, Reason: "wire: not a PCActn"}, nil
	}
	now := opts.Now
	if now == 0 {
		now = time.Now().UnixMilli() // the reference's default clock
	}
	v, err := VerifyPCActnCoreWith(pm, rm, now, aud, VerifyOptions{InsecureSkipPlanRootCheck: true})
	if err != nil {
		return Verdict{Allow: false, Reason: err.Error()}, nil
	}
	return v, nil
}

func tkFailing(v Verdict) []string {
	var out []string
	for name, ok := range v.Checks {
		if !ok {
			out = append(out, name)
		}
	}
	return sbxSort(out)
}

// ExpectVerifies asserts that pcactn verifies: it fails naming the failing checks and the reason, else returns the Verdict.
func ExpectVerifies(pcactn any, opts FakeVerifyOptions) (Verdict, error) {
	v, err := FakeVerify(pcactn, opts)
	if err != nil {
		return v, err
	}
	if !v.Allow {
		why := ""
		if v.Reason != "" {
			why = " — " + v.Reason
		}
		return v, fmt.Errorf("expectVerifies: PCActn was denied. failing checks: [%s]%s", strings.Join(tkFailing(v), ", "), why)
	}
	return v, nil
}

// ExpectDenied is the inverse of ExpectVerifies: it fails when pcactn unexpectedly verifies.
func ExpectDenied(pcactn any, opts FakeVerifyOptions) (Verdict, error) {
	v, err := FakeVerify(pcactn, opts)
	if err != nil {
		return v, err
	}
	if v.Allow {
		return v, errors.New("expectDenied: PCActn verified but was expected to be denied")
	}
	return v, nil
}

// ---- in-memory state store ---------------------------------------------------------------------------------------------------------------

// MemoryTestStateStore is an in-memory per-holder state store (replay counter, budget): a drop-in budget store for tests. Nothing
// persists.
type MemoryTestStateStore struct{ m map[string]any }

// NewMemoryTestStateStore returns an empty store.
func NewMemoryTestStateStore() *MemoryTestStateStore {
	return &MemoryTestStateStore{m: map[string]any{}}
}

// Get returns the state under key, or nil.
func (s *MemoryTestStateStore) Get(key string) any { return s.m[key] }

// Put stores state under key.
func (s *MemoryTestStateStore) Put(key string, state any) { s.m[key] = state }

// ---- tampering -----------------------------------------------------------------------------------------------------------------------------

func tkDecode(s string) (map[string]any, error) {
	if len(s) > MaxArtifactBytes { // FIRST: before any parsing
		return nil, errors.New(ArtifactSizeReason)
	}
	v, err := StrictParse(s)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("decodePCActn: not an object")
	}
	return m, nil
}

// Tamper decodes an encoded PCActn (strict profile, size-capped), lets mutate corrupt the object in place, then re-encodes it so a
// test can assert the corruption is caught. A change touching the signed body breaks `leaf_signature`.
func Tamper(encoded string, mutate func(rec map[string]any) error) (string, error) {
	dec, err := tkDecode(encoded)
	if err != nil {
		return "", err
	}
	rec := normalizeJSONKeep(dec).(map[string]any)
	if err := mutate(rec); err != nil {
		return "", err
	}
	again, err := tkDecode(schemaStringify(rec))
	if err != nil {
		return "", err
	}
	return Canonicalize(again)
}

// ---- adapter acceptance routes ----------------------------------------------------------------------------------------------------------------

var (
	tkSpecial   = setOf("http", "https", "ftp", "ws", "wss", "file")
	tkSchemeRx  = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.\-]*):`)
	tkErrInvURL = errors.New("Invalid URL")
)

// tkPathname is the pathname of url resolved against a base origin as a WHATWG URL parser yields it, for the shapes a request
// carries (absolute and scheme-relative URLs, rooted and relative paths, dot segments, query, fragment).
// shortcut: percent-encoding of the path is not reproduced (an encoded spelling never equals a route); upgrade if routes ever
// contain non-ASCII.
func tkPathname(url string) (string, error) {
	s := strings.TrimFunc(url, func(r rune) bool { return r <= 0x20 })
	s = strings.NewReplacer("\t", "", "\n", "", "\r", "").Replace(s)
	rest := s
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		rest = s[:i]
	}
	var path string
	if m := tkSchemeRx.FindStringSubmatch(rest); m != nil {
		scheme := strings.ToLower(m[1])
		rest = rest[len(m[0]):]
		switch {
		case !tkSpecial[scheme]:
			switch {
			case strings.HasPrefix(rest, "//"):
				if end := strings.Index(rest[2:], "/"); end < 0 {
					path = ""
				} else {
					path = rest[2+end:]
				}
			case strings.HasPrefix(rest, "/"):
				path = rest
			default:
				return rest, nil // opaque path: never a route
			}
		case scheme == "file":
			rest = strings.ReplaceAll(rest, `\`, "/")
			if strings.HasPrefix(rest, "//") {
				if end := strings.Index(rest[2:], "/"); end < 0 {
					path = "/"
				} else {
					path = rest[2+end:]
				}
			} else if strings.HasPrefix(rest, "/") {
				path = rest
			} else {
				path = "/" + rest
			}
		default:
			rest = strings.ReplaceAll(rest, `\`, "/")
			if scheme == "http" && !strings.HasPrefix(rest, "//") { // same scheme as the base: relative
				if strings.HasPrefix(rest, "/") {
					path = rest
				} else {
					path = "/" + rest
				}
			} else {
				p, err := tkAuthorityPath(strings.TrimLeft(rest, "/"))
				if err != nil {
					return "", err
				}
				path = p
			}
		}
	} else {
		rest = strings.ReplaceAll(rest, `\`, "/")
		switch {
		case strings.HasPrefix(rest, "//"):
			p, err := tkAuthorityPath(strings.TrimLeft(rest[2:], "/"))
			if err != nil {
				return "", err
			}
			path = p
		case strings.HasPrefix(rest, "/"):
			path = rest
		default:
			path = "/" + rest
		}
	}
	if path == "" {
		return "", nil
	}
	var out []string
	segs := strings.Split(path[1:], "/")
	for i, seg := range segs {
		low := strings.ToLower(seg)
		last := i == len(segs)-1
		switch low {
		case "..", ".%2e", "%2e.", "%2e%2e":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			if last {
				out = append(out, "")
			}
		case ".", "%2e":
			if last {
				out = append(out, "")
			}
		default:
			out = append(out, seg)
		}
	}
	return "/" + strings.Join(out, "/"), nil
}

// tkAuthorityPath splits "host/path" and returns the path ("/" when there is none); an empty host is invalid.
func tkAuthorityPath(t string) (string, error) {
	end := strings.Index(t, "/")
	host := t
	if end >= 0 {
		host = t[:end]
	}
	if host == "" {
		return "", tkErrInvURL
	}
	if end < 0 {
		return "/", nil
	}
	return t[end:], nil
}

// AcceptanceOperation is the server's mapping from request to operation: a route table on method + path with the JSON body as
// params. req is {method, url, body}. It returns nil for an unknown route or a body that is not an object, else {verb, resource,
// params}; a URL the parser rejects is an error.
func AcceptanceOperation(req map[string]any) (map[string]any, error) {
	path := ""
	if u, ok := req["url"].(string); ok {
		p, err := tkPathname(u)
		if err != nil {
			return nil, err
		}
		path = p
	}
	m, present := req["method"]
	key := strings.ToUpper(sbxText(m, present)) + " " + path
	var verb string
	switch key {
	case "POST /payments":
		verb = "payments.send"
	case "POST /refunds":
		verb = "payments.refund"
	default:
		return nil, nil
	}
	body, ok := req["body"].(map[string]any)
	if !ok {
		return nil, nil
	}
	return map[string]any{"verb": verb, "resource": "payments", "params": body}, nil
}
