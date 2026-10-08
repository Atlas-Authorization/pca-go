package pca

// net/http middleware for Proof-Carrying Authority. This layers transport concerns (where the
// PCActn comes from, how failures surface) on top of the existing offline verifier,
// VerifyPCActnCore; it does NOT re-implement any canonicalization, Ed25519 or chain logic.
//
// Note on types: this package models both the PCActn and a capability/grant as map[string]any
// (see ValidateWireV2 / VerifyChain), so the middleware mirrors that. RequirePCAOptions.ResolveGrant
// therefore returns a *grant capability* as map[string]any and FromContext returns the PCActn as
// map[string]any rather than a dedicated struct.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PCAHeader is the request header carrying a base64url(JSON) PCActn.
const PCAHeader = "PCA-Action"

// ctxKey is the unexported context key under which a successful verification is stashed.
type ctxKey struct{}

// contextValue holds what a passing request carries to downstream handlers.
type contextValue struct {
	verdict *Verdict
	pcactn  map[string]any
}

// RequirePCAOptions configures the RequirePCA middleware.
//
//   - Audience is this resource server / instance id; it is checked against the PCActn's signed `aud`.
//   - ResolveGrant maps a PCActn's grant_ref to the root grant capability (the chain is rooted at it).
//     Returning an error or a nil grant is treated as an unknown grant (HTTP 401).
//   - Now returns the current time in epoch milliseconds; nil defaults to time.Now().UnixMilli().
type RequirePCAOptions struct {
	Audience     string
	ResolveGrant func(grantRef string) (map[string]any, error)
	Now          func() int64
}

// FromContext returns the Verdict and the verified PCActn stashed by a passing RequirePCA
// middleware, and whether one was present.
func FromContext(ctx context.Context) (*Verdict, map[string]any, bool) {
	cv, ok := ctx.Value(ctxKey{}).(*contextValue)
	if !ok || cv == nil {
		return nil, nil, false
	}
	return cv.verdict, cv.pcactn, true
}

// decodeB64u accepts either the raw (unpadded) or padded base64url alphabet.
func decodeB64u(s string) ([]byte, bool) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, true
	}
	return nil, false
}

// extractPCActn pulls the PCActn from the PCA-Action header (base64url -> JSON) or, failing a header,
// from a JSON request body of the shape {"pcactn": {...}}. Reading the body is non-destructive: it is
// buffered and restored so downstream handlers still see it. The returned reason is only meaningful
// when ok is false.
func extractPCActn(r *http.Request) (pcactn map[string]any, reason string, ok bool) {
	if h := r.Header.Get(PCAHeader); h != "" {
		raw, dok := decodeB64u(h)
		if !dok {
			return nil, "PCA-Action header is not valid base64url", false
		}
		p, err := ParsePCActn(string(raw))
		if err != nil {
			return nil, "PCA-Action header is not a valid PCActn JSON object", false
		}
		return p, "", true
	}

	if r.Body == nil || r.Body == http.NoBody {
		return nil, "no PCActn presented (missing PCA-Action header and request body)", false
	}

	buf, err := io.ReadAll(io.LimitReader(r.Body, int64(MaxJSONChars)+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(buf)) // restore for downstream handlers
	if err != nil || len(buf) == 0 {
		return nil, "no PCActn presented (missing PCA-Action header and request body)", false
	}

	v, perr := StrictParse(string(buf))
	if perr != nil {
		return nil, "request body is not valid strict JSON", false
	}
	m, isObj := v.(map[string]any)
	if !isObj {
		return nil, "request body is not a JSON object", false
	}
	pv, has := m["pcactn"]
	if !has {
		return nil, "request body has no 'pcactn' field", false
	}
	p, isObj := pv.(map[string]any)
	if !isObj {
		return nil, "'pcactn' is not a JSON object", false
	}
	return p, "", true
}

// writePCAError writes a JSON error body plus an RFC-6750-shaped WWW-Authenticate challenge.
func writePCAError(w http.ResponseWriter, status int, code, desc string, verdict *Verdict) {
	challenge := fmt.Sprintf("PCA realm=%q, error=%q", "pca", code)
	if desc != "" {
		challenge += fmt.Sprintf(", error_description=%q", desc)
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	body := map[string]any{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	if verdict != nil {
		if verdict.Reason != "" {
			body["reason"] = verdict.Reason
		}
		body["checks"] = verdict.Checks
	}
	_ = json.NewEncoder(w).Encode(body)
}

// RequirePCA returns standard net/http middleware that requires a valid Proof-Carrying Authority
// action on every request it guards.
//
// On success the Verdict and PCActn are placed in the request context (read them with FromContext)
// and the next handler runs. On failure it responds with a JSON body and a WWW-Authenticate: PCA
// challenge, using status:
//
//   - 401 when no PCActn is presented, it cannot be decoded, or its grant_ref is unknown;
//   - 403 when a well-formed PCActn resolves a grant but fails verification.
func RequirePCA(opts RequirePCAOptions) func(http.Handler) http.Handler {
	now := opts.Now
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pcactn, reason, ok := extractPCActn(r)
			if !ok {
				writePCAError(w, http.StatusUnauthorized, "invalid_request", reason, nil)
				return
			}

			grantRef, _ := pcactn["grant_ref"].(string)
			if grantRef == "" {
				writePCAError(w, http.StatusUnauthorized, "invalid_request", "PCActn has no grant_ref", nil)
				return
			}
			if opts.ResolveGrant == nil {
				writePCAError(w, http.StatusUnauthorized, "invalid_request", "no grant resolver configured", nil)
				return
			}
			grant, err := opts.ResolveGrant(grantRef)
			if err != nil || grant == nil {
				writePCAError(w, http.StatusUnauthorized, "unknown_grant", "grant_ref does not resolve to a known grant", nil)
				return
			}

			verdict, verr := VerifyPCActnCore(pcactn, grant, now(), opts.Audience)
			if verr != nil {
				writePCAError(w, http.StatusForbidden, "verification_error", verr.Error(), nil)
				return
			}
			if !verdict.Allow {
				writePCAError(w, http.StatusForbidden, "insufficient_authority", verdict.Reason, &verdict)
				return
			}

			ctx := context.WithValue(r.Context(), ctxKey{}, &contextValue{verdict: &verdict, pcactn: pcactn})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
