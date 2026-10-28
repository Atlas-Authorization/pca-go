package pca

import (
	"net/http"
	"sync"
)

// ProtectOptions are the inputs of Protect: only what is specific to your server. Everything else gets a secure default.
//
//   - Audience is this resource server's id (the proof's signed `aud` must equal it).
//   - Operation maps the request to the operation your route executes (from your routing and body, never from the proof).
//   - Grants are the grants this server accepts, looked up by their "id"; or set ResolveGrant to look one up yourself.
//     Never resolve a grant from the request. With neither, every proof is refused as an unknown grant.
//   - IsRevoked is an extra revocation source, consulted in addition to Protected.Revoke.
//   - Authorize, when set, is the base for the AuthorizeOptions: any field you set there wins over the default
//     (StateStore, IsRevoked, Plan, Operation). Now is optional (epoch milliseconds; default the system clock).
//
// Defaults: an in-process MemoryStateStore (replay counters; use SQLStateStore for several workers), a revocation source,
// and the single-step plan (the grant alone limits what runs). The TypeScript protect() also prices risk from the
// connector catalog; Go has no catalog, so no risk is priced here: add what your grant's thresholds need through
// Authorize.Context.
type ProtectOptions struct {
	Audience     string
	Operation    func(r *http.Request, body []byte) (*Operation, error)
	Grants       []map[string]any
	ResolveGrant func(grantRef string) (map[string]any, error)
	IsRevoked    func(pcactn, grant map[string]any) (bool, error)
	Authorize    *AuthorizeOptions
	Now          func() int64
}

// Protected is the result of Protect.
type Protected struct {
	// Options go to RequirePCA (or use Middleware).
	Options RequirePCAOptions

	mu      sync.Mutex
	revoked map[string]bool
}

// Middleware is RequirePCA(p.Options).
func (p *Protected) Middleware() func(http.Handler) http.Handler { return RequirePCA(p.Options) }

// Revoke refuses every further action under this grant id.
func (p *Protected) Revoke(grantID string) {
	p.mu.Lock()
	p.revoked[grantID] = true
	p.mu.Unlock()
}

func (p *Protected) isRevoked(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revoked[id]
}

// Protect is the secure defaults for a resource server, in one call:
//
//	p := pca.Protect(pca.ProtectOptions{Audience: "ins_acme", Grants: grants, Operation: operationFor})
//	mux.Handle("/refunds", p.Middleware()(handler))
//	p.Revoke(grantID) // later: every action under that grant is refused
//
// It is still Authorize: the proof is bound to the operation your route executes, and anything missing denies.
func Protect(o ProtectOptions) *Protected {
	p := &Protected{revoked: map[string]bool{}}
	az := AuthorizeOptions{}
	if o.Authorize != nil {
		az = *o.Authorize
	}
	if az.StateStore == nil {
		az.StateStore = NewMemoryStateStore()
	}
	if az.Operation == nil {
		az.Operation = o.Operation
	}
	if az.Plan == "" {
		az.Plan = PlanSingleStep
	}
	if az.IsRevoked == nil {
		extra := o.IsRevoked
		az.IsRevoked = func(pcactn, grant map[string]any) (bool, error) {
			// a grant without a string id cannot be looked up, so it is treated as revoked (fail closed)
			id, ok := grant["id"].(string)
			if !ok || p.isRevoked(id) {
				return true, nil
			}
			if extra != nil {
				return extra(pcactn, grant)
			}
			return false, nil
		}
	}
	resolve := o.ResolveGrant
	if resolve == nil {
		byID := map[string]map[string]any{}
		for _, g := range o.Grants {
			if id, ok := g["id"].(string); ok {
				byID[id] = g
			}
		}
		resolve = func(ref string) (map[string]any, error) { return byID[ref], nil }
	}
	p.Options = RequirePCAOptions{Audience: o.Audience, ResolveGrant: resolve, Now: o.Now, Authorize: &az}
	return p
}
