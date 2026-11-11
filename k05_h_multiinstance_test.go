package pca

import (
	"strings"
	"testing"
)

const multiInstanceText = "multiInstance requires a shared state store (a process-scoped store lets one PCActn replay once per instance)"

func TestH16_MultiInstanceNeedsASharedStore(t *testing.T) {
	yes, no := true, false
	if got := NewMemoryStateStore().Scope(); got != ScopeProcess {
		t.Errorf("memory store scope %q", got)
	}
	if got := (&SQLStateStore{}).Scope(); got != ScopeShared {
		t.Errorf("sql store scope %q", got)
	}
	// process store + multiInstance=true: refused
	if got := multiInstanceError(NewMemoryStateStore(), &yes); got != multiInstanceText {
		t.Errorf("process + true: %q", got)
	}
	// process store: default (nil) and explicit false are fine (one process on purpose)
	if got := multiInstanceError(NewMemoryStateStore(), nil); got != "" {
		t.Errorf("process + default: %q", got)
	}
	if got := multiInstanceError(NewMemoryStateStore(), &no); got != "" {
		t.Errorf("process + false: %q", got)
	}
	// shared store: ok with true, false, default; a store that declares nothing is shared
	if got := multiInstanceError(&SQLStateStore{}, &yes); got != "" {
		t.Errorf("shared + true: %q", got)
	}
	if got := multiInstanceError(unscopedStore{}, &yes); got != "" {
		t.Errorf("undeclared + true: %q", got)
	}
	if got := multiInstanceError(nil, &yes); got != "" {
		t.Errorf("no store: %q", got)
	}
	// Authorize: the configuration is reported as a missing component (deny)
	in := AuthorizeInput{Risk: InsecureCalmRisk, Audience: "a", ResolveGrant: func(string) (map[string]any, error) { return nil, nil },
		IsRevoked: func(_, _ map[string]any) (bool, error) { return false, nil }, StateStore: NewMemoryStateStore(), MultiInstance: &yes}
	miss := MissingAuthorizeComponents(in)
	if len(miss) != 1 || miss[0] != multiInstanceText {
		t.Errorf("missing: %v", miss)
	}
	in.MultiInstance = nil
	if miss := MissingAuthorizeComponents(in); len(miss) != 0 {
		t.Errorf("default: %v", miss)
	}
	// RequirePCA panics at construction
	func() {
		defer func() {
			r := recover()
			if s, ok := r.(string); !ok || !strings.Contains(s, multiInstanceText) {
				t.Errorf("RequirePCA panic: %v", r)
			}
		}()
		RequirePCA(RequirePCAOptions{Authorize: &AuthorizeOptions{Risk: InsecureCalmRisk, StateStore: NewMemoryStateStore(), MultiInstance: &yes}})
	}()
}

type unscopedStore struct{}

func (unscopedStore) Claim(string, int64) (ClaimResult, error) { return ClaimResult{OK: true}, nil }
