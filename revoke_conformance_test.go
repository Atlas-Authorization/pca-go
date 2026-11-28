package pca

import (
	"path/filepath"
	"testing"
)

func TestRevocationStoreCasesMemory(t *testing.T) {
	for _, c := range RevocationStoreCases(func() (RevocationStore, error) { return NewMemoryRevocationStore(), nil }, nil) {
		if err := c.Run(); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
}

func TestRevocationStoreCasesFile(t *testing.T) {
	path := ""
	open := func() (RevocationStore, error) {
		path = filepath.Join(t.TempDir(), "revocations.json")
		return OpenFileRevocationStore(path)
	}
	reopen := func(RevocationStore) (RevocationStore, error) { return OpenFileRevocationStore(path) }
	cases := RevocationStoreCases(open, reopen)
	if len(cases) != 10 {
		t.Fatalf("%d cases, want 10 (the durability case included)", len(cases))
	}
	for _, c := range cases {
		if err := c.Run(); err != nil {
			t.Errorf("%s: %v", c.Name, err)
		}
	}
}

// a store that forgets what it was given must fail the cases
type forgetfulRevocationStore struct{ RevocationStore }

func (forgetfulRevocationStore) Add(RevocationEntry) error { return nil }

func TestRevocationStoreCasesCatchABrokenStore(t *testing.T) {
	failed := 0
	for _, c := range RevocationStoreCases(func() (RevocationStore, error) { return forgetfulRevocationStore{NewMemoryRevocationStore()}, nil }, nil) {
		if c.Run() != nil {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("a store that drops every add passed the cases")
	}
}
