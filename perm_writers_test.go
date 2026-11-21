package pca

import (
	"io/fs"
	"path/filepath"
	"testing"
)

// Every file the library writes with mode 0600 is owner-only on every platform (on Windows through an owner-only protected access
// list, since the mode bits mean nothing there).

func assertAllOwnerOnly(t *testing.T, dir string) {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		n++
		if oerr := OwnerOnly(p); oerr != nil {
			t.Errorf("%s is not private to its owner: %v", p, oerr)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatalf("no file was written under %s", dir)
	}
}

func TestApprovalFileStoreIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	st := NewFileApprovalStore(filepath.Join(dir, "approvals.json"))
	if ok, err := st.Cas("k", 0, "v"); err != nil || !ok {
		t.Fatalf("cas: %v %v", ok, err)
	}
	assertAllOwnerOnly(t, dir)
}

func TestApprovalDirectoryKvIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	kv, err := NewDirectoryKv(filepath.Join(dir, "kv"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := kv.PutIfEquals("k", nil, "v"); err != nil || !ok {
		t.Fatalf("put: %v %v", ok, err)
	}
	assertAllOwnerOnly(t, dir)
}

func TestRevocationFileStoreIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenFileRevocationStore(filepath.Join(dir, "revocations.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Add(RevocationEntry{"kind": "cap", "value": "c1", "reason": "", "revokedAt": jsNumber(1)}); err != nil {
		t.Fatal(err)
	}
	assertAllOwnerOnly(t, dir)
}

func TestMeshWitnessFileStoreIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	st := NewFileMeshWitnessStore(filepath.Join(dir, "witness.json"))
	if err := st.Save(map[string]any{"heads": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	assertAllOwnerOnly(t, dir)
}

func TestDurableStateFilesAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenDurableState(DurableStateOptions{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("k", "v"); err != nil {
		t.Fatal(err)
	}
	assertAllOwnerOnly(t, dir)
}

func TestStoreConformanceRecorderFileIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	r, err := NewStoreFileRecorder(filepath.Join(dir, "ops.jsonl"), "p")
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	assertAllOwnerOnly(t, dir)
}
