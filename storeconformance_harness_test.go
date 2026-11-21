package pca

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreRecordersRoundTrip(t *testing.T) {
	mem := &StoreMemoryRecorder{}
	a := mem.Invoke("c0", "consume", "k", 5, 50)
	b := mem.Invoke("c1", "consume", "k", 6, 60)
	mem.Complete(a, "true")
	mem.Complete(b, "unknown")
	ops := mem.Ops()
	if len(ops) != 2 || ops[0].Res != "true" || math.IsInf(ops[0].Ret, 1) || ops[1].Res != "unknown" || !math.IsInf(ops[1].Ret, 1) {
		t.Fatalf("memory recorder: %+v %+v", ops[0], ops[1])
	}

	path := filepath.Join(t.TempDir(), "history.jsonl")
	rec, err := NewStoreFileRecorder(path, "p1")
	if err != nil {
		t.Fatal(err)
	}
	x := rec.Invoke("c0", "consume", "k", 5, 50)
	y := rec.Invoke("c1", "advance", "k2", 3, 3)
	z := rec.Invoke("c2", "consume", "k", 7, 70) // never completed: the process "died"
	rec.Complete(x, "false")
	rec.Complete(y, "unknown")
	_ = z
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`["r","p1",9`) // a torn last line
	_ = f.Close()
	text, _ := os.ReadFile(path)
	got, torn, pending := StoreParseHistory(string(text))
	if len(got) != 3 || torn != 1 || pending != 1 {
		t.Fatalf("parsed %d ops, %d torn, %d pending", len(got), torn, pending)
	}
	if got[0].Res != "false" || got[0].Client != "c0" || got[0].Lo != 5 || got[0].W != 50 || got[0].Ret < got[0].Call {
		t.Fatalf("completed op: %+v", got[0])
	}
	if got[1].Res != "unknown" || got[1].Kind != "advance" || !math.IsInf(got[1].Ret, 1) || got[2].Res != "unknown" {
		t.Fatalf("open ops: %+v %+v", got[1], got[2])
	}
	if lines := StoreFormatOps(got); len(lines) != 3 {
		t.Fatalf("format: %v", lines)
	}
}
