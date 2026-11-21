package pca

import "testing"

func TestPartD2SmallSurfaces(t *testing.T) {
	if got := ActionUnitTagOf(map[string]any{"kind": "count"}); got["kind"] != "count" || len(got) != 1 {
		t.Fatal("plain unit")
	}
	if ActionUnitTagOf(map[string]any{"kind": "money"}) != nil {
		t.Fatal("money without currency has no tag")
	}
	if g := ActionUnitTagOf(map[string]any{"kind": "money", "ccy": "USD", "exp": 2.0}); g["currency"] != "USD" || g["exponent"] != 2.0 {
		t.Fatal("money unit")
	}
	if len(ProvLevels) != 5 || ProvLevels[4] != "agent" {
		t.Fatal("levels")
	}
	b := NewInMemoryBondAccount(map[string]float64{"a": 1.5})
	if b.Debit("a", 2) == nil || b.Debit("a", -1) == nil || b.Credit("a", 1) != nil || b.Debit("a", 2.5) != nil || b.BalanceOf("a") != 0 {
		t.Fatal("bond account")
	}
	s := NewMemoryIntentSessionStore()
	err := s.WithSession("s", func(tx SessionTx) error {
		if err := tx.Append(map[string]any{"id": "e1", "status": "reserved"}); err != nil {
			return err
		}
		if tx.Append(map[string]any{"id": "e1"}) == nil {
			t.Fatal("duplicate id accepted")
		}
		if ok, _ := tx.SetStatus("e1", "committed"); !ok {
			t.Fatal("set status")
		}
		return nil
	})
	if err != nil || s.Durable() || s.Snapshot("s")[0]["status"] != "committed" {
		t.Fatal("session store")
	}
}
