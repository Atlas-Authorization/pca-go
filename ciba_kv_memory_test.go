package pca

import "testing"

func TestCreateMemoryKvIsACompareAndSwap(t *testing.T) {
	kv := CreateMemoryKv()
	one, two := "1", "2"
	if ok, _ := kv.PutIfEquals("k", &one, "x"); ok {
		t.Fatal("wrote over an absent key with an expected value")
	}
	if ok, _ := kv.PutIfEquals("k", nil, "1"); !ok {
		t.Fatal("first write refused")
	}
	if ok, _ := kv.PutIfEquals("k", nil, "again"); ok {
		t.Fatal("created an existing key")
	}
	if ok, _ := kv.PutIfEquals("k", &two, "x"); ok {
		t.Fatal("wrote over a different value")
	}
	if ok, _ := kv.PutIfEquals("k", &one, "2"); !ok {
		t.Fatal("matching write refused")
	}
	if v, found, _ := kv.Get("k"); !found || v != "2" {
		t.Fatalf("get: %q %v", v, found)
	}
	if _, found, _ := kv.Get("missing"); found {
		t.Fatal("missing key found")
	}
}
