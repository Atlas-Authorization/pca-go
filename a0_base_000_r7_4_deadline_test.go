package pca

import (
	"reflect"
	"testing"
)

// r7-4: mutants that panic (an unrecovered runtime panic is a run error, not a kill). These calls recover the panic themselves and
// turn it into an ordinary failure; the a0_ prefix sorts them ahead of the other callers of the same code.

func r7n4Catch(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if p := recover(); p != nil {
			t.Errorf("%s panicked: %v", what, p)
		}
	}()
	f()
}

func TestR7N4_K5StrsLengths(t *testing.T) {
	r7n4Catch(t, "k5Strs", func() {
		if got := k5Strs([]any{}); !reflect.DeepEqual(got, []string{}) {
			t.Errorf("empty list: %#v", got)
		}
		if got := k5Strs(nil); !reflect.DeepEqual(got, []string{}) {
			t.Errorf("nil: %#v", got)
		}
		if got := k5Strs([]any{"a", "b"}); !reflect.DeepEqual(got, []string{"a", "b"}) {
			t.Errorf("two strings: %#v", got)
		}
	})
}

// The TLV header reads its length byte right after the tag, wherever the element starts.
func TestR7N4_ReadTlvStrictLengthByteIsAfterTheTag(t *testing.T) {
	r7n4Catch(t, "readTlvStrict", func() {
		b := []byte{0xaa, 0x30, 0x01, 0x05}
		got, err := readTlvStrict(b, 1, len(b))
		if err != nil || got != (derTlv{tag: 0x30, start: 3, end: 4}) {
			t.Errorf("got %+v %v", got, err)
		}
		b = []byte{0x30, 0x01, 0x05}
		got, err = readTlvStrict(b, 0, len(b))
		if err != nil || got != (derTlv{tag: 0x30, start: 2, end: 3}) {
			t.Errorf("at 0: %+v %v", got, err)
		}
	})
}

func r7n4HopsOf(pairs ...string) []any {
	out := []any{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, map[string]any{"issuer": pairs[i], "holder": pairs[i+1]})
	}
	return out
}

// A chain none of whose issuers is a blueprint key is allowed with nothing governed (no minimum epoch asked for).
func TestR7N4_CheckBlueprintsUngovernedChain(t *testing.T) {
	r7n4Catch(t, "CheckBlueprints", func() {
		reg := NewBlueprintRegistry(nil, MemoryBlueprintKv())
		d := CheckBlueprints(r7n4HopsOf("root", "a", "a", "b"), reg, jnum(5), "any", nil)
		if d.Decision != "allow" || d.Code != "" || len(d.Governed) != 0 {
			t.Errorf("got %+v", d)
		}
	})
}

// The link check compares the previous hop's holder with the blueprint key; hops after the governed one are not consulted.
func TestR7N4_CheckBlueprintsLinkIsThePreviousHop(t *testing.T) {
	r7n4Catch(t, "CheckBlueprints", func() {
		reg := NewBlueprintRegistry(nil, MemoryBlueprintKv())
		// the registry reads its stored document: seed it directly (a record signed by no operator, for the link check only)
		if err := reg.kv.Update(blueprintKeyDoc("K"), func([]byte) []byte {
			return kvEncode(map[string]any{"id": "bp1", "key": "K1", "status": "active", "ceiling": []any{}})
		}); err != nil {
			t.Fatal(err)
		}
		d := CheckBlueprints(r7n4HopsOf("root", "K1", "K", "mid", "mid", "leaf"), reg, jnum(5), "require", nil)
		if d.Decision != "allow" || len(d.Governed) != 1 || d.Governed[0] != "bp1" {
			t.Errorf("linked: %+v", d)
		}
		d = CheckBlueprints(r7n4HopsOf("root", "other", "K", "mid", "mid", "K1"), reg, jnum(5), "any", nil)
		if d.Decision != "deny" || d.Code != "broken_link" || d.Blueprint != "bp1" {
			t.Errorf("broken: %+v", d)
		}
	})
}
