package pcasigstore

import "testing"

// The entry body and the in-toto statement are read with the duplicate-only check (the reference's parseNoDuplicates): JSON.parse
// keeps the last repeated member while only the first is signed. The throw becomes `tlog_body: fail closed: duplicate key "kind"`
// and `statement: fail closed: duplicate key "_type"` through the stage the caller set.
func TestDecodeOneJSONNoDup(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`{"kind":"x","kind":"hashedrekord","apiVersion":"0.0.1"}`, `duplicate key "kind"`},
		{`{"_type":"x","_type":"https://in-toto.io/Statement/v1"}`, `duplicate key "_type"`},
		{`{"spec":{"a":1,"a":2}}`, `duplicate key "a"`},
	} {
		if err := catch(func() { decodeOneJSONNoDup([]byte(c.in)) }); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v, want %q", c.in, err, c.want)
		}
	}
	// numbers stay as written and a text that is not JSON is reported as not JSON (the syntax error comes first)
	if v, ok := decodeOneJSONNoDup([]byte(`{"n":1e3,"m":8.0}`)); !ok || v == nil {
		t.Error("1e3 and 8.0 stay accepted")
	}
	if err := catch(func() {
		if _, ok := decodeOneJSONNoDup([]byte(`{"a":1,"a":`)); ok {
			t.Error("truncated text parsed")
		}
	}); err != nil {
		t.Errorf("a syntax error is not a duplicate: %v", err)
	}
}
