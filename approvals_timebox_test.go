package pca

import (
	"strings"
	"testing"
)

func TestTimeBoxKeepsAFractionalInstantAndRefusesAHugeOne(t *testing.T) {
	k := apvKey(t, "timebox")
	root, err := MintRoot(k, k.Public, []any{}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := 10.0
	box, err := TimeBox(root, k, 1.5, &now)
	if err != nil {
		t.Fatal(err)
	}
	cvs, _ := box["caveats"].([]any)
	last, _ := cvs[len(cvs)-1].(map[string]any)
	if at, _ := jsNum(last["at"]); at != 11.5 {
		t.Errorf("expires at: %v", last["at"])
	}
	huge := 1e300
	if _, err := TimeBox(root, k, huge, &huge); err == nil || !strings.Contains(err.Error(), "canonicalize: integer outside the safe range") {
		t.Errorf("1e+300: %v", err)
	}
}
