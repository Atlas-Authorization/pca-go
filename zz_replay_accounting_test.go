package pca

import (
	"os"
	"strings"
	"testing"
)

// A shared corpus may be replayed in parts, each owner replaying its functions and skipping the rest. This test, which runs after
// every replay of the package, demands that no function a replay skipped is replayed by no replay at all (by name): a function that
// only ever appears as a skipped case would be covered by nothing. In a run narrowed to a few tests (-run) it has nothing to judge.
func TestNoSkippedFunctionGoesUnreplayed(t *testing.T) {
	replayRec.Lock()
	defer replayRec.Unlock()
	if len(replayRec.ran) < 150 {
		t.Skipf("a partial run: only %d functions were replayed", len(replayRec.ran))
	}
	// functions replayed by a sibling Go module of this repository (its own go.mod): the claim is checked against that module's test
	sibling := map[string]struct{ file, corpus string }{
		"issueArtifactDischarge": {"sigstore/artifact_discharge_test.go", "ref-attest-eat.json.gz"},
	}
	for file, fns := range replayRec.skipped {
		for fn := range fns {
			if s, ok := sibling[fn]; ok && replayRec.ran[fn] == 0 {
				b, err := os.ReadFile(s.file)
				if err != nil || !strings.Contains(string(b), fn) || !strings.Contains(string(b), s.corpus) {
					t.Errorf("%s: %s is claimed by %s, which does not replay it", file, fn, s.file)
				}
				continue
			}
			if replayRec.ran[fn] == 0 {
				t.Errorf("%s: %s is skipped there and replayed by no replay", file, fn)
			}
		}
	}
}
