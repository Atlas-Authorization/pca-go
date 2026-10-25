package pca

import (
	"fmt"
	"os"
	"sort"
	"testing"
)

// textDiffs collects the places where Go's refusal reason TEXT differs from the TS reference. The reference wording is the
// contract: any difference fails the test. PCA_TEXTDIFF_DUMP=<file> appends the distinct pairs to the file instead of failing (porting aid).
type textDiffs struct {
	n    int
	seen map[string]bool
	list []string
}

func (d *textDiffs) add(want, got string) {
	d.n++
	if d.seen == nil {
		d.seen = map[string]bool{}
	}
	k := fmt.Sprintf("\n  want %q\n  got  %q", want, got)
	if !d.seen[k] {
		d.seen[k] = true
		d.list = append(d.list, k)
	}
}

func (d *textDiffs) finish(t *testing.T) {
	t.Helper()
	sort.Strings(d.list)
	if d.n == 0 {
		return
	}
	if p := os.Getenv("PCA_TEXTDIFF_DUMP"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err == nil {
			fmt.Fprintf(f, "### %s %d diffs, %d distinct", t.Name(), d.n, len(d.list))
			for _, k := range d.list {
				fmt.Fprint(f, k)
			}
			fmt.Fprintln(f)
			f.Close()
		}
		return
	}
	t.Errorf("%d reason texts differ from the reference (%d distinct)%v", d.n, len(d.list), d.list)
}
