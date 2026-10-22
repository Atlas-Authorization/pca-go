package pca

// Differential kill test for saferegex.go against the TypeScript reference (packages/pca/src/safe-regex.ts +
// predicates.ts): every pattern of the shared corpus (tools/pca-audit/java-mutate/k042-saferegex-oracle.mjs) must compile
// to the EXACT same NFA program (instruction for instruction) or be refused alike, get the same isSafeRegexSource verdict,
// and full-match every recorded subject with the same true / false / budget-refused answer.

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

func k042Unhex(h string) []uint16 {
	if h == "-" {
		return []uint16{}
	}
	out := make([]uint16, 0, len(h)/4)
	for k := 0; k+4 <= len(h); k += 4 {
		v, _ := strconv.ParseUint(h[k:k+4], 16, 16)
		out = append(out, uint16(v))
	}
	return out
}

func k042DumpProg(prog []reInst) string {
	var sb strings.Builder
	for k, ins := range prog {
		if k > 0 {
			sb.WriteByte(';')
		}
		fmt.Fprintf(&sb, "%d,%d,%d,", ins.op, ins.x, ins.y)
		if ins.set == nil {
			sb.WriteString("-,-")
			continue
		}
		if ins.set.negated {
			sb.WriteString("1,")
		} else {
			sb.WriteString("0,")
		}
		if len(ins.set.ranges) == 0 {
			sb.WriteByte('E')
		}
		for r, rg := range ins.set.ranges {
			if r > 0 {
				sb.WriteByte(':')
			}
			fmt.Fprintf(&sb, "%d-%d", rg[0], rg[1])
		}
	}
	s := sb.String()
	if len(s) > 1000 {
		h := sha256.Sum256([]byte(s))
		s = "H" + hex.EncodeToString(h[:])
	}
	return s
}

func TestK042SafeRegexCorpusMatchesTheReference(t *testing.T) {
	k042RequireCovers(t, "saferegex.go")
	f, err := os.Open("testdata/k042-saferegex.txt.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 1<<20), 1<<26)
	var fails []string
	patterns, compiled, safe, matches := 0, 0, 0, 0
	var pat []uint16
	var cur []reInst
	var have bool
	for sc.Scan() {
		fl := strings.Split(sc.Text(), " ")
		if fl[0] == "P" {
			patterns++
			pat = k042Unhex(fl[1])
			wantSafe := fl[2] == "1"
			cur = compileSafeRegex(pat)
			have = cur != nil
			got := "N"
			if have {
				got = k042DumpProg(cur)
				compiled++
			}
			if got != fl[3] {
				fails = append(fails, fmt.Sprintf("compile %q: want %.160s got %.160s", fl[1], fl[3], got))
			}
			gs := isSafeRegexSource(pat)
			if gs {
				safe++
			}
			if gs != wantSafe {
				fails = append(fails, fmt.Sprintf("isSafeRegexSource %q: want %v got %v", fl[1], wantSafe, gs))
			}
			if !have {
				if _, ok := safeRegexFullMatch(pat, u16s("a")); ok {
					fails = append(fails, fmt.Sprintf("fullMatch on refused %q ok", fl[1]))
				}
			}
			continue
		}
		matches++
		if !have {
			fails = append(fails, "subject for a refused pattern "+fl[1])
			continue
		}
		subj := k042Unhex(fl[1])
		m, ok := runSafeRegex(cur, subj)
		got := "N"
		if ok {
			got = "F"
			if m {
				got = "T"
			}
		}
		if got != fl[2] {
			fails = append(fails, fmt.Sprintf("run %q on %q: want %s got %s", k042Hex(pat), fl[1], fl[2], got))
		}
		m2, ok2 := safeRegexFullMatch(pat, subj)
		if ok2 != ok || (ok && m2 != m) {
			fails = append(fails, fmt.Sprintf("safeRegexFullMatch disagrees with runSafeRegex %q on %q", k042Hex(pat), fl[1]))
		}
		if len(fails) >= 3 {
			break
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(fails) > 0 {
		if len(fails) > 40 {
			fails = fails[:40]
		}
		t.Fatalf("%d differences, first:\n%s", len(fails), strings.Join(fails, "\n"))
	}
	if patterns != 8648 || compiled != 5267 || safe != 3206 || matches != 572525 {
		t.Fatalf("corpus counts: patterns %d compiled %d safe %d matches %d", patterns, compiled, safe, matches)
	}
}

func k042Hex(u []uint16) string {
	var sb strings.Builder
	for _, c := range u {
		fmt.Fprintf(&sb, "%04x", c)
	}
	return sb.String()
}
