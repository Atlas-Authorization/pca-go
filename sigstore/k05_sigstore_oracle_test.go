package pcasigstore

// k05 differential oracle: offline Sigstore bundle verification against the TypeScript reference sigstore.ts
// (testdata/k05-sigstore.json.gz, ~46 MB inflated, streamed one case at a time; tools/pca-audit/k05-oracles/sigstore-oracle.mts;
// every native replays the same file). parseTrustedRoot: the summary (log key ids, validity, v2 names, chain lengths) or a
// refusal; later cases name a root as {"$root": id} and get the Go parse of that root. verifySigstoreBundleCore /
// verifySigstoreBundle: ok and the exact core / facts, or the exact refusal code (the detail embeds JavaScript runtime
// messages, so it is never compared). verifyRfc3161: the exact genTime (ms) or a refusal; dssePae: the exact bytes.
// `<fn>@suspect` cases run and are reported, never failed.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type k05SigCase struct {
	Fn   string            `json:"fn"`
	Name string            `json:"name"`
	Args []json.RawMessage `json:"args"`
	Out  json.RawMessage   `json:"out"`
}

func k05SigDecode(raw []byte) any {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		panic(err)
	}
	return v
}

// k05SigJSON round-trips a Go value through encoding/json so it compares with a decoded reference value.
func k05SigJSON(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<unmarshalable %v>", err)
	}
	return k05SigDecode(b)
}

func k05RootSummary(r *PinnedRoots) any {
	end := func(e int64) any {
		if e == forever {
			return nil
		}
		return e
	}
	logs := func(ls []PinnedLog) []any {
		out := []any{}
		for _, l := range ls {
			var v2 any
			if l.v2Name != "" {
				v2 = l.v2Name
			}
			out = append(out, map[string]any{"keyId": base64.StdEncoding.EncodeToString(l.keyID), "start": l.valid.start, "end": end(l.valid.end), "v2": v2})
		}
		return out
	}
	cas := func(cs []PinnedCA) []any {
		out := []any{}
		for _, c := range cs {
			out = append(out, map[string]any{"chain": len(c.chain), "start": c.valid.start, "end": end(c.valid.end)})
		}
		return out
	}
	return k05SigJSON(map[string]any{"tlogs": logs(r.tlogs), "ctlogs": logs(r.ctlogs), "cas": cas(r.cas), "tsas": cas(r.tsas)})
}

// k05SameMsg: a refusal detail or thrown message must equal the reference's exactly (the code alone let mutants that swap
// one refusal reason for another survive), except where the reference's text is its host runtime's own wording (V8
// TypeError/SyntaxError, WHATWG URL, OpenSSL error strings), which a native port cannot reproduce: there the code decides.
func k05SameMsg(want any, got string) bool {
	w, _ := want.(string)
	for _, host := range []string{"Cannot read properties of ", "Unexpected token", "Unexpected end of JSON input", "is not valid JSON", "Invalid URL", "error:0"} {
		if strings.Contains(w, host) {
			return true
		}
	}
	return w == got
}

func TestK05Sigstore(t *testing.T) {
	fh, err := os.Open("testdata/k05-sigstore.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(zr)
	tok := func() json.Token {
		x, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		return x
	}
	roots := map[string]*PinnedRoots{}
	ran, suspect := map[string]int{}, 0
	byGroup := map[string]int{}
	var bad []string
	nbad := 0
	fail := func(c *k05SigCase, format string, a ...any) {
		if strings.HasSuffix(c.Fn, "@suspect") {
			suspect++
			return
		}
		nbad++
		p := strings.SplitN(c.Name, "/", 4)
		byGroup[strings.Join(p[:min(len(p), 3)], "/")]++
		if len(bad) < 120 {
			msg := c.Name + ": " + fmt.Sprintf(format, a...)
			if len(msg) > 400 {
				msg = msg[:400] + "..."
			}
			bad = append(bad, msg)
		}
	}
	rootOf := func(raw json.RawMessage) *PinnedRoots {
		var ref struct {
			Root string `json:"$root"`
		}
		if json.Unmarshal(raw, &ref) != nil {
			return nil
		}
		return roots[ref.Root]
	}
	std := func(raw json.RawMessage) ([]byte, bool) {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, false
		}
		b, err := base64.StdEncoding.DecodeString(s)
		return b, err == nil
	}
	tok() // {
	n := 0
	for dec.More() {
		key, _ := tok().(string)
		if key != "cases" {
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatal(err)
			}
			continue
		}
		tok() // [
		for dec.More() {
			var c k05SigCase
			if err := dec.Decode(&c); err != nil {
				t.Fatal(err)
			}
			n++
			fn := strings.TrimSuffix(c.Fn, "@suspect")
			out := k05SigDecode(c.Out)
			om, _ := out.(map[string]any)
			_, threw := om["$throws"]
			ran[fn]++
			switch fn {
			case "parseTrustedRoot":
				tr, err := ParseTrustedRoot(c.Args[0])
				if err == nil {
					roots[strings.TrimPrefix(c.Name, "parseTrustedRoot/")] = tr
				}
				switch {
				case (err != nil) != threw:
					fail(&c, "want %s, got err=%v", string(c.Out), err)
				case threw && !k05SameMsg(om["$throws"], err.Error()):
					fail(&c, "want throw %q, got %q", om["$throws"], err.Error())
				case err == nil && !reflect.DeepEqual(k05RootSummary(tr), out):
					fail(&c, "summary: want %s, got %v", string(c.Out), k05RootSummary(tr))
				}
			case "verifySigstoreBundleCore", "verifySigstoreBundle":
				tr := rootOf(c.Args[1])
				if tr == nil {
					fail(&c, "names a root Go refused (or no root)")
					continue
				}
				var ok bool
				var code, detail string
				var got any
				if fn == "verifySigstoreBundleCore" {
					r := VerifySigstoreBundleCore(c.Args[0], tr)
					ok, code, detail, got = r.OK, r.Code, r.Detail, k05SigJSON(r.Core)
				} else {
					r := VerifySigstoreBundle(c.Args[0], tr)
					ok, code, detail, got = r.OK, r.Code, r.Detail, k05SigJSON(r.Facts)
				}
				switch {
				case threw:
					if ok {
						fail(&c, "want a throw, got ok")
					}
				case ok != (om["ok"] == true):
					fail(&c, "want %s, got ok=%v %s: %s", string(c.Out), ok, code, detail)
				case ok:
					member := "core"
					if fn == "verifySigstoreBundle" {
						member = "facts"
					}
					if !reflect.DeepEqual(got, om[member]) {
						fail(&c, "want %v, got %v", om[member], got)
					}
				case code != om["code"] || !k05SameMsg(om["detail"], detail):
					fail(&c, "want %v: %q, got %s: %q", om["code"], om["detail"], code, detail)
				}
			case "verifyRfc3161":
				token, ok1 := std(c.Args[0])
				data, ok2 := std(c.Args[1])
				tr := rootOf(c.Args[2])
				if !ok1 || !ok2 || tr == nil {
					fail(&c, "unreadable arguments")
					continue
				}
				ms, err := tr.VerifyRFC3161(token, data)
				switch {
				case (err != nil) != threw:
					fail(&c, "want %s, got %d err=%v", string(c.Out), ms, err)
				case threw && !k05SameMsg(om["$throws"], err.Error()):
					fail(&c, "want throw %q, got %q", om["$throws"], err.Error())
				case err == nil && fmt.Sprint(ms) != fmt.Sprint(out):
					fail(&c, "want %v, got %d", out, ms)
				}
			case "dssePae":
				var pt string
				payload, ok := std(c.Args[1])
				if json.Unmarshal(c.Args[0], &pt) != nil || !ok {
					fail(&c, "unreadable arguments")
					continue
				}
				if got := base64.RawURLEncoding.EncodeToString(DSSEPAE(pt, payload)); got != om["$bytes"] {
					fail(&c, "want %v, got %s", om["$bytes"], got)
				}
			default:
				fail(&c, "unknown fn %s", c.Fn)
			}
		}
		tok() // ]
	}
	if n == 0 {
		t.Fatal("no cases")
	}
	keys := func(m map[string]int) []string {
		out := []string{}
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	for _, k := range keys(ran) {
		t.Logf("%s: %d compared", k, ran[k])
	}
	if suspect > 0 {
		t.Logf("%d @suspect cases differ (reported, not failed)", suspect)
	}
	if nbad > 0 {
		groups := []string{}
		for _, k := range keys(byGroup) {
			groups = append(groups, fmt.Sprintf("%s=%d", k, byGroup[k]))
		}
		t.Fatalf("%d cases diverge from the reference (by group: %s):\n  %s", nbad, strings.Join(groups, " "), strings.Join(bad, "\n  "))
	}
}
