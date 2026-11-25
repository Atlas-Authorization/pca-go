package pca

// Replays the reference corpora of the authoring surface: shorthands, entry expansion, the document loader over a parsed value,
// action(), the typed param constructors, and the text loader (YAML and JSON, with source positions).

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func authorStr(a []any, i int) string { s, _ := vecArg(a, i).(string); return s }

func authorInt(a []any, i int) *int {
	f, ok := jsNum(vecArg(a, i))
	if !ok {
		return nil
	}
	n := int(f)
	return &n
}

func authorStrs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, len(l))
	for i, x := range l {
		out[i], _ = x.(string)
	}
	return out
}

func authorBuilder(a []any) (any, error) {
	x := func(i int) map[string]any { return vecObj(vecArg(a, i)) }
	switch name := authorStr(a, 0); name {
	case "email":
		return ActionPEmail(x(1)), nil
	case "phone":
		return ActionPPhone(x(1)), nil
	case "url":
		return ActionPURL(x(1)), nil
	case "uuid":
		return ActionPUUID(x(1)), nil
	case "ccy":
		return ActionPCcy(x(1)), nil
	case "country":
		return ActionPCountry(x(1)), nil
	case "secret":
		return ActionPSecret(x(1)), nil
	case "bool":
		return ActionPBool(x(1)), nil
	case "date":
		return ActionPDate(x(1)), nil
	case "datetime":
		return ActionPDatetime(x(1)), nil
	case "duration":
		return ActionPDuration(authorInt(a, 1), x(2))
	case "message":
		return ActionPMessage(authorInt(a, 1), x(2))
	case "text":
		return ActionPText(authorInt(a, 1), x(2))
	case "int":
		return ActionPInt(authorInt(a, 1), authorInt(a, 2), x(3))
	case "count":
		return ActionPCount(authorInt(a, 1), x(2))
	case "money":
		return ActionPMoney(vecArg(a, 1), x(2), x(3))
	case "id":
		return ActionPID(authorStr(a, 1), x(2))
	case "enum":
		return ActionPEnum(authorStrs(vecArg(a, 1)), x(2))
	case "set":
		return ActionPSet(authorStrs(vecArg(a, 1)), x(2))
	case "array":
		return ActionPArray(authorStr(a, 1), authorInt(a, 2), x(3))
	case "optional":
		return ActionPOptional(x(1)), nil
	default:
		return nil, errors.New("no builder " + name)
	}
}

var authorFns = map[string]vecFn{
	"parseParamShorthand":    func(a []any) (any, error) { return ActionParseParamShorthand(authorStr(a, 0)) },
	"parseResourceShorthand": func(a []any) (any, error) { return ActionParseResourceShorthand(authorStr(a, 0)) },
	"defaultTitle":           func(a []any) (any, error) { return ActionDefaultTitle(authorStr(a, 0)), nil },
	"expandAction": func(a []any) (any, error) {
		ex, err := ActionExpand(vecArg(a, 0), vecArg(a, 1))
		if err != nil {
			return nil, err
		}
		return map[string]any{"def": ex.Def, "notes": ex.Notes}, nil
	},
	"loadActionsValue": func(a []any) (any, error) { return ActionLoadValue(vecArg(a, 0)), nil },
	"action":           func(a []any) (any, error) { return ActionAuthor(authorStr(a, 0), vecObj(vecArg(a, 1))) },
	"builder":          authorBuilder,
}

func TestActionAuthorVectors(t *testing.T) {
	replayOrdered(t, "ref-actions-author.json.gz", authorFns)
}

func TestActionAuthorPyVectors(t *testing.T) {
	replayOrdered(t, "ref-actions-author-py.json.gz", authorFns)
}

// authorLoadNorm keeps the members a load result is compared on.
func authorLoadNorm(v any) string {
	m := vecObj(v)
	out := map[string]any{}
	for _, k := range []string{"defs", "notes", "errors", "locs", "rules", "ns"} {
		if x, ok := m[k]; ok {
			out[k] = x
		}
	}
	return baseCanon(out)
}

var authorStricterBareCR = regexp.MustCompile(`\r([^\n]|$)`)

// A syntax error is compared by class (the parser's wording is its own); a result where the loader is deliberately STRICTER than
// the reference must be a single "not YAML" refusal on a text that uses one of the documented constructs, never a different
// successful value.
func TestActionLoadTextVectors(t *testing.T) {
	var bad []string
	n := 0
	orderedEach(t, "ref-actions-yaml-load-py.json.gz", func(c *baseCase) {
		n++
		text, format := authorStr(c.Args, 0), authorStr(c.Args, 1)
		got := ActionLoadText(text, format)
		gotJ := vecJSON(got)
		exp := vecObj(c.Out)
		e0 := ""
		if errs, _ := exp["errors"].([]any); len(errs) > 0 {
			e0, _ = vecObj(errs[0])["message"].(string)
		}
		gm := vecObj(gotJ)
		gerrs, _ := gm["errors"].([]any)
		gdefs, _ := gm["defs"].([]any)
		gmsg := ""
		if len(gerrs) > 0 {
			gmsg, _ = vecObj(gerrs[0])["message"].(string)
		}
		var ok bool
		switch {
		case strings.HasPrefix(e0, "not YAML") || strings.HasPrefix(e0, "YAML warning") || strings.HasPrefix(e0, "not JSON"):
			want := "not JSON"
			if format != "json" {
				want = "not YAML"
			}
			ok = len(gerrs) == 1 && len(gdefs) == 0 && strings.HasPrefix(gmsg, want)
		case authorLoadNorm(gotJ) == authorLoadNorm(exp):
			ok = true
		default:
			stricter := strings.Contains(text, "!custom") || strings.Contains(text, "!!binary") || strings.Contains(text, "? [") || authorStricterBareCR.MatchString(text)
			ok = stricter && len(gerrs) == 1 && strings.HasPrefix(gmsg, "not YAML") && len(gdefs) == 0
		}
		if !ok {
			clip := func(s string) string {
				if len(s) > 300 {
					return s[:300]
				}
				return s
			}
			bad = append(bad, c.Name+" "+strconv.Quote(clip(text))+"\n  got  "+clip(authorLoadNorm(gotJ))+"\n  want "+clip(authorLoadNorm(exp)))
		}
	})
	if nbad := len(bad); nbad > 0 {
		if nbad > 8 {
			bad = bad[:8]
		}
		t.Fatalf("%d of %d differ:\n%s", nbad, n, strings.Join(bad, "\n"))
	}
}
