package pca

import (
	"errors"
	"strings"
)

// Duplicate-member check for JSON received from outside (signed or digested). JSON.parse keeps the LAST duplicate member, so the
// signer and a verifier could read different claims from the same bytes. This checks ONLY duplicates (at any depth, keys compared
// after unescaping, so "a" and "a" collide); numbers and everything else stay as the sender wrote them. Use StrictParse for
// formats this library defines.

// DuplicateKeyJSON returns the first repeated object member of text, spelled as JSON.stringify spells the key (`"kind"`), in the
// order a left-to-right scan meets the repeat. text must already be valid JSON (a text that is not has no meaningful answer).
func DuplicateKeyJSON(text string) (string, bool) {
	type frame struct {
		keys  map[string]bool
		isObj bool
	}
	var stack []frame
	expectKey := false
	for i := 0; i < len(text); i++ {
		switch c := text[i]; c {
		case '"':
			j := i + 1
			for j < len(text) && text[j] != '"' {
				if text[j] == '\\' {
					j += 2
				} else {
					j++
				}
			}
			if expectKey && len(stack) > 0 && stack[len(stack)-1].isObj {
				end := min(j+1, len(text))
				v, err := ParseJSONLastWins([]byte(text[i:end]))
				key, ok := v.(string)
				if err != nil || !ok {
					return "", false
				}
				top := stack[len(stack)-1]
				if top.keys[key] {
					var sb strings.Builder
					lenientString(&sb, key)
					return sb.String(), true
				}
				top.keys[key] = true
				expectKey = false
			}
			i = j
		case '{':
			stack = append(stack, frame{keys: map[string]bool{}, isObj: true})
			expectKey = true
		case '[':
			stack = append(stack, frame{})
			expectKey = false
		case '}', ']':
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			expectKey = false
		case ',':
			expectKey = len(stack) > 0 && stack[len(stack)-1].isObj
		}
	}
	return "", false
}

// ParseNoDuplicates is JSON.parse that refuses a repeated member (the message names the key as JSON.stringify spells it:
// `duplicate key "kind"`); a syntax error is reported first, as the reference's JSON.parse does. Numbers are read as written.
func ParseNoDuplicates(text string) (any, error) {
	v, err := ParseJSONLastWins([]byte(text))
	if err != nil {
		return nil, err
	}
	if k, dup := DuplicateKeyJSON(text); dup {
		return nil, errors.New("duplicate key " + k)
	}
	return v, nil
}
