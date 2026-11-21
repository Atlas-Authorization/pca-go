package pca

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// schemaTypeOf is the JSON type name of a decoded value; a number with no fraction is an "integer".
func schemaTypeOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case []any:
		return "array"
	case bool:
		return "boolean"
	case string:
		return "string"
	case map[string]any:
		return "object"
	}
	if f, ok := jsNum(v); ok {
		if schemaIsInteger(f) {
			return "integer"
		}
		return "number"
	}
	return "object"
}

func schemaIsInteger(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f == math.Trunc(f)
}

func schemaMatchesType(expected any, v any) bool {
	e, _ := expected.(string)
	f, isNum := jsNum(v)
	_, isBool := v.(bool)
	isNum = isNum && !isBool
	switch e {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		return isNum && !math.IsNaN(f) && !math.IsInf(f, 0)
	case "integer":
		return isNum && schemaIsInteger(f) && !(f == 0 && math.Signbit(f))
	case "boolean":
		return isBool
	case "null":
		return v == nil
	}
	return false
}

// schemaResolveRef walks a local '#/...' pointer over own keys of objects only; nil when it does not name an object.
func schemaResolveRef(root any, ref string) map[string]any {
	if !strings.HasPrefix(ref, "#/") {
		return nil
	}
	cur := root
	for _, token := range strings.Split(ref[2:], "/") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[token]; !ok {
			return nil
		}
	}
	m, _ := cur.(map[string]any)
	return m
}

func schemaLabel(path string) string {
	if path == "" {
		return "(root)"
	}
	return path
}

// schemaStrictEqual is JS === over decoded JSON: objects and arrays never match (identity).
func schemaStrictEqual(a, b any) bool {
	switch x := a.(type) {
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case map[string]any, []any:
		return false
	}
	if _, isBool := b.(bool); isBool {
		return false
	}
	fa, oka := jsNum(a)
	fb, okb := jsNum(b)
	return oka && okb && fa == fb
}

// schemaStringify is JSON.stringify of a decoded JSON value (member order from jsKeys).
func schemaStringify(v any) string {
	var sb strings.Builder
	var w func(x any)
	w = func(x any) {
		switch t := x.(type) {
		case nil:
			sb.WriteString("null")
		case bool:
			if t {
				sb.WriteString("true")
			} else {
				sb.WriteString("false")
			}
		case string:
			_ = jsString(&sb, t)
		case []any:
			sb.WriteByte('[')
			for i, e := range t {
				if i > 0 {
					sb.WriteByte(',')
				}
				w(e)
			}
			sb.WriteByte(']')
		case map[string]any:
			sb.WriteByte('{')
			for i, k := range jsKeys(t) {
				if i > 0 {
					sb.WriteByte(',')
				}
				_ = jsString(&sb, k)
				sb.WriteByte(':')
				w(t[k])
			}
			sb.WriteByte('}')
		default:
			if f, ok := jsNum(x); ok && !math.IsNaN(f) && !math.IsInf(f, 0) {
				sb.WriteString(jsNumberString(f))
			} else {
				sb.WriteString("null")
			}
		}
	}
	w(v)
	return sb.String()
}

func schemaTruthy(v any) bool {
	if v == nil || v == false || v == "" {
		return false
	}
	if f, ok := jsNum(v); ok && f == 0 {
		return false
	}
	return true
}

func schemaJoin(path string, key any) (string, error) {
	k, ok := key.(string)
	if !ok {
		return "", errors.New("required entry is not a string")
	}
	if path == "" {
		return k, nil
	}
	return path + "." + k, nil
}

func schemaCheckNode(schema any, value any, path string, root any, errs *[]string) error {
	if schema == nil {
		return errors.New("schema node is null")
	}
	s, ok := schema.(map[string]any)
	if !ok {
		return nil // a boolean/number schema constrains nothing in this subset
	}
	if ref, isStr := s["$ref"].(string); isStr {
		resolved := schemaResolveRef(root, ref)
		if resolved == nil {
			*errs = append(*errs, fmt.Sprintf("%s: unresolved $ref '%s'", schemaLabel(path), ref))
			return nil
		}
		return schemaCheckNode(resolved, value, path, root, errs)
	}
	if t, has := s["type"]; has {
		types, isList := t.([]any)
		if !isList {
			types = []any{t}
		}
		matched := false
		for _, x := range types {
			matched = matched || schemaMatchesType(x, value)
		}
		if !matched {
			names := make([]string, len(types))
			for i, x := range types {
				names[i] = jsValueString(x)
			}
			*errs = append(*errs, fmt.Sprintf("%s: expected type %s, got %s", schemaLabel(path), strings.Join(names, "|"), schemaTypeOf(value)))
			return nil // a wrong base type makes any deeper check meaningless
		}
	}
	if enum, isList := s["enum"].([]any); isList {
		found := false
		for _, e := range enum {
			found = found || schemaStrictEqual(e, value)
		}
		if !found {
			names := make([]string, len(enum))
			for i, e := range enum {
				names[i] = schemaStringify(e)
			}
			*errs = append(*errs, fmt.Sprintf("%s: value is not one of [%s]", schemaLabel(path), strings.Join(names, ", ")))
		}
	}
	if obj, isObj := value.(map[string]any); isObj {
		if required, isList := s["required"].([]any); isList {
			for _, key := range required {
				k, isStr := key.(string)
				if _, present := obj[k]; !isStr || !present {
					p, err := schemaJoin(path, key)
					if err != nil {
						return err
					}
					*errs = append(*errs, fmt.Sprintf("%s: missing required property '%s'", p, k))
				}
			}
		}
		props, propsOK := s["properties"].(map[string]any)
		if propsOK && schemaTruthy(props) {
			for _, key := range jsKeys(props) {
				if sub, present := obj[key]; present {
					p, _ := schemaJoin(path, key)
					if err := schemaCheckNode(props[key], sub, p, root, errs); err != nil {
						return err
					}
				}
			}
		}
		if s["additionalProperties"] == false && propsOK {
			for _, key := range jsKeys(obj) {
				if _, known := props[key]; !known {
					p, _ := schemaJoin(path, key)
					*errs = append(*errs, fmt.Sprintf("%s: additional property not allowed", p))
				}
			}
		}
	}
	if items, has := s["items"]; has {
		if list, isList := value.([]any); isList && schemaTruthy(items) {
			for i, el := range list {
				if err := schemaCheckNode(items, el, fmt.Sprintf("%s[%d]", path, i), root, errs); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// SchemaValidate is structural validation: {"valid": bool, "errors": [string]} (errors empty when valid). It never fails on a bad
// value; a null schema node is an error (the reference throws).
func SchemaValidate(schema, value any) (map[string]any, error) {
	errs := []string{}
	if err := schemaCheckNode(schema, value, "", schema, &errs); err != nil {
		return nil, err
	}
	return map[string]any{"valid": len(errs) == 0, "errors": connAnyList(errs)}, nil
}
