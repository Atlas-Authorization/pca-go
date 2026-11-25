package blstkit

import pca "github.com/Atlas-Authorization/pca-go"

// The canonical attribute names of a capability's ABE attribute set (the reference's Attr builders).

// AbeAttrHolder is the holder attribute of a public key.
func AbeAttrHolder(key string) string { return "holder:" + key }

// AbeAttrVerb is the attribute of a verb.
func AbeAttrVerb(v string) string { return "verb:" + v }

// AbeAttrResource is the attribute of a resource.
func AbeAttrResource(r string) string { return "resource:" + r }

// AbeAttrScope is the attribute of a scope.
func AbeAttrScope(s string) string { return "scope:" + s }

// AbeAttrAct is the attribute of a bound (verb, resource) pair: only a predicate that grants exactly this verb on exactly this
// resource yields it.
func AbeAttrAct(verb, resource string) (string, error) {
	pair, err := pca.Canonicalize([]any{verb, resource})
	if err != nil {
		return "", err
	}
	return "act:" + pair, nil
}
