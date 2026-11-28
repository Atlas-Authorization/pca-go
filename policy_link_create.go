package pca

import "fmt"

// SlotsDigest is the digest a bind_params_digest reference cites: the canonical hash of the slot object.
func SlotsDigest(slots any) (string, error) { return HashCanonical(slots) }

// CreateLink builds the template reference of def filled with slots: the slots travel in the reference or, with bindParams, only
// their digest does. It fails when the slots do not instantiate the template.
func CreateLink(def, slots any, bindParams bool) (map[string]any, error) {
	if _, why := InstantiateTemplate(def, slots); why != "" {
		return nil, fmt.Errorf("createLink: %s", why)
	}
	digest, err := TemplateDigest(def)
	if err != nil {
		return nil, err
	}
	d, _ := def.(map[string]any)
	ref := map[string]any{"template_id": d["id"], "version_digest": digest}
	if bindParams {
		sd, err := SlotsDigest(slots)
		if err != nil {
			return nil, err
		}
		ref["bind_params_digest"] = sd
	} else {
		ref["slots"] = normalizeJSON(slots)
	}
	return ref, nil
}
