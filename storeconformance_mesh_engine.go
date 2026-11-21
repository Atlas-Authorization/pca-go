package pca

import (
	"crypto/sha256"
	"errors"
)

// NewMeshWitnessEngine returns the MeshWitnessEngine over this package's MeshWitness and MeshDomain, so the mesh-witness profile
// can drive a real witness: RunMeshWitnessStoreConformance(adapter, NewMeshWitnessEngine()). Keys derive from the seed labels
// (test keys: SHA-256 of a public label).
func NewMeshWitnessEngine() MeshWitnessEngine { return meshEngine{} }

type meshEngine struct{}

func meshEngineKey(label string) *KeyPair {
	h := sha256.Sum256([]byte("atlas-pca-conformance/mesh-witness-profile/" + label))
	k, err := KeyPairFromSeed(h[:])
	if err != nil {
		panic(err) // a 32-byte seed is always accepted
	}
	return k
}

func (meshEngine) NewWitness(seedLabel string, store MeshWitnessStateStore) (MeshWitnessHandle, error) {
	opts := MeshWitnessOptions{}
	if store != nil {
		opts.Store = store
	}
	return NewMeshWitness(meshEngineKey(seedLabel), opts)
}

func (meshEngine) NewDomain(id, seedLabel string) MeshDomainHandle {
	return meshEngineDomain{NewMeshDomain(id, meshEngineKey(seedLabel))}
}

type meshEngineDomain struct{ d *MeshDomain }

func (h meshEngineDomain) ID() string { return h.d.ID }

func (h meshEngineDomain) Record(label string) {
	// a complete hop (issuer and holder named), so that it has a capability hash to log
	_, _ = h.d.Record(map[string]any{"id": label, "issuer": "iss-" + label, "holder": "h",
		"caveats": []any{map[string]any{"type": "scope", "actions": []any{label}}}})
}

func (h meshEngineDomain) PublishHead(witnesses []MeshWitnessHandle, now int64) (map[string]any, error) {
	ws := make([]*MeshWitness, 0, len(witnesses))
	for _, w := range witnesses {
		mw, ok := w.(*MeshWitness)
		if !ok {
			return nil, errors.New("this engine publishes to its own witnesses only")
		}
		ws = append(ws, mw)
	}
	return h.d.PublishHead(ws, float64(now), nil)
}
