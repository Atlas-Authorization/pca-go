package pca

// The mesh-witness state store profile: the durable memory of a mesh log witness. A witness cosigns a head only if it extends the last
// head THIS witness cosigned. A store that forgets across a restart, or that loses a save and still lets the cosignature out, lets a
// domain walk the witness back and show two verifiers different histories. The cases check the store by itself (round trip, replace,
// copy semantics, reopen, damage) and, given a MeshWitnessEngine, through a real witness (every cosignature is persisted first; a
// restarted witness refuses rollback and forks; a failed save refuses the cosignature and changes nothing; damaged storage is not read
// as empty).

import (
	"errors"
	"fmt"
)

// MeshWitnessStateStore is the witness's durable memory: Load returns nil when nothing was ever saved and an error when the storage is
// damaged (never an empty state); Save replaces the state. Both copy: neither shares memory with what the caller holds.
type MeshWitnessStateStore interface {
	Load() (map[string]any, error)
	Save(state map[string]any) error
}

// MeshWitnessStoreAdapter creates the stores the profile runs against.
type MeshWitnessStoreAdapter struct {
	Name string
	// Make returns a fresh, empty store.
	Make func() (MeshWitnessStateStore, error)
	// Reopen returns a new store object over the same backing storage as previous (a restart); nil for a store that cannot persist.
	Reopen func(previous MeshWitnessStateStore) (MeshWitnessStateStore, error)
	// Damage damages the backing storage of store so that Load must fail; nil for a store that cannot detect damage.
	Damage func(store MeshWitnessStateStore) error
}

// MeshWitnessHandle is a witness under test.
type MeshWitnessHandle interface {
	// ExportState is the state the witness holds (what it has cosigned).
	ExportState() map[string]any
	// LastSeen is the last head the witness cosigned for a domain, or nil.
	LastSeen(domainID string) map[string]any
}

// MeshDomainHandle is a domain log under test. Two domains built with the same id and seed label are two logs of one domain key.
type MeshDomainHandle interface {
	ID() string
	// Record appends a capability {id: label, caveats: [{type: scope, actions: [label]}]} to the log.
	Record(label string)
	// PublishHead publishes the head to the witnesses at now (epoch ms): {head, cosigs}. A witness that refuses (a fork, a rollback,
	// a failed save) makes it an error.
	PublishHead(witnesses []MeshWitnessHandle, now int64) (map[string]any, error)
}

// MeshWitnessEngine supplies the real witness and domain the driven cases run: adapt the mesh witness of this package to it.
type MeshWitnessEngine interface {
	// NewWitness builds a witness with the key of seedLabel over store (nil: no store). A store whose Load fails makes it an error.
	NewWitness(seedLabel string, store MeshWitnessStateStore) (MeshWitnessHandle, error)
	// NewDomain builds an empty log of the domain id signed with the key of seedLabel.
	NewDomain(id, seedLabel string) MeshDomainHandle
}

// MeshWitnessStoreCase is one case; Run panics-free: it returns the failure, or nil.
type MeshWitnessStoreCase struct {
	Name string
	// NeedsEngine marks a case that drives a real witness.
	NeedsEngine bool
	Run         func()
}

// MeshWitnessPersistFailure is the error a witness must report when it could not persist its state and so refused to cosign.
const MeshWitnessPersistFailure = "witness: could not persist state; refusing to cosign"

func meshState(n int) map[string]any {
	return map[string]any{"seen": []any{map[string]any{"head": map[string]any{"domain": fmt.Sprintf("d%d", n), "size": 0, "root": "", "rev_root": "r", "rev_size": 0, "timestamp": n}, "rev_ids": []any{}}}}
}

func meshTwoLogs(e MeshWitnessEngine) (honest, fork MeshDomainHandle) {
	// same domain key, different history: the second is a fork of the first from entry 0 on
	honest, fork = e.NewDomain("d", "domain"), e.NewDomain("d", "domain")
	honest.Record("a")
	fork.Record("x")
	return
}

func meshLoad(s MeshWitnessStateStore) map[string]any { return pMust(s.Load()) }

type meshFlaky struct {
	inner   MeshWitnessStateStore
	failing *bool
}

func (f meshFlaky) Load() (map[string]any, error) { return f.inner.Load() }
func (f meshFlaky) Save(st map[string]any) error {
	if *f.failing {
		return errors.New("disk full")
	}
	return f.inner.Save(st)
}

func meshCosigs(r map[string]any) int {
	switch c := r["cosigs"].(type) {
	case []any:
		return len(c)
	case []map[string]any:
		return len(c)
	}
	return 0
}

// MeshWitnessStoreCases is the mesh-witness profile: the store cases, the reopen and damage cases when the adapter has them, and the
// cases that drive a real witness (marked NeedsEngine; they run only when an engine is supplied). e may be nil.
func MeshWitnessStoreCases(a MeshWitnessStoreAdapter, e MeshWitnessEngine) []MeshWitnessStoreCase {
	make1 := func() MeshWitnessStateStore { return pMust(a.Make()) }
	cases := []MeshWitnessStoreCase{
		{"a fresh store loads nothing", false, func() { pEq(meshLoad(make1()), nil) }},
		{"save then load returns the same state", false, func() {
			s := make1()
			pNoErr(s.Save(meshState(1)))
			pEq(meshLoad(s), meshState(1))
		}},
		{"a later save replaces the earlier one", false, func() {
			s := make1()
			pNoErr(s.Save(meshState(1)))
			pNoErr(s.Save(meshState(2)))
			pEq(meshLoad(s), meshState(2))
		}},
		{"load returns a copy: changing it does not change the store", false, func() {
			s := make1()
			pNoErr(s.Save(meshState(1)))
			got := meshLoad(s)
			got["seen"] = []any{}
			pEq(meshLoad(s), meshState(1))
		}},
		{"save keeps its own copy: changing the argument afterwards does not change the store", false, func() {
			s := make1()
			st := meshState(1)
			pNoErr(s.Save(st))
			st["seen"] = []any{}
			pEq(meshLoad(s), meshState(1))
		}},
		{"a witness persists every cosignature before returning it", true, func() {
			st := make1()
			w := pMust(e.NewWitness("w", st))
			honest, _ := meshTwoLogs(e)
			ch := pMust(honest.PublishHead([]MeshWitnessHandle{w}, 1_000))
			pEq(meshLoad(st), w.ExportState())
			var heads []any
			for _, s := range profNorm(meshLoad(st)).(map[string]any)["seen"].([]any) {
				heads = append(heads, s.(map[string]any)["head"])
			}
			pEq(heads, []any{ch["head"]})
		}},
		{"a failed save refuses the cosignature and leaves the witness unchanged", true, func() {
			inner := make1()
			failing := false
			w := pMust(e.NewWitness("w", meshFlaky{inner, &failing}))
			honest, _ := meshTwoLogs(e)
			pMust(honest.PublishHead([]MeshWitnessHandle{w}, 1_000))
			before := profNorm(w.ExportState())
			honest.Record("b")
			failing = true
			_, err := honest.PublishHead([]MeshWitnessHandle{w}, 2_000)
			if err == nil {
				pFail("a failed save must refuse the cosignature")
			}
			pEq(err.Error(), MeshWitnessPersistFailure)
			pEq(w.ExportState(), before)
			pEq(meshLoad(inner), before)
			failing = false
			pEq(meshCosigs(pMust(honest.PublishHead([]MeshWitnessHandle{w}, 2_000))), 1, "the same head is cosigned once the disk recovers")
		}},
	}
	if a.Reopen != nil {
		cases = append(cases,
			MeshWitnessStoreCase{"state survives reopening the store", false, func() {
				s := make1()
				pNoErr(s.Save(meshState(3)))
				pEq(meshLoad(pMust(a.Reopen(s))), meshState(3))
			}},
			MeshWitnessStoreCase{"a restarted witness remembers what it cosigned: it refuses a fork and a rollback", true, func() {
				st := make1()
				w1 := pMust(e.NewWitness("w", st))
				honest, fork := meshTwoLogs(e)
				pMust(honest.PublishHead([]MeshWitnessHandle{w1}, 1_000))
				honest.Record("b")
				pMust(honest.PublishHead([]MeshWitnessHandle{w1}, 2_000))
				w2 := pMust(e.NewWitness("w", pMust(a.Reopen(st))))
				pEq(w2.LastSeen(honest.ID())["size"], 2)
				fork.Record("y")
				fork.Record("z")
				pRejects(fork.PublishHead([]MeshWitnessHandle{w2}, 3_000)) // a fork that grew past the remembered size
				rollback := e.NewDomain("d", "domain")
				rollback.Record("a")
				pRejects(rollback.PublishHead([]MeshWitnessHandle{w2}, 3_000)) // a rollback to the first head
				pEq(meshCosigs(pMust(honest.PublishHead([]MeshWitnessHandle{w2}, 3_000))), 1, "the honest log is still cosigned")
			}})
	}
	if a.Damage != nil {
		cases = append(cases, MeshWitnessStoreCase{"damaged storage makes load throw, so a witness never starts empty over it", false, func() {
			s := make1()
			if e != nil {
				// a state a witness accepts, so that only the damage can make construction fail
				w0 := pMust(e.NewWitness("w", nil))
				d0 := e.NewDomain("d", "domain")
				d0.Record("a")
				pMust(d0.PublishHead([]MeshWitnessHandle{w0}, 1_000))
				pNoErr(s.Save(w0.ExportState()))
			} else {
				pNoErr(s.Save(meshState(1)))
			}
			pNoErr(a.Damage(s))
			pRejects(s.Load()) // load must fail on damaged storage
			if e != nil {
				pRejects(e.NewWitness("w", s)) // a witness constructed over damaged storage must fail
			}
		}})
	}
	return cases
}

// RunMeshWitnessStoreConformance runs the mesh-witness profile. A nil engine skips the cases that drive a real witness.
func RunMeshWitnessStoreConformance(a MeshWitnessStoreAdapter, e MeshWitnessEngine) ConformanceReport {
	rep := ConformanceReport{Name: "mesh-witness store: " + a.Name}
	if a.Make == nil {
		rep.add("configuration", errors.New("Make is required"), "")
		return rep
	}
	for _, c := range MeshWitnessStoreCases(a, e) {
		if c.NeedsEngine && e == nil {
			rep.skip(c.Name, "no MeshWitnessEngine supplied")
			continue
		}
		rep.add(c.Name, runMeshCase(c), "")
	}
	return rep
}

func runMeshCase(c MeshWitnessStoreCase) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if f, ok := r.(profileFailure); ok {
				err = errors.New(f.msg)
				return
			}
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	c.Run()
	return nil
}
