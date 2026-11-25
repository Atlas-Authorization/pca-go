package pca

// Building, sharding and upgrading signed action packs, and the transparency payload of a pack. Verification of one pack lives in
// actions_registry.go; this adds the producing side and the chain check between two packs.

import (
	"errors"
	"fmt"
	"math"
	"sort"
)

const defaultShardDefs = 512

func packErr(code, msg string) error { return &CodedError{Code: code, Msg: msg} }

// ActionShardDefs splits defs into shards by resource family (the first segment of the resource type), at most max defs each
// (nil = the default 512). A family over max is split into `<family>-<n>`.
func ActionShardDefs(defs []any, maxDefs *float64) ([]map[string]any, error) {
	max := float64(defaultShardDefs)
	if maxDefs != nil {
		max = *maxDefs
	}
	if max != math.Trunc(max) || max < 1 || max > 9007199254740991 {
		return nil, packErr("bad_shard_size", "the shard size must be a positive integer")
	}
	n := int(math.Min(max, 1<<30))
	fam := map[string][]any{}
	var names []string
	for _, x := range defs {
		d, _ := x.(map[string]any)
		res, _ := d["resource"].(map[string]any)
		rt := jsAnyString(res["type"])
		f := rt
		for i := 0; i < len(rt); i++ {
			if rt[i] == '.' {
				f = rt[:i]
				break
			}
		}
		if _, seen := fam[f]; !seen {
			names = append(names, f)
		}
		fam[f] = append(fam[f], x)
	}
	adSortU16(names)
	out := []map[string]any{}
	for _, f := range names {
		l := fam[f]
		for i, k := 0, 1; i < len(l); i, k = i+n, k+1 {
			end := i + n
			if end > len(l) {
				end = len(l)
			}
			name := f
			if len(l) > n {
				name = fmt.Sprintf("%s-%d", f, k)
			}
			out = append(out, map[string]any{"name": name, "defs": append([]any{}, l[i:end]...)})
		}
	}
	return out, nil
}

// ActionPackBuild is the build input: ns, version, stability, defs, source, kid; shard (true or {max}) forces sharding; prev is
// {pack, shards?} of the previous pack. confirmed is the attestation check used for the evolution records (nil = never).
type ActionPackBuild struct {
	Args      map[string]any
	Seed      []byte
	Confirmed ActionDiffConfirmed
}

// ActionBuildPack builds the signed pack (and its shard documents). Defs are sorted by verb; the evolution against the previous
// pack is derived and signed; a large pack (or shard: true) is split into shards. The result is shape-checked before signing.
func ActionBuildPack(b ActionPackBuild) (pack map[string]any, shards map[string]any, err error) {
	a := b.Args
	ns, _ := a["ns"].(string)
	version, _ := a["version"].(string)
	kid, _ := a["kid"].(string)
	in, _ := a["defs"].([]any)
	defs := append([]any{}, in...)
	verbOf := func(x any) string { m, _ := x.(map[string]any); s, _ := m["verb"].(string); return s }
	sort.SliceStable(defs, func(i, j int) bool { return u16Less(verbOf(defs[i]), verbOf(defs[j])) })
	if de := sortedUniqueDefsError(defs); de != "" {
		return nil, nil, packErr("bad_pack", de)
	}
	if len(defs) == 0 {
		return nil, nil, packErr("empty_pack", "a pack has at least one def")
	}
	var prevDefs []any
	var prevPack map[string]any
	if pv, has := a["prev"]; has && pv != nil {
		pm, _ := pv.(map[string]any)
		prevPack, _ = pm["pack"].(map[string]any)
		ps, _ := pm["shards"].(map[string]any)
		if prevDefs, err = packDefs(prevPack, ps); err != nil {
			return nil, nil, err
		}
		if prevPack["ns"] != ns {
			return nil, nil, packErr("bad_chain", "the previous pack is of another namespace")
		}
		pvs, _ := prevPack["version"].(string)
		c, cerr := compareVersions(version, pvs)
		if cerr != nil {
			return nil, nil, cerr
		}
		if c <= 0 {
			return nil, nil, packErr("bad_chain", "the version must increase")
		}
	}
	records, err := ActionEvolutionRecords(ns, prevDefs, defs, coreRegistry, b.Confirmed)
	if err != nil {
		return nil, nil, err
	}
	evolution, err := ActionSignEvolution(records, kid, b.Seed)
	if err != nil {
		return nil, nil, err
	}
	digests := make([]string, len(defs))
	for i, d := range defs {
		if digests[i], err = packDefDigest(d.(map[string]any)); err != nil {
			return nil, nil, err
		}
	}
	root, err := packRoot(digests)
	if err != nil {
		return nil, nil, err
	}
	shardOpt, hasShard := a["shard"]
	wantShards := hasShard && shardOpt != false // null counts as present, as in the reference
	if !wantShards {
		wantShards = len(defs) > 4096 // MAX_PACK_DEFS: larger packs are sharded
	}
	shards = map[string]any{}
	var body any = defs
	if wantShards {
		so, _ := shardOpt.(map[string]any)
		var max *float64
		if m, ok := so["max"]; ok && m != nil {
			f := jsF(m)
			max = &f
		}
		refs := []any{}
		parts, err := ActionShardDefs(defs, max)
		if err != nil {
			return nil, nil, err
		}
		for _, s := range parts {
			name := s["name"].(string)
			doc := map[string]any{"v": jsNumber(1), "kind": packShardKind, "ns": ns, "version": version, "name": name, "defs": s["defs"]}
			shards[name] = doc
			dg, err := shardDigest(doc)
			if err != nil {
				return nil, nil, err
			}
			refs = append(refs, map[string]any{"name": name, "digest": dg, "uri": "shards/" + name + ".json"})
		}
		body = map[string]any{"shards": refs}
	}
	td, err := traitsDigest(coreRegistry)
	if err != nil {
		return nil, nil, err
	}
	rd, err := tablesDigest()
	if err != nil {
		return nil, nil, err
	}
	ru, err := rulesDigest()
	if err != nil {
		return nil, nil, err
	}
	var prevRef any
	if prevPack != nil {
		if prevRef, err = packDigest(prevPack); err != nil {
			return nil, nil, err
		}
	}
	unsigned := map[string]any{"v": jsNumber(1), "kind": actionPackKind, "ns": ns, "version": version, "stability": a["stability"],
		"traits_digest": td, "roles_digest": rd, "rules_digest": ru, "root": root, "defs": body, "source": a["source"], "prev": prevRef,
		"evolution": evolution}
	if pe := packShapeError(unsigned, false); pe != "" {
		return nil, nil, packErr("bad_pack", pe)
	}
	kp, err := KeyPairFromSeed(b.Seed)
	if err != nil {
		return nil, nil, err
	}
	sig, err := signBody(kp, packSigDomain, unsigned)
	if err != nil {
		return nil, nil, err
	}
	pack = map[string]any{}
	for k, v := range unsigned {
		pack[k] = v
	}
	pack["sig"] = map[string]any{"alg": "ed25519", "kid": kid, "value": sig}
	return pack, shards, nil
}

// ActionVerifyUpgrade verifies next as the successor of prev: both verify, same namespace, next.prev is prev's digest, the version
// increases, and the signed evolution is EXACTLY the computed change (a registry cannot sign `narrow` for a widening def).
// "" = ok, else the reason.
func ActionVerifyUpgrade(prev, next map[string]any, keys any, prevShards, shards map[string]any, confirmed ActionDiffConfirmed) string {
	ad, _, ar := verifyPack(prev, keys, prevShards)
	if ar != "" {
		return "previous pack: " + ar
	}
	bd, _, br := verifyPack(next, keys, shards)
	_ = bd
	if br != "" {
		return "pack: " + br
	}
	if next["ns"] != prev["ns"] {
		return "the packs are of different namespaces"
	}
	if next["prev"] != ad {
		return "chain gap: prev does not name the previous pack"
	}
	nv, _ := next["version"].(string)
	pv, _ := prev["version"].(string)
	if c, err := compareVersions(nv, pv); err != nil || c <= 0 {
		return "the version does not increase"
	}
	adefs, _ := packDefs(prev, prevShards)
	bdefs, _ := packDefs(next, shards)
	ns, _ := next["ns"].(string)
	ev, _ := next["evolution"].([]any)
	return ActionEvolutionError(ns, adefs, bdefs, ev, keys, coreRegistry, confirmed)
}

// ActionPackStatementPayload is the payload of the transparency statement for a pack.
func ActionPackStatementPayload(p map[string]any) (map[string]any, error) {
	for _, k := range []string{"ns", "version", "root", "prev"} { // an absent member is undefined: it has no canonical form
		if _, has := p[k]; !has {
			return nil, errors.New("canonicalize: unsupported type undefined")
		}
	}
	dg, err := packDigest(p)
	if err != nil {
		return nil, err
	}
	return map[string]any{"v": jsNumber(1), "kind": "pca-action-pack-statement", "ns": p["ns"], "version": p["version"], "digest": dg,
		"root": p["root"], "prev": p["prev"]}, nil
}
