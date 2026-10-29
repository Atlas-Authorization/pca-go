package pca

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Replays packages/pca/conformance/attestation-evidence-vectors.json: every vendor verifier answers exactly what the
// reference verifiers answered when the file was generated (reason text included; an OpenSSL / node:crypto message is
// compared by its stable prefix), and the strict X.509 readers answer every unit row. The file is produced by the
// TypeScript generator; a missing file FAILS the test (it is never skipped).

const attestVectorFile = "attestation-evidence-vectors.json"

// hydrateBlobs replaces every {"$blob": id} with the string stored under blobs[id].
func hydrateBlobs(x any, blobs map[string]any) (any, error) {
	switch t := x.(type) {
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			h, err := hydrateBlobs(e, blobs)
			if err != nil {
				return nil, err
			}
			out[i] = h
		}
		return out, nil
	case map[string]any:
		if len(t) == 1 {
			if id, ok := t["$blob"].(string); ok {
				v, ok := blobs[id]
				if !ok {
					return nil, fmt.Errorf("unknown blob %s", id)
				}
				return v, nil
			}
		}
		out := make(map[string]any, len(t))
		for k, e := range t {
			h, err := hydrateBlobs(e, blobs)
			if err != nil {
				return nil, err
			}
			out[k] = h
		}
		return out, nil
	}
	return x, nil
}

// normJSON round-trips a value through JSON so that numbers, maps and slices compare structurally.
func normJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func loadAttestVectors(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(dir + attestVectorFile)
	if err != nil {
		t.Fatalf("conformance/%s is missing (%v): generate it with the TypeScript reference (tsx scripts/gen-conformance-attestation.ts in packages/pca)", attestVectorFile, err)
	}
	v, err := ParseJSONLenient(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func asInt64(t *testing.T, v any) int64 {
	t.Helper()
	f, ok := asFinite(v)
	if !ok {
		t.Fatalf("not a number: %v", v)
	}
	return int64(f)
}

func bindingOf(v any) *AttestationBinding {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	f, _ := asFinite(m["epoch"])
	b := &AttestationBinding{Epoch: f}
	b.HolderPub, _ = m["holderPub"].(string)
	b.GrantRef, _ = m["grantRef"].(string)
	b.Nonce, _ = m["nonce"].(string)
	return b
}

// runAttestationRow is verifier_from_config + verify for one row: the wire result, or {"construct_error": text}.
func runAttestationRow(t *testing.T, row map[string]any) map[string]any {
	t.Helper()
	vendor, _ := row["vendor"].(string)
	cfg, _ := row["config"].(map[string]any)
	ver, err := VerifierFromConfig(vendor, cfg)
	if err != nil {
		return map[string]any{"construct_error": err.Error()}
	}
	ev, _ := row["evidence"].(map[string]any)
	res := ver.Verify(ev, bindingOf(row["expected_binding"]), asInt64(t, row["now"]))
	return res.Wire()
}

func TestAttestationEvidenceVectors(t *testing.T) {
	doc := loadAttestVectors(t)
	blobs, _ := doc["blobs"].(map[string]any)
	rows, _ := doc["attestation_vectors"].([]any)

	schema, _ := doc["verifier_config_schema"].(map[string]any)
	var schemaVendors []string
	for k := range schema {
		schemaVendors = append(schemaVendors, k)
	}
	sort.Strings(schemaVendors)
	want := append([]string{}, AttestationVendors...)
	sort.Strings(want)
	if !reflect.DeepEqual(schemaVendors, want) {
		t.Fatalf("verifier_config_schema vendors %v, this package builds %v", schemaVendors, want)
	}

	seen := map[string]bool{}
	perVendor := map[string]int{}
	for _, r := range rows {
		row := r.(map[string]any)
		id, _ := row["id"].(string)
		if seen[id] {
			t.Fatalf("duplicate vector id %s", id)
		}
		seen[id] = true
		perVendor[row["vendor"].(string)]++
	}
	for _, v := range AttestationVendors {
		if perVendor[v] == 0 {
			t.Fatalf("no vectors for %s", v)
		}
	}
	if len(rows) < 750 {
		t.Fatalf("only %d attestation vectors", len(rows))
	}

	for _, r := range rows {
		hr, err := hydrateBlobs(r, blobs)
		if err != nil {
			t.Fatal(err)
		}
		row := hr.(map[string]any)
		id, _ := row["id"].(string)
		t.Run(id, func(t *testing.T) {
			got := runAttestationRow(t, row)
			exp := map[string]any{}
			for k, v := range row["expect"].(map[string]any) {
				exp[k] = v
			}
			gotN := normJSON(t, got).(map[string]any)
			expN := normJSON(t, exp).(map[string]any)
			if exp["reason_match"] == "prefix" {
				prefix, _ := exp["reason_prefix"].(string)
				reason, _ := gotN["reason"].(string)
				if !strings.HasPrefix(reason, prefix) {
					t.Fatalf("reason %q does not start with %q", reason, prefix)
				}
				delete(gotN, "reason")
				delete(expN, "reason")
			}
			delete(expN, "reason_match")
			delete(expN, "reason_prefix")
			if !reflect.DeepEqual(gotN, expN) {
				gb, _ := json.Marshal(gotN)
				eb, _ := json.Marshal(expN)
				t.Fatalf("intent %v\n got  %s\n want %s", row["intent"], gb, eb)
			}
		})
	}
}

// ───────────────────────────────────────────────────────────── the strict X.509 readers

func b64Std(t *testing.T, v any) []byte {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("not a base64 string: %v", v)
	}
	return nodeB64(s)
}

// runX509Row runs one unit row: {"ok": true, "value": V} or {"ok": false, "error": text}.
func runX509Row(t *testing.T, fn string, in map[string]any) map[string]any {
	t.Helper()
	okv := func(v any) map[string]any { return map[string]any{"ok": true, "value": v} }
	bad := func(err error) map[string]any { return map[string]any{"ok": false, "error": err.Error()} }
	extList := func(tbl *extTable) any {
		out := []any{}
		for _, oid := range tbl.oids {
			e := tbl.m[oid]
			out = append(out, map[string]any{"oid": oid, "critical": e.critical, "value": hex.EncodeToString(e.value)})
		}
		return out
	}
	instant := func(i derInstant) any {
		if !i.ok {
			return nil
		}
		return i.ms
	}
	switch fn {
	case "read_cert_role_info":
		info, err := readCertRoleInfo(b64Std(t, in["cert"]))
		if err != nil {
			return bad(err)
		}
		m := map[string]any{"hasBasicConstraints": info.hasBasicConstraints, "ca": info.ca, "hasKeyUsage": info.hasKeyUsage, "keyCertSign": info.keyCertSign}
		if info.pathLen >= 0 {
			m["pathLen"] = info.pathLen
		}
		return okv(m)
	case "parse_cert_extensions":
		tbl, err := parseCertExtensions(b64Std(t, in["cert"]))
		if err != nil {
			return bad(err)
		}
		return okv(extList(tbl))
	case "parse_tbs_extensions":
		tbl, err := parseTbsExtensions(b64Std(t, in["tbs"]))
		if err != nil {
			return bad(err)
		}
		return okv(extList(tbl))
	case "tbs_of_certificate":
		tbs, err := tbsOfCertificate(b64Std(t, in["cert"]))
		if err != nil {
			return bad(err)
		}
		return okv(base64.StdEncoding.EncodeToString(tbs))
	case "unrecognised_critical_extension":
		var rec map[string]bool
		if l, ok := in["recognised"].([]any); ok {
			rec = map[string]bool{}
			for _, x := range l {
				rec[x.(string)] = true
			}
		}
		oid, found, err := unrecognisedCriticalExtension(b64Std(t, in["cert"]), rec)
		if err != nil {
			return bad(err)
		}
		if !found {
			return okv(nil)
		}
		return okv(oid)
	case "check_chain_roles":
		var chain [][]byte
		for _, c := range in["chain"].([]any) {
			chain = append(chain, b64Std(t, c))
		}
		if why := checkChainRoles(chain); why != "" {
			return okv(why)
		}
		return okv(nil)
	case "der_validity_ms":
		from, to := derValidity(b64Std(t, in["cert"]))
		return okv(map[string]any{"from": instant(from), "to": instant(to)})
	case "parse_der_time":
		tag, _ := asFinite(in["tag"])
		text, _ := in["text"].(string)
		return okv(instant(parseDerTime(int(tag), text)))
	}
	t.Fatalf("unknown x509 function %s", fn)
	return nil
}

func TestX509StrictVectors(t *testing.T) {
	doc := loadAttestVectors(t)
	blobs, _ := doc["blobs"].(map[string]any)
	rows, _ := doc["x509_vectors"].([]any)
	if len(rows) < 90 {
		t.Fatalf("only %d x509 vectors", len(rows))
	}
	for _, r := range rows {
		hr, err := hydrateBlobs(r, blobs)
		if err != nil {
			t.Fatal(err)
		}
		row := hr.(map[string]any)
		id, _ := row["id"].(string)
		t.Run(id, func(t *testing.T) {
			fn, _ := row["fn"].(string)
			in, _ := row["input"].(map[string]any)
			got := normJSON(t, runX509Row(t, fn, in))
			want := normJSON(t, row["expect"])
			if !reflect.DeepEqual(got, want) {
				gb, _ := json.Marshal(got)
				wb, _ := json.Marshal(want)
				t.Fatalf("got %s want %s", gb, wb)
			}
		})
	}
}
