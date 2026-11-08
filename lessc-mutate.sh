#!/usr/bin/env bash
# lessc-mutate.sh: hand-mutation gate for lessc/atlas_less.c, our C wrapper over the LESS reference (go-mutate mutates only
# Go). Each mutant of lessc-mutants.json (a literal substring replacement in one line) is applied to a fresh copy of this
# module and run against the LESS known answers and the direct wrapper tests:
#   go test -count=1 -tags less -run '^(TestLessKnownAnswers|TestLessWrapper.*)$' .
# (never TestLessCopyMatchesCanonical: the mutated copy differs from the canonical one, which would "kill" every mutant).
# killed = a test failed (--- FAIL). survived fails the gate unless the mutant is in lessc-mutants-ledger.json (true
# equivalents, each with its proof); build-failed and crash/timeout always fail (an equivalent runs clean); a ledger entry
# for a killed or unknown mutant is stale and fails too. Mutants with "applicable": false (the Windows branch) are listed, never run. The unmutated baseline must
# pass first. Needs bash, python3, go with cgo, coreutils timeout. Env: JOBS (parallel mutants, default 2), MUTANT_TIMEOUT
# (seconds per mutant, build included, default 600).
set -euo pipefail
MOD="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST="$MOD/lessc-mutants.json"
LEDGER="$MOD/lessc-mutants-ledger.json"
SRC="lessc/atlas_less.c"
JOBS="${JOBS:-2}"
MUTANT_TIMEOUT="${MUTANT_TIMEOUT:-600}"
RUN='^(TestLessKnownAnswers|TestLessWrapper.*)$'
# each copy sits BESIDE the module: in the monorepo the tests reach the vectors at ../../packages/..., so the copy must be
# at the module's depth (the mirror vendors them inside the module, where any location works)
PARENT="$(dirname "$MOD")"
OUT="$(mktemp -d)"
TAG="$$" # this run's copies: .lessc-mut-<TAG>-<id> (run_one runs in child shells, whose $$ differs)
trap 'rm -rf "$OUT" "$PARENT"/.lessc-mut-"$TAG"-*' EXIT
export MOD LIST SRC MUTANT_TIMEOUT RUN PARENT OUT TAG

# validate the list + ledger; print "<id> run|na" per mutant
python3 - "$LIST" "$LEDGER" "$MOD/$SRC" > "$OUT/plan.txt" <<'PY'
import json, sys
muts, led = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
src = open(sys.argv[3]).read().split("\n")
bad = []
ids = [m.get("id") for m in muts]
if len(set(ids)) != len(ids): bad.append("duplicate mutant ids")
for m in muts:
    i = m.get("id")
    if any(not isinstance(m.get(k), str) or not m[k] for k in ("id", "line", "from", "to", "what")): bad.append(f"{i}: needs id, line, from, to, what"); continue
    if src.count(m["line"]) != 1: bad.append(f"{i}: line occurs {src.count(m['line'])} times in the source (want exactly 1)")
    if m["line"].count(m["from"]) != 1: bad.append(f"{i}: 'from' occurs {m['line'].count(m['from'])} times in the line (want exactly 1)")
    if m["from"] == m["to"]: bad.append(f"{i}: from == to")
    if m.get("applicable", True) is not True and not m.get("reason"): bad.append(f"{i}: not applicable without a reason")
lids = [e.get("id") for e in led]
if len(set(lids)) != len(lids): bad.append("duplicate ledger ids")
na = {m["id"] for m in muts if m.get("applicable", True) is not True}
for e in led:
    if set(e) != {"id", "reason"} or not e["reason"]: bad.append(f"ledger {e.get('id')}: needs exactly id and a reason")
    if e.get("id") not in ids: bad.append(f"ledger {e.get('id')}: stale (no such mutant)")
    if e.get("id") in na: bad.append(f"ledger {e.get('id')}: stale (mutant is not applicable, never run)")
if bad:
    for b in bad: print("::error::" + b, file=sys.stderr)
    sys.exit(1)
for m in muts: print(m["id"], "na" if m["id"] in na else "run")
PY

# apply mutant <id> to <file> in place: the line must occur exactly once and 'from' exactly once in it
apply_mutant() {
  python3 - "$LIST" "$1" "$2" <<'PY'
import json, sys
m = next(x for x in json.load(open(sys.argv[1])) if x["id"] == sys.argv[2])
lines = open(sys.argv[3]).read().split("\n")
at = [i for i, l in enumerate(lines) if l == m["line"]]
if len(at) != 1 or lines[at[0]].count(m["from"]) != 1:
    sys.exit(f"{m['id']}: does not apply exactly once")
lines[at[0]] = lines[at[0]].replace(m["from"], m["to"])
open(sys.argv[3], "w").write("\n".join(lines))
PY
}

# run_one <id|baseline>: fresh copy, mutate, test, classify into $OUT/<id>.status
run_one() {
  local id="$1" copy="$PARENT/.lessc-mut-$TAG-$1" log="$OUT/$1.log" rc=0 st
  rm -rf "$copy"; mkdir "$copy"
  tar -C "$MOD" --exclude=./.git -cf - . | tar -C "$copy" -xf -
  if [ "$id" != baseline ]; then
    if ! apply_mutant "$id" "$copy/$SRC" >"$log" 2>&1 || cmp -s "$MOD/$SRC" "$copy/$SRC"; then
      echo apply-failed >"$OUT/$id.status"; rm -rf "$copy"; return 0
    fi
  fi
  (cd "$copy" && GOWORK=off timeout -k 10 "$MUTANT_TIMEOUT" go test -count=1 -tags less -v -run "$RUN" .) >>"$log" 2>&1 || rc=$?
  rm -rf "$copy"
  if [ "$rc" = 0 ]; then st=survived
  elif grep -q -- '--- FAIL' "$log"; then st=killed
  elif [ "$rc" = 124 ] || [ "$rc" = 137 ]; then st=timeout
  elif grep -Eq '\[(build|setup) failed\]' "$log"; then st=build-failed
  else st=crash; fi
  echo "$st" >"$OUT/$id.status"
  echo "$id: $st"
}
export -f apply_mutant run_one

echo "baseline (unmutated)"
run_one baseline >/dev/null
if [ "$(cat "$OUT/baseline.status")" != survived ] || ! grep -q -- '--- PASS: TestLessKnownAnswers' "$OUT/baseline.log" \
   || ! grep -q -- '--- PASS: TestLessWrapper' "$OUT/baseline.log"; then
  cat "$OUT/baseline.log"; echo "::error::the unmutated baseline must pass and run TestLessKnownAnswers + TestLessWrapper*"; exit 1
fi

awk '$2 == "run" { print $1 }' "$OUT/plan.txt" | xargs -P "$JOBS" -I{} bash -c 'run_one "$1"' _ {}

python3 - "$LIST" "$LEDGER" "$OUT" <<'PY'
import json, os, sys
muts, led = json.load(open(sys.argv[1])), {e["id"]: e for e in json.load(open(sys.argv[2]))}
out = sys.argv[3]
counts, fail = {}, []
for m in muts:
    i = m["id"]
    if m.get("applicable", True) is not True:
        st = "not-applicable"
    else:
        p = os.path.join(out, i + ".status")
        st = open(p).read().strip() if os.path.exists(p) else "not-run"
    counts[st] = counts.get(st, 0) + 1
    if st in ("killed", "not-applicable"):
        if i in led: fail.append(f"{i}: stale ledger entry ({st})")
    elif i in led and st != "survived":
        fail.append(f"{i}: ledgered as equivalent but {st} (an equivalent runs clean)")
    elif i not in led:
        fail.append(f"{i}: {st}, not in the ledger ({m['what']})")
        log = os.path.join(out, i + ".log")
        if st != "survived" and os.path.exists(log): print(f"--- {i} log tail:\n" + "".join(open(log).readlines()[-25:]))
print(f"lessc mutants: {len(muts)} listed; " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())) + f"; ledgered {len(led)}")
for f in fail: print("::error::" + f)
sys.exit(1 if fail else 0)
PY
