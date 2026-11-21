#!/usr/bin/env node
// Go merge gate, dead-minion rule: a ledgered EQUIVALENT mutant that a test KILLED in this run is evidence of a nondeterministic
// killer (the equivalence proof says no test can tell it from the original), not a gap in the ledger. mutation-merge.mjs fails such
// an entry as STALE; this wraps it:
//   node stale-killed.mjs <merge.log> <mut-results dir> <merge exit code> [sigstore-results dir]     (exit code 0: nothing to do)
// Fails (exit 1) unless the merge failed ONLY by STALE ("no survivor at this site") lines, none of its survivors was unlisted, and
// every one of those lines is a mutant that a mut-results/*/results.json records as plainly killed (same file, source line and
// mutant). A stale entry whose mutant was not generated, or was generated but did not die, still fails. Each excused entry is a
// ::notice:: naming it and the test that killed it. The sigstore module's results (its own directory, file names relative to
// sigstore/) are read with that prefix, as the ledger names them.
//   node stale-killed.mjs --selftest        both cases on a small fixture (the merge runs it first: a control that must hold)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// The label is `<crate>/<file>:<line>[ (#n)][ in <fn>]: <mutant, 90 chars> | <source line, 70 chars>`. Both halves can contain ' | ' (a
// `|` operator mutant, a Go source line), so the tail is kept whole and compared with the one built from each killed result.
const STALE = /^STALE \(no survivor at this site; killed or changed, remove it\): (\S+?)\/(\S+?\.go):(\d+)(?: \(#(\d+)\))?(?: in (.+?))?: (.*)$/;

export function judge(log, results, code) {
  if (code === 0) return { ok: true, notices: [], errors: [] };
  const lines = log.split('\n').map((l) => l.replace(/^\S+Z /, '').replace(/^##\[error\]/, '')); // CI timestamps / annotations
  const stale = lines.map((l) => STALE.exec(l)).filter(Boolean);
  const tally = /unlisted survivors: (\d+); stale entries: (\d+)/.exec(log);
  const errors = [];
  if (!tally) errors.push('no ledger tally in the merge log (the merge failed before the ledger check)');
  else {
    if (Number(tally[1]) !== 0) errors.push(`${tally[1]} unlisted survivor(s)`);
    if (Number(tally[2]) !== stale.length || stale.length === 0) errors.push(`${tally[2]} stale entr(ies) but ${stale.length} excusable STALE line(s)`);
  }
  // the checker prints other error shapes too (survivor site matches N ledger entries, UNPLACEABLE SURVIVOR, source file gone,
  // multiplicity ...): whatever it prints, its own count of problems must be exactly the stale lines excused here
  const failLine = lines.map((l) => /^FAIL: (\d+) problem\(s\); \d+ entries$/.exec(l)).find(Boolean);
  if (!failLine) errors.push('no "FAIL: N problem(s)" count in the merge log');
  else if (Number(failLine[1]) !== stale.length) errors.push(`the checker counts ${failLine[1]} problem(s) but ${stale.length} stale line(s) are excused: something else failed`);
  const bad = lines.filter((l) => /^(STALE|AMBIGUOUS|UNLISTED|duplicate|bad |fn '|multiplicity|FAIL)/.test(l) && !STALE.test(l) && !/^FAIL: \d+ problem\(s\); \d+ entries$/.test(l));
  for (const b of bad) errors.push(b);
  const notices = [];
  for (const m of stale) {
    const [, , file, lineno, , fn, tail] = m;
    const hit = results.find((r) => r.status === 'killed' && r.file === file && String(r.line) === lineno && `${String(r.mutant).slice(0, 90)} | ${String(r.line_text || '').trim().slice(0, 70)}` === tail);
    if (hit) notices.push(`::notice::equivalent entry killed this run (nondeterministic killer): ${file}:${lineno}${fn ? ` in ${fn}` : ''}: ${tail} (${String(hit.evidence || 'no evidence recorded').split('\n')[0].replace(/^--- FAIL: /, '')})`);
    else errors.push(`stale entry, no such mutant killed this run: ${file}:${lineno}: ${tail}`);
  }
  return { ok: errors.length === 0, notices, errors };
}

export function loadResults(dir, prefix = '') {
  const out = [];
  const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (e.name === 'results.json') for (const r of JSON.parse(fs.readFileSync(p, 'utf8'))) out.push(prefix ? { ...r, file: prefix + r.file } : r); } };
  if (dir && fs.existsSync(dir)) walk(dir);
  return out;
}

function selftest() {
  const rec = { file: 'pca.go', line: 9, mutant: 'binary < -> <=', line_text: 'if x < 1 {', status: 'killed', evidence: '--- FAIL: TestX (0.00s)' };
  const one = 'STALE (no survivor at this site; killed or changed, remove it): go-pca/pca.go:9 (#1): binary < -> <= | if x < 1 {';
  const withFn = 'STALE (no survivor at this site; killed or changed, remove it): go-pca/pca.go:9 in zkRank (package var): binary < -> <= | if x < 1 {';
  const tally = (u, s, f = s) => `FAIL: ${f} problem(s); 5 entries\nledger entries for go-pca: 5; unlisted survivors: ${u}; stale entries: ${s}\n`;
  const t = (name, r, ok) => { if (r.ok !== ok) { console.error(`stale-killed selftest FAILED: ${name}: ${JSON.stringify(r)}`); process.exit(1); } return r; };
  const r1 = t('killed equivalent is a notice', judge(`${one}\n${tally(0, 1)}`, [rec], 1), true);
  if (r1.notices.length !== 1 || !r1.notices[0].startsWith('::notice::equivalent entry killed this run (nondeterministic killer)')) { console.error('selftest: no notice'); process.exit(1); }
  t('an entry with a function name is matched too', judge(`${withFn}\n${tally(0, 1)}`, [rec], 1), true);
  t('not killed (not generated / survived elsewhere) stays stale', judge(`${one}\n${tally(0, 1)}`, [], 1), false);
  t('a mutant that survived does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, status: 'SURVIVED' }], 1), false);
  t('another mutant killed does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, mutant: 'binary < -> >=' }], 1), false);
  t('another line killed does not excuse it', judge(`${one}\n${tally(0, 1)}`, [{ ...rec, line: 10 }], 1), false);
  t('an unlisted survivor still fails', judge(`${one}\nUNLISTED SURVIVOR go-pca/a.go:1: m | l\n${tally(1, 1, 2)}`, [rec], 1), false);
  // the checker's other error shapes: only its own problem count catches them
  for (const other of ['UNPLACEABLE SURVIVOR go-pca/a.go:1: m', 'survivor site matches 2 ledger entries: go-pca/a.go:1', 'source file gone: go-pca/a.go', 'something new the checker prints']) {
    t(`stale plus "${other.slice(0, 24)}" fails`, judge(`${one}\n${other}\n${tally(0, 1, 2)}`, [rec], 1), false);
  }
  t('a missing FAIL count fails', judge(`${one}\nledger entries for go-pca: 5; unlisted survivors: 0; stale entries: 1\n`, [rec], 1), false);
  // ' | ' inside the source line or the mutant is not a separator
  const piped = { ...rec, mutant: 'binary | -> &', line_text: 'x := a | b | c' };
  const pipedLine = 'STALE (no survivor at this site; killed or changed, remove it): go-pca/pca.go:9 (#1): binary | -> & | x := a | b | c';
  t('a source line with " | " matches', judge(`${pipedLine}\n${tally(0, 1)}`, [piped], 1), true);
  t('a piped line does not match another mutant', judge(`${pipedLine}\n${tally(0, 1)}`, [{ ...piped, mutant: 'binary | -> ^' }], 1), false);
  t('a multiplicity mismatch still fails', judge(`${one}\nmultiplicity: 2 identical survivor(s) at this site, entry covers 1: go-pca/a.go:1\n${tally(0, 1)}`, [rec], 1), false);
  t('a source-line-gone stale still fails', judge(`STALE (source line gone): go-pca/pca.go:9: m | l\n${tally(0, 1)}`, [rec], 1), false);
  // the sigstore module: its results name sigstore.go, the ledger and the STALE line name sigstore/sigstore.go
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'stale-killed-'));
  fs.mkdirSync(path.join(tmp, 'sig')); fs.mkdirSync(path.join(tmp, 'root', 'mut-results-1'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'sig', 'results.json'), JSON.stringify([{ ...rec, file: 'sigstore.go' }]));
  fs.writeFileSync(path.join(tmp, 'root', 'mut-results-1', 'results.json'), JSON.stringify([rec]));
  const loaded = [...loadResults(path.join(tmp, 'root')), ...loadResults(path.join(tmp, 'sig'), 'sigstore/')];
  fs.rmSync(tmp, { recursive: true, force: true });
  if (loaded.length !== 2 || loaded[1].file !== 'sigstore/sigstore.go') { console.error('stale-killed selftest FAILED: sigstore prefix'); process.exit(1); }
  const sig = 'STALE (no survivor at this site; killed or changed, remove it): go-pca/sigstore/sigstore.go:9 (#1): binary < -> <= | if x < 1 {';
  t('a killed sigstore equivalent is a notice', judge(`${sig}\n${tally(0, 1)}`, loaded, 1), true);
  t('the root file of the same name does not excuse the sigstore entry', judge(`${sig}\n${tally(0, 1)}`, [rec], 1), false);
  t('exit 0 passes', judge('', [], 0), true);
  console.log('stale-killed selftest ok');
}

if (process.argv[2] === '--selftest') selftest();
else if (process.argv[1] && import.meta.url === new URL(`file://${path.resolve(process.argv[1])}`).href) {
  selftest(); // the control first
  const [logFile, resultsDir, code, sigDir] = process.argv.slice(2);
  const results = [...loadResults(resultsDir), ...loadResults(sigDir, 'sigstore/')];
  const r = judge(fs.readFileSync(logFile, 'utf8'), results, Number(code));
  for (const n of r.notices) console.log(n);
  for (const e of r.errors) console.log(`::error::${e}`);
  process.exit(r.ok ? 0 : 1);
}
