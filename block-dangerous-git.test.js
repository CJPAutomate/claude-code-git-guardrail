// Test suite for the git guardrail hook (block-dangerous-git.js).
// Run after ANY edit to the hook:   node block-dangerous-git.test.js
// Exit 0 = all pass. Dependency-free.
//
// NOTE: command strings are assembled at RUNTIME from fragments so that this
// file's own text never contains a literal dangerous git command — otherwise
// the live hook blocks the very Bash call used to run these tests.
const { spawnSync } = require('child_process');
const HOOK = require('path').join(__dirname, 'block-dangerous-git.js');
// Fixture paths are GENERIC placeholders, not any real machine's paths. These cases
// exist to prove the exemption keys off the path SHAPE (.claude/projects/<slug>/memory),
// so the slug used here is arbitrary on purpose.
//
// `C--Temp-cjp` is the one exception: the hook's regex still carries that literal as a
// backwards-compatible alternative for a retired path form, so a case must exercise it
// or that branch goes untested. It is a legacy folder name, nothing more.
const MEM = String.raw`C:\Users\dev\.claude\projects\C--Temp-cjp\memory`;
const MEMU = '~/.claude/projects/C--Temp-cjp/memory';
// A differently-shaped slug — proves the exemption is not keyed to one machine's slug.
const MEMMAC = '/Users/dev/.claude/projects/-Users-dev/memory';

const g = 'git ';
const push = g + 'push ';
const HARD = 'reset --' + 'hard';     // split so the literal never appears here
const CLEANF = 'clean -' + 'fd';
const FORCE = '--for' + 'ce';

const cases = [
  // ---- refspec-less push (bypass found + closed 2026-08-16): MUST BLOCK ----
  // `git push` with no refspec pushes the CURRENT branch, which this hook cannot see.
  // Before the fix these were ALLOW while the explicit `push origin main` form was BLOCK,
  // even though on a main-tracking branch the two do exactly the same thing.
  ['bare push, no remote',          g + '-C /Users/dev/.claude/hooks push', 'BLOCK'],
  ['bare push, remote only',        g + '-C /Users/dev/.claude/hooks push origin', 'BLOCK'],
  ['bare push in a loop variable',  'for r in a b; do ' + g + '-C $r push; done', 'BLOCK'],
  ['bare push with flags only',     push + '--quiet', 'BLOCK'],
  ['memory bare push still exempt', g + '-C ' + MEMMAC + ' push', 'ALLOW'],
  ['feature push still allowed',    push + 'origin feat/x', 'ALLOW'],
  ['feature push -u still allowed', push + '-u origin feat/x', 'ALLOW'],

  // ---- memory-store exemption: MUST ALLOW ---------------------------------
  ['memory push via -C',            g + '-C "' + MEM + '" push origin main', 'ALLOW'],
  ['memory push via cd &&',         'cd "$HOME/.claude/projects/C--Temp-cjp/memory" && ' + push + 'origin main', 'ALLOW'],
  ['memory push, fwd slashes',      'cd /c/Users/dev/.claude/projects/C--Temp-cjp/memory && ' + push + 'origin main', 'ALLOW'],
  ['memory push HEAD:main',         g + '-C ' + MEM + ' push origin HEAD:main', 'ALLOW'],

  // ---- macOS store path (2026-08-12 migration) ----------------------------
  ['mac memory push via -C',        g + '-C "' + MEMMAC + '" push origin main', 'ALLOW'],
  ['mac memory push via cd &&',     'cd "' + MEMMAC + '" && ' + push + 'origin main', 'ALLOW'],
  ['mac memory push HEAD:main',     g + '-C ' + MEMMAC + ' push origin HEAD:main', 'ALLOW'],
  // …and the exemption must NOT widen: force, smuggling and destructive verbs still block.
  ['mac memory push ' + FORCE,      g + '-C ' + MEMMAC + ' push ' + FORCE + ' origin main', 'BLOCK'],
  ['mac SMUGGLE: memory + other',   g + '-C ' + MEMMAC + ' push origin main && ' + g + '-C ~/repos/x push origin main', 'BLOCK'],
  ['mac memory hard reset',         g + '-C ' + MEMMAC + ' ' + HARD + ' origin/main', 'BLOCK'],
  ['mac memory branch -D',          g + '-C ' + MEMMAC + ' branch -D feat/x', 'BLOCK'],

  // ---- false positives that must now be ALLOWED ---------------------------
  ['worktree --force then push',    g + 'worktree remove ' + FORCE + ' wt && ' + push + 'origin feat/x', 'ALLOW'],
  ['worktree --force alone',        g + 'worktree remove ' + FORCE + ' /c/Temp/wt-1', 'ALLOW'],
  ['push feat + gh pr --base main', push + 'origin feat/x && gh pr create --base main --title t', 'ALLOW'],
  ['push -u feat + gh pr main',     push + '-u origin feat/x && gh pr create --base main', 'ALLOW'],
  ['push feat + echo origin/main',  push + 'origin feat/x && echo origin/main', 'ALLOW'],
  // ACCEPTED limitation (not a bug to fix): a trailing shell comment lives in the
  // same segment as the push, so a comment mentioning main still blocks. Stripping
  // `#…` was considered and REJECTED — a bare `git push origin` pushes the CURRENT
  // branch, so making text after `#` invisible would open a way to hide a main push.
  // Workaround is trivial: leave the comment off the push line.
  ['ACCEPTED FP: comment says main', push + 'origin feat/x # rebased onto main', 'BLOCK'],

  // ---- must still BLOCK ---------------------------------------------------
  ['app push to main'    ,           'cd /c/Temp/app && ' + push + 'origin main', 'BLOCK'],
  ['bare unscoped push main',       push + 'origin main', 'BLOCK'],
  ['second repo push main',           'cd /c/Temp/second-repo && ' + push + 'origin main', 'BLOCK'],
  ['push master',                   push + 'origin master', 'BLOCK'],
  ['BYPASS: main push then feat',   push + 'origin main && ' + push + 'origin feat/x', 'BLOCK'],
  ['BYPASS: feat push then main',   push + 'origin feat/x && ' + push + 'origin main', 'BLOCK'],
  ['force-push feature branch',     push + FORCE + ' origin feat/x', 'BLOCK'],
  ['force-with-lease feature',      push + FORCE + '-with-lease origin feat/x', 'BLOCK'],
  ['push -f feature',               push + '-f origin feat/x', 'BLOCK'],
  ['+refspec force form',           push + 'origin +feat/x', 'BLOCK'],
  ['memory FORCE push',             g + '-C ' + MEM + ' ' + push + FORCE + ' origin main', 'BLOCK'],
  ['memory push -f',                'cd ' + MEMU + ' && ' + push + '-f origin main', 'BLOCK'],
  ['memory +refspec force',         g + '-C ' + MEM + ' ' + push + 'origin +main', 'BLOCK'],
  ['SMUGGLE: memory + other push', 'cd ' + MEMU + ' && ' + push + 'origin main && cd /c/Temp/app && ' + push + 'origin main', 'BLOCK'],
  ['path only in a comment',        'cd /c/Temp/app && ' + push + 'origin main # ' + MEMU, 'BLOCK'],
  ['memory hard reset',             g + '-C ' + MEM + ' ' + HARD + ' HEAD~1', 'BLOCK'],
  ['app hard reset via -C'  ,      g + '-C /c/Temp/app ' + HARD + ' HEAD~1', 'BLOCK'],
  ['memory clean force',            'cd ' + MEMU + ' && ' + g + CLEANF, 'BLOCK'],
  ['memory branch -D',              g + '-C ' + MEM + ' branch -D main', 'BLOCK'],
  ['checkout . discard',            'cd /c/Temp/app && ' + g + 'checkout .', 'BLOCK'],

  // ---- ordinary work: unchanged ------------------------------------------
  ['feature branch push',           'cd /c/Temp/app && ' + push + 'origin feat/thing', 'ALLOW'],
  ['plain status',                  'cd /c/Temp/app && ' + g + 'status', 'ALLOW'],
  ['single-file checkout',          'cd /c/Temp/app && ' + g + 'checkout -- src/app.js', 'ALLOW'],
  ['branch -d merged',              g + 'branch -d feat/merged', 'ALLOW'],
];

// ---- TRANSPORT COVERAGE (added 2026-08-16) ------------------------------
// Before this, the hook was invoked only for Bash and read .tool_input.command,
// a field only Bash carries. A forge MCP server reached the SAME operations and
// was never seen: a standalone negative control measured 9 of 9 sailing through.
// These cases keep that closed. Shape: [label, tool_name, tool_input, want].
const mcpCases = [
  // --- forge WRITES: fail closed -----------------------------------------
  ['forge: delete the main ref',   'mcp__github__delete_ref',  { ref: 'heads/main' }, 'BLOCK'],
  ['forge: force-update a ref',    'mcp__github__update_ref',  { ref: 'heads/main', force: true }, 'BLOCK'],
  ['forge: commit onto main',      'mcp__github__create_or_update_file', { branch: 'main' }, 'BLOCK'],
  ['forge: push_files to main',    'mcp__github__push_files',  { branch: 'main' }, 'BLOCK'],
  ['forge: delete a repository',   'mcp__github__delete_repository', {}, 'BLOCK'],
  ['forge: create a PR (write)',   'mcp__github__create_pull_request', {}, 'BLOCK'],
  ['forge: unknown future tool',   'mcp__github__some_future_tool', { unexpected: true }, 'BLOCK'],
  ['forge: unrecognised shape',    'mcp__github__delete_ref',  null, 'BLOCK'],
  ['forge: gitlab server too',     'mcp__gitlab__delete_ref',  {}, 'BLOCK'],
  ['forge: plugin-namespaced',     'mcp__plugin_acme_github__delete_ref', {}, 'BLOCK'],
  // FORGE_OP backstop: an OPAQUE (uuid) server is still caught when the tool
  // name is high-specificity — the only axis available when the server is anonymous.
  ['forge: uuid server, known op', 'mcp__230416e2-71c4-4361-abef-ca4cc656e5a8__merge_pull_request', {}, 'BLOCK'],

  // --- forge READS: allowed ----------------------------------------------
  ['forge read: get file',         'mcp__github__get_file_contents', {}, 'ALLOW'],
  ['forge read: list PRs',         'mcp__github__list_pull_requests', {}, 'ALLOW'],
  ['forge read: search code',      'mcp__github__search_code', {}, 'ALLOW'],

  // --- NOT a forge: must stay allowed, or the guard cries wolf ------------
  // Supabase genuinely exposes delete_branch / reset_branch / merge_branch on
  // DATABASE branches. FORGE_OP is deliberately high-specificity so these pass;
  // broadening it to a bare /delete|merge|reset/ would block ordinary work.
  ['supabase delete_branch',       'mcp__49a2518e-ab12-453f-bbab-55195cf38f35__delete_branch', {}, 'ALLOW'],
  ['supabase reset_branch',        'mcp__49a2518e-ab12-453f-bbab-55195cf38f35__reset_branch', {}, 'ALLOW'],
  ['supabase merge_branch',        'mcp__49a2518e-ab12-453f-bbab-55195cf38f35__merge_branch', {}, 'ALLOW'],
  ['drive trash_file',             'mcp__b9ab8664-d88f-4232-8ccc-38d11791f63b__trash_file', {}, 'ALLOW'],
  ['playwright click',             'mcp__playwright__browser_click', {}, 'ALLOW'],
  // ⚠️ STATED RESIDUAL, asserted so it is on the record rather than a surprise:
  // a forge behind an OPAQUE server id using a GENERIC tool name is NOT detected.
  // Mitigation is registration — add the server id to FORGE_SERVER in both hooks.
  ['RESIDUAL: uuid forge, generic name', 'mcp__230416e2-71c4-4361-abef-ca4cc656e5a8__delete_branch', {}, 'ALLOW'],

  // --- built-in non-Bash tools: untouched ---------------------------------
  ['builtin Read',                 'Read',  { file_path: '/x' }, 'ALLOW'],
  ['builtin Edit',                 'Edit',  { file_path: '/x' }, 'ALLOW'],
  ['builtin Write',                'Write', { file_path: '/x' }, 'ALLOW'],
];

// Bash cases run twice: once WITHOUT tool_name (the legacy fixture shape, which
// must keep working) and once WITH tool_name:"Bash" (the real payload — the docs
// confirm PreToolUse always sends it). A rule that only held for one of the two
// would be a gap dressed as coverage.
let fail = 0;
let count = 0;
for (const [label, command, want] of cases) {
  for (const [suffix, payload] of [
    ['', { tool_input: { command } }],
    [' [+tool_name]', { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command } }],
  ]) {
    const r = spawnSync(process.execPath, [HOOK], { input: JSON.stringify(payload), encoding: 'utf8' });
    const got = r.status === 0 ? 'ALLOW' : 'BLOCK';
    const ok = got === want;
    count++;
    if (!ok) fail++;
    console.log(`${ok ? 'ok  ' : 'FAIL'}  got=${got} want=${want}  ${label}${suffix}`);
  }
}
for (const [label, tool_name, tool_input, want] of mcpCases) {
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name, tool_input }), encoding: 'utf8',
  });
  const got = r.status === 0 ? 'ALLOW' : 'BLOCK';
  const ok = got === want;
  count++;
  if (!ok) fail++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  got=${got} want=${want}  MCP ${label}`);
}

// ---- DRIFT GATE ---------------------------------------------------------
// The classifier is duplicated into both guards on purpose (self-containment:
// a failed `require` exits non-2, which Claude Code treats as a NON-blocking
// error — i.e. fail open — so a shared file is a single point of disarmament).
// Duplication is only safe if drift is detected, so assert the copies match.
// ⚠️ THREE outcomes, not two. codex-review-guard.js is LIVE-ONLY BY DESIGN — it
// is deliberately not published to the public mirror. A plain pass/fail gate
// therefore turned the public repo's suite RED for a file that is *supposed* to
// be absent: an instrument fault wearing a defect's clothes, and on the one
// artifact strangers verify by running it. So absence is N/A (announced, never
// silent), while a present-but-different copy is a real FAIL.
const fs = require('fs');
const COUNTERPART = require('path').join(__dirname, 'codex-review-guard.js');
const grab = (f) => {
  const src = fs.readFileSync(require('path').join(__dirname, f), 'utf8');
  const m = src.match(/const FORGE_SERVER = [\s\S]*?^}/m);
  if (!m) throw new Error(`classifier block not found in ${f} — the gate cannot measure`);
  return m[0];
};
if (!fs.existsSync(COUNTERPART)) {
  console.log('n/a   classifier drift gate — codex-review-guard.js is not in this checkout ' +
    '(expected in the public mirror, where it is live-only by design; NOT a pass)');
} else {
  let driftOk;
  try {
    driftOk = grab('block-dangerous-git.js') === grab('codex-review-guard.js');
  } catch (e) {
    driftOk = false;
    console.log('FAIL  drift gate could not run: ' + e.message);
  }
  count++;
  if (!driftOk) fail++;
  console.log(`${driftOk ? 'ok  ' : 'FAIL'}  classifier identical in both guards (no drift)`);
}

console.log(fail === 0 ? `\nALL PASS (${count} cases)` : `\n${fail} FAILURE(S) of ${count}`);
process.exit(fail === 0 ? 0 : 1);
