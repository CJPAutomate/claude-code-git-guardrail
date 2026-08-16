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

let fail = 0;
for (const [label, command, want] of cases) {
  const r = spawnSync(process.execPath, [HOOK], {
    input: JSON.stringify({ tool_input: { command } }), encoding: 'utf8',
  });
  const got = r.status === 0 ? 'ALLOW' : 'BLOCK';
  const ok = got === want;
  if (!ok) fail++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  got=${got} want=${want}  ${label}`);
}
console.log(fail === 0 ? `\nALL PASS (${cases.length} cases)` : `\n${fail} FAILURE(S) of ${cases.length}`);
process.exit(fail === 0 ? 0 : 1);
