#!/usr/bin/env node
/*
 * PreToolUse(Bash) git guardrail — CJP.
 *
 * Blocks, for the AGENT only (not the human), the git operations that are
 * irreversible or dangerous on a SHARED checkout worked by concurrent sessions:
 *   - force-push (any form: --force, --force-with-lease, -f, +refspec)
 *   - pushing directly to main / master
 *   - git reset --hard
 *   - git clean -f / -fd / -xf ...
 *   - git branch -D            (use -d for merged branches)
 *   - git checkout . / git restore .  (discard ALL working-tree changes)
 *
 * ALLOWS ordinary feature-branch pushes (git push origin <branch>) so the
 * PR workflow stays autonomous.
 *
 * NARROW EXEMPTION — the agent's own memory store (added 2026-08-10):
 *   ~/.claude/projects/<project-slug>/memory  ->  a private, single-writer repo
 * That repo has no CI, no reviewers and no ruleset; push-to-main IS its intended
 * workflow, and /wrap-session writes to it every session. So a push to main is
 * allowed *only* when the command explicitly scopes itself to that directory via
 * `git -C <path>` or `cd <path> && …` (the hook cannot see the shell's cwd, so an
 * unscoped bare `git push origin main` stays blocked — deliberately fail-safe).
 * Everything else still applies there: force-push, reset --hard, clean -f, etc.
 * remain blocked, because a shared knowledge base is exactly what you must not
 * clobber. The exemption also refuses to fire on a command containing more than
 * one `git push`, so it can't be used to smuggle a second push to another repo.
 *
 * Contract: reads the tool call as JSON on stdin; the command is at
 * .tool_input.command. Exit 2 => Claude Code blocks the call and feeds stderr
 * back to the model. Any parse failure or non-git command exits 0 (allow) —
 * but note a parse failure means "fail open", so the script is dependency-free
 * (no jq) and defensive. jq is NOT installed on this machine; do not reintroduce it.
 *
 * Emergency bypass for the human: remove/disable this hook in
 * ~/.claude/settings.json, or run the command yourself.
 */
'use strict';

let data = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => (data += c));
process.stdin.on('end', () => {
  let cmd = '';
  try {
    cmd = ((JSON.parse(data) || {}).tool_input || {}).command || '';
  } catch (_) {
    cmd = '';
  }
  if (!cmd || typeof cmd !== 'string') process.exit(0);

  // Collapse whitespace for matching; keep the original for the message.
  const c = ' ' + cmd.replace(/\s+/g, ' ').trim() + ' ';

  // Normalised copy with git's GLOBAL OPTIONS stripped, so the rules below also
  // catch the `-C <path>` form. Without this, `git -C <repo> reset --hard` slipped
  // past every check (found 2026-08-10 by the hook's own test suite — it was a
  // bypass for ALL repos, not just the memory store).
  const cn = c.replace(
    /\bgit\s+((?:-C\s+(?:"[^"]*"|'[^']*'|\S+)|--git-dir=\S+|--work-tree=\S+|--exec-path=\S+|-c\s+\S+|--no-pager|--paginate|-P)\s+)+/g,
    'git '
  );

  const block = (why) => {
    process.stderr.write(
      'BLOCKED by git guardrail: ' + why + '\n' +
      'Command: ' + cmd + '\n' +
      'You do not have authority to run this. Use a non-destructive alternative ' +
      '(e.g. `git branch -d` for a merged branch, open a PR instead of pushing to ' +
      'main), or ask the user to run it themselves.\n'
    );
    process.exit(2);
  };

  // --- Always-block: local history / working-tree destroyers ----------------
  // (matched against `cn` so the `git -C <path> …` form is covered too)
  if (/ git reset --hard\b/.test(cn)) block('git reset --hard can irreversibly discard work.');
  if (/ git clean -[a-z]*f/.test(cn)) block('git clean -f permanently deletes untracked files.');
  if (/ git branch -D\b/.test(cn)) block('git branch -D force-deletes a branch (possibly unmerged); use -d for merged branches.');
  if (/ git checkout (-- )?\.( |$)/.test(cn)) block('git checkout . discards ALL working-tree changes.');
  if (/ git restore ((--staged|--worktree|--source[= ]\S+) )*\.( |$)/.test(cn)) block('git restore . discards ALL working-tree changes.');

  // --- git push: block force + main/master; allow feature-branch pushes -----
  // Each `git push` is judged on ITS OWN shell segment, not the whole command line.
  // That kills two bug classes at once (both found 2026-08-10):
  //   • false positives — `git worktree remove --force … && git push origin feat/x`
  //     read as a force-push, and `git push origin feat/x && gh pr create --base main`
  //     read as a push to main, because the old checks scanned the entire command.
  //   • a BYPASS — the old `afterPush` used a GREEDY `/^.* git push\b/`, so in
  //     `git push origin main && git push origin feat/x` only the LAST push was
  //     examined and the push to main sailed through.
  const segments = cn.split(/&&|\|\||[;&|()]/);

  // Memory-store exemption inputs, computed once over the WHOLE command.
  // NB: matched against the ORIGINAL `c` — `cn` has stripped the `-C <path>`
  // that identifies the store. Requires a single push so a second repo's push
  // cannot ride along under the exemption.
  // The store's directory is named after the PROJECT, so it changes with the machine —
  // the slug is derived from the working directory, so it differs on Windows vs macOS
  // and changes on any migration. Match the stable shape — `.claude/projects/<slug>/memory` —
  // rather than one machine's slug, or the exemption silently stops firing after a move
  // and every autonomous memory push is blocked. The legacy literal is kept so the rule
  // still holds for any command written against the old path.
  const MEM = String.raw`(?:C--Temp-cjp|\.claude[\\/]projects[\\/][^\\/"';&|]+)[\\/]memory`;
  const scopedToMemory =
    new RegExp(`(^|[;&|(])\\s*cd\\s+["']?[^"';&|]*${MEM}`).test(c) ||
    new RegExp(`git\\s+-C\\s+["']?[^"';&|]*${MEM}`).test(c);
  // Counted against `cn`, NOT `c`: the real command is `git -C <path> push origin main`,
  // which does not contain the literal "git push" — against `c` this counted 0, the
  // exemption (which requires exactly 1) never fired, and every memory push was blocked.
  // `cn` has git's global options stripped, so every push form normalises to `git push`.
  // The suite missed this for months because its -C cases were built as
  // `git -C <path> git push …` (two gits), which DOES contain the literal — they passed
  // for the wrong reason and never exercised the real shape. Fixed 2026-08-12.
  const pushCount = (cn.match(/git push\b/g) || []).length;
  const memoryExempt = scopedToMemory && pushCount === 1;

  for (const seg of segments) {
    if (!/(^|\s)git push\b/.test(seg)) continue;
    // Args of THIS push only (non-greedy: the first push in this segment).
    const args = ' ' + seg.replace(/^.*?\bgit push\b/, '').trim() + ' ';

    const isForce =
      /(^| )--force(-with-lease)?( |=|$)/.test(args) ||
      /(^| )-[a-zA-Z]*f( |$)/.test(args) ||        // -f, -vf, etc.
      / \+[A-Za-z0-9_./-]+( |$)/.test(args);       // +refspec force form
    if (isForce) block('force-push can clobber a concurrent session\'s work on the shared checkout.');

    // explicit target main/master: "origin main", "HEAD:main", "main:main", "main "
    if (/(^| |[:/])(main|master)( |:|$)/.test(args) && !memoryExempt) {
      block('pushing to main/master directly is not allowed — open a PR (main is protected by the required-check ruleset).');
    }
  }

  process.exit(0);
});
