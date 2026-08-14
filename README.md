# Claude Code git guardrail

A `PreToolUse` hook for [Claude Code](https://claude.com/claude-code) that blocks destructive
git commands **before they execute** — for the agent only, never for you.

It exists because "please don't force-push" in an instructions file is a request, not a
control. A hook is a control: the command never runs.

```
BLOCKED by git guardrail: force-push can clobber a concurrent session's work on the shared checkout.
Command: git push --force origin main
You do not have authority to run this. Use a non-destructive alternative
(e.g. `git branch -d` for a merged branch, open a PR instead of pushing to main),
or ask the user to run it themselves.
```

## What it blocks

| Blocked | Why |
| --- | --- |
| `git push --force` / `-f` / `+refspec` | clobbers concurrent sessions on a shared checkout |
| `git push origin main` / `master` | main is PR-only |
| `git reset --hard` | irreversibly discards work |
| `git clean -f` | permanently deletes untracked files |
| `git branch -D` | force-deletes a possibly-unmerged branch (`-d` is allowed) |
| `git checkout .` / `git restore .` | discards **all** working-tree changes |

Ordinary feature-branch pushes stay allowed, so the PR workflow remains autonomous.

## The interesting part: the guardrail has its own test suite

41 cases, dependency-free, `node block-dangerous-git.test.js`.

That suite is not ceremony. **It found two real bypasses in the hook it was written to
verify** — both of which had been live and silently ineffective:

1. **`git -C <path>` slipped every rule.** The checks matched `git reset --hard`, but the
   `-C <path>` form puts a global option between `git` and the subcommand, so
   `git -C /repo reset --hard` matched nothing. This was a bypass for *every* repo, not just
   the exempt one. Fixed by matching against a normalised copy with git's global options
   stripped.

2. **A greedy regex checked only the last push.** `afterPush` used `/^.* git push\b/`, so in
   `git push origin main && git push origin feat/x` only the *second* push was examined and
   the push to main sailed through. Fixed by judging each `git push` on its own shell segment
   — which also cleared two false positives, where
   `git worktree remove --force … && git push origin feat/x` read as a force-push.

A third defect surfaced later: several `-C` test cases were built as `git -C <path> git push …`
— two `git`s — which *does* contain the literal `git push`. They passed for the wrong reason and
never exercised the real command shape. **Tests that pass for the wrong reason are worse than
missing tests**, because they retire the suspicion that would otherwise find the bug.

## Verify it yourself

```bash
node block-dangerous-git.test.js          # expect: ALL PASS (41 cases)
```

Then prove the suite can actually fail — a gate you have never seen go red is not evidence:

```bash
sed -i '' 's/if (isForce) block(/if (false) block(/' block-dangerous-git.js
node block-dangerous-git.test.js          # expect: 8 FAILURE(S) of 41
git checkout block-dangerous-git.js       # restore
```

## The narrow exemption

One directory is exempt from the push-to-main rule: the agent's own memory store
(`~/.claude/projects/<slug>/memory`), a private single-writer repo where push-to-main is the
intended workflow. Three properties keep it narrow:

- It keys off the path **shape**, not a hard-coded slug — the slug is derived from the working
  directory, so it changes between machines. An earlier version pinned one machine's slug and
  silently stopped exempting anything after a migration.
- The command must **explicitly scope itself** via `git -C <path>` or `cd <path> && …`. The hook
  cannot see the shell's cwd, so a bare unscoped `git push origin main` stays blocked. That is
  deliberate fail-safe design: ambiguity resolves to *blocked*.
- It refuses to fire on a command containing **more than one** `git push`, so a second repo's
  push cannot ride along under the exemption.

Force-push, `reset --hard`, and `clean -f` remain blocked there too — a shared knowledge base is
exactly what you must not clobber.

## Install

Copy `block-dangerous-git.js` somewhere (e.g. `~/.claude/hooks/`) and register it in
`~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "node \"$HOME/.claude/hooks/block-dangerous-git.js\"" }
        ]
      }
    ]
  }
}
```

**Read the exemption block and either remove it or point it at your own path before installing.**
It is scoped to one specific directory shape and is not a general-purpose allowance.

Contract: reads the tool call as JSON on stdin, command at `.tool_input.command`. Exit `2` blocks
the call and feeds stderr back to the model; anything else allows. A parse failure exits `0` —
it **fails open**, so the script is dependency-free and defensive rather than clever. Adjust that
tradeoff if your threat model differs.

## Also here

`session-consolidation.js` — a `SessionEnd`/`SessionStart` pair that drops a marker when a session
ends and surfaces a reminder on the next start, so a session is never archived without capturing
what was learned. Always exits `0`; a hook must never break the session.

## Notes

Written with [Claude Code](https://claude.com/claude-code), which is also what it constrains.
Both hooks are dependency-free Node, no `jq`, no packages.

## License

[MIT](LICENSE) — use it, fork it, adapt the exemption to your own paths.
