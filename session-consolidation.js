#!/usr/bin/env node
/**
 * session-consolidation hook (CJP growth protocol).
 *
 * Drives the "never archive a session without capturing learnings" loop:
 *   - SessionEnd   → drop a `pending` marker recording that a session ended.
 *   - SessionStart → if a `pending` marker exists (last session wasn't wrapped up),
 *                    surface a reminder to run /wrap-session.
 *
 * The /wrap-session skill CLEARS the marker as its final step, so the reminder only
 * fires when a session genuinely ended without consolidation. Always exits 0 — a hook
 * must never break the session.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const MARKER = path.join(os.homedir(), '.claude', '.consolidation-pending');

function readStdin() {
    try { return fs.readFileSync(0, 'utf8'); } catch (_) { return ''; }
}

(function main() {
    let evt = {};
    try { evt = JSON.parse(readStdin() || '{}'); } catch (_) { evt = {}; }
    const event = evt.hook_event_name || process.argv[2] || '';

    try {
        if (event === 'SessionEnd') {
            fs.writeFileSync(MARKER, JSON.stringify({
                endedAt: new Date().toISOString(),
                cwd: evt.cwd || process.cwd(),
                reason: evt.reason || null,
            }));
        } else if (event === 'SessionStart') {
            if (fs.existsSync(MARKER)) {
                let info = {};
                try { info = JSON.parse(fs.readFileSync(MARKER, 'utf8')); } catch (_) { /* ignore */ }
                // stdout from a SessionStart hook is added to the session context.
                process.stdout.write(
                    `[growth-protocol] A previous session ended (${info.endedAt || 'unknown time'}) without a consolidation pass. ` +
                    `Before doing new work, consider running /wrap-session to capture learnings → CLAUDE.md/memory, ` +
                    `audit skills/MCPs/tools, and update project-status. (This reminder clears once /wrap-session runs.)\n`
                );
            }
        }
    } catch (_) { /* never fail the session */ }
    process.exit(0);
})();
