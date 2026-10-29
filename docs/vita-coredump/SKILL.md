---
name: vita-coredump
description: "Catch and analyze PS Vita psp2core-*.psp2dmp application crash dumps: keep serve running with a coredump event monitor, then read the crashing thread, registers, backtrace, modules. Use before launching or testing an app that may crash, and for CPU-side app crashes; use vita-gpucrash for GPUCRASH dumps."
---

# vita-coredump

Use [psp2_core_parse](https://github.com/shoui520/psp2_core_parse). Its README and docs explain usage.

**Local path:** `UNSET`

If the local path is `UNSET` or missing, clone it with `git clone https://github.com/shoui520/psp2_core_parse agent/tools/psp2_core_parse` (from the repo root; `agent/` is git-ignored), then replace `UNSET` above with the repo-relative path. Never write an absolute or personal path here.

## Watch for crashes

Before launching or testing an app that may crash, and for the rest of the session:

1. **Keep `serve` running** in a long-lived background process, not inside a tool call that ends. It receives the dump events the Vita pushes; without it, nothing sees a crash as it happens. Check that `server status` shows `connected`. Never stop it while a dump is saving.
2. **Arm a coredump monitor** that follows `server events` and prints only crash-relevant records. In Claude Code, use the Monitor tool with the maximum timeout and re-arm it each time it expires. In other harnesses, use their background watcher. Run it from the repo root. It keeps its cursor in `agent/coredump-monitor.cursor`, so re-arming resumes where the last one stopped. Use a separate cursor file for each Vita.

```sh
python3 -u - agent/coredump-monitor.cursor <<'PY'
import json, pathlib, subprocess, sys
state = pathlib.Path(sys.argv[1])
def events(*extra):
    p = subprocess.run(['./vita-agent', 'server', 'events', '--limit', '1024', *extra], capture_output=True, text=True)
    try: r = json.loads(p.stdout.splitlines()[-1])
    except (IndexError, ValueError): r = {}
    if r.get('status') != 'ok':
        print('MONITOR STOPPED: server events failed; is serve running?', (p.stdout or p.stderr).strip()[-400:]); sys.exit(1)
    return r['result']
cursor = int(state.read_text()) if state.exists() else events()['latest']
while True:
    r = events('--after', str(cursor), '--wait', '60')
    if r['lost']: print('GAP: %d events after %d left server memory; search %s' % (r['lost'], cursor, r['journal']))
    for e in r['events']:
        t = e.get('type', '')
        if t.startswith(('coredump.', 'connection.')) or (t == 'events.overflow' and e.get('source') in (None, 'coredump.batch')):
            print(json.dumps(e, separators=(',', ':')))
    cursor = r['next']; state.parent.mkdir(parents=True, exist_ok=True); state.write_text(str(cursor))
PY
```

| Line | Action |
|---|---|
| `coredump.saving` | The app crashed and the `.psp2dmp.tmp` is still being written. Tell the user. Stop sending input, and do not close the app, reboot or turn the screen off. |
| `coredump.complete` | The final `.psp2dmp` path, which is the saving path without `.tmp`. Download and analyze it now. |
| `coredump.reconciled` | The complete event was lost, so the server settled the dump from its files. With `state: complete`, download and analyze `path`; it may be truncated if the Vita hung or lost power. `missing` means no dump file survived; `abandoned` means `run cancel --yes` released it. |
| `connection.lost` / `connection.ready` | Dumps can be missed while disconnected. Treat the gap as unobserved. |
| `events.overflow`, `GAP` | Dump observations were lost. Report the gap, and never fill it in. |
| `MONITOR STOPPED` | `serve` is gone or unreachable, so crash detection is off. Restart `serve`, then re-arm the monitor. |

The native listener reports only **new** dumps, and a fresh monitor starts at the latest event. Never claim "no crashes" for a period when `serve` or the monitor was not running. A `run` also reports a crash, as `failed: coredump`, but the monitor still applies.

## Analyze

Only analyze a dump after `coredump.complete`; get it with `fs download`. For symbols, pass the matching decrypted ELF under its real runtime module name.
