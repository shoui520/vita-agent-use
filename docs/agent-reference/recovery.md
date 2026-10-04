# Failure recovery

Keep the complete JSON error and the related operation and run IDs. State whether the request was sent, accepted, started its effect, and completed or passed readback.

## Native wrapper codes

| Code | Symbol | Recovery |
|---|---|---|
| 0 | `VAU_OK` | Still check terminal, persistence and readback fields. |
| -1 | `VAU_INVALID` | Fix the schema, types, path, arguments or limits. |
| -2 | `VAU_BUSY` | Find the owner (a run, input lease, dialog, installer or content task). Wait and check status; do not retry rapidly. |
| -3 | `VAU_EXPIRED` | The lease or grant expired. Stop the old workflow, inspect, then renew or reacquire. |
| -4 | `VAU_DENIED` | Policy, rights, stop, approval or intent. Flags cannot bypass immutable rules. |
| -5 | `VAU_STALE` | The cursor, process or operation no longer matches. Use that operation's recovery path. |
| -6 | `VAU_UNSUPPORTED` | Report the limitation. |
| -7 | `VAU_DEVICE_ERROR` | Keep the native result and diagnostics. |
| -8 | `VAU_LATE` | Timing was missed. Stop, observe, and build a fresh sequence. |
| -9 | `VAU_RECOVERY_REQUIRED` | The outcome is uncertain. Keep all state and reconcile. |

Large negative numbers are Sony codes, not these. Keep both the signed decimal and the hex. `0x80020005` can mean an invalid argument or flags. `C2-12570-5` can accompany an unsupported system-app launch. `0x80290008` (-2144796664) is `SCE_DISPLAY_ERROR_NO_PIXEL_DATA`, "Cannot screenshot with no framebuffer present." Look codes up with the vita-err skill (`docs/vita-err/SKILL.md`); leave codes it does not know unmapped.

## By symptom

| Symptom | Action |
|---|---|
| Missing config, or wrong Vita or name | Check the working directory, `--config`, the pointer target and file permissions. Global flags go before the command. Never copy the client once per Vita. |
| Private JSON rejected | It must be a regular, user-owned file (`chmod 600`); check its shape, size and duplicate keys. Never loosen the checks. |
| `bootstrap` fails for the agent | It needs a human at a terminal. |
| Server socket missing | Start `serve` with the same state directory. |
| Socket exists but connection refused | An unclean exit can leave a stale socket. Confirm no process owns the lock, then restart `serve` (it removes the stale socket). Never start duplicates or delete live state. |
| `connected:false` | Keep `connection_error`. Check the network and IP, run one diagnostics query, and inspect the grant and any pending command. |
| 8847 refused but 8848 active | An existing session owns the service; use its server instead of re-pairing. |
| Command port refused right after reconnect or reboot | The listener isn't ready yet. Let the existing readiness/reconnect logic handle it; do not hammer the port. |
| Timeout, reset or truncated response | The command may have run. Recover the exact pending request before doing anything else with effects; check the journal, diagnostics and current task. |
| TLS pin mismatch | Stop. Check whether the IP or device is wrong, or the identity was deliberately reset. Never disable pinning or send tokens to the unexpected device. Re-pair only as a deliberate reset with human approval. |
| HTTP 401 or expired grant | Normal expiry: `session connect` or a server reconnect. If the human stopped access, respect that. |
| "An uncertain command is pending" | `session recover`. Never delete `state.json`, edit counters or create a new ID. |
| Recovery fails after a new session or reboot | Replay is cached for only one response. Reconcile using the native app, install, ACL or content status, or the upload and audit records, before any new operation. |
| PS+SELECT / "Agent stopped." | Stop. Keep pending effects and wait for the user. An old lease never resumes by itself. |
| Screen off | Normal access wakes it. Check the evidence before blaming the display. |
| `frame_unavailable` | Report it. Wait about 2 s after a launch or wake, then capture to a new filename. Never fake a frame. |
| Output path already exists | Use a new path; the tool will not overwrite. Never delete unrelated files. |
| Launch accepted but wrong or no title in foreground | Unconfirmed. Check `app running`, the snapshot, dialog events and a capture, and handle any dialog with the user. Never bypass the confirmation. |
| VPK still installing | Query the same ID. Never start overlapping installs or free resources the installer is using. |
| ACL pending or denied | Wait for the physical decision and query the same ID. Only `approved` grants access. |
| Write denied despite ACL | Check the immutable and core-plugin rules, the private storage and tai-root rules, which tai directory is active, narrower denies, and `--yes`. |
| Original-hash mismatch | The target changed. Keep the old plan and make a fresh one; never force it. |
| Interrupted upload | Rerun exactly the same command with the same state file, source, config and flags. Never change the source mid-upload. |
| Config guard or prerequisite failure | Leave the config alone. Check the host guard, protected lines, which tai directory is active and the recovery VitaShell. |
| Config readback failed | Unacknowledged. Rerun `apply` with the same plan and state; never reboot until it is verified. |
| `effect_started` but uncertain | Inspect both paths and the audit. A deletion may have partly succeeded. Never replay with a new ID or assume a rollback happened. |
| Dump saving | Wait for completion; keep the server alive. Captures may fail during crash handling. |
| Run failed with `coredump` | Check the path, the terminal state and `cleanup_errors`. This can be a correct result. |
| Log literal never arrives | The watch started at the end of the file. Check the exact bytes, the path, whether the app launched and flushed its log, and reset, connection or overflow events. Never match an old line. |
| Metrics null, wrong process or dropped | Keep the error, foreground-process and window evidence; never invent values. |
| IPC timeout after 65 s | The job may still be running. Check events and status before resubmitting. Prefer the asynchronous interfaces. |
| IPC reply over 1 MiB | Use `--limit` and handle `has_more` (`livearea layout` needs `--section` first). Say the result is limited. |
| Event `lost` or overflow | Report the gap and check the journal. Events lost on the Vita cannot be recovered. |
| Audit sync fails | Keep the mirror and its cursor, and retry into the same mirror. Never reset native journals. |
| Service dead but Vita usable | One UDP diagnostics query, plus the runtime log if you can reach it. If nothing works, ask for a human-opened VitaShell FTP and do one transfer at a time. |
| Vita hangs, crashes or reboots | Stop traffic, keep the dump, event and runtime evidence, and report it. No remote dumper exists. |

## Safe diagnostics

Run only what you need, and never in a loop:

```sh
python3 client/vita_agent.py server status
python3 client/vita_agent.py diagnostics status        # add --host IP (after the subcommand) when there is no config
python3 client/vita_agent.py diagnostics input
python3 client/vita_agent.py diagnostics log
python3 client/vita_agent.py fs download ur0:data/vita-agent-use/runtime.log ./private-work/runtime-log.txt   # if commands work
```

Read `phase_name`, the result and error hex, logging errors and the input samples. Use timestamps to match log lines to the incident. Diagnostics show startup and input state only; they do not prove the whole Vita is healthy.

## Redeploying the plugin

There are three parts: `vita_agent_kernel.skprx` (kernel bridge), `vita_agent_loader.suprx` (Shell loader) and `vita_agent_shell.suprx` (runtime). A runtime-only change needs only that file; a change to the bridge's interface or to the loader needs matching files. Never edit the tai config just to redeploy. Back up first, upload one file at a time, verify each one completely, close the connection, and reboot only after everything is verified. Pairing survives as long as the Vita's private directory is kept.
