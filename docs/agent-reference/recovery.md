# Failure recovery

Keep the complete JSON error and the related operation and run IDs. State whether the request was sent, accepted, started its effect, and completed or passed readback.

## What the client recovers by itself

Every command, direct or under `serve`, keeps trying for up to 90 s from its first failure before it reports one. Within that window it:

- reconnects after a reset, a timeout or a Vita that went away (TCP keepalive notices a vanished peer in about 40 s);
- waits out HTTP 503 (`"retry":true`, the command service is momentarily busy) and a command port that is still starting after a new token;
- renews the session from the saved pairing when the Vita answers 401 or refuses the command port (expiry, reboot, plugin restart); this needs `device_dir` in the config;
- resends a request that provably never ran (not sent, refused, 401, 503, or a parse rejection with `"id":null`);
- replays a request whose reply was lost under its original ID. The Vita answers from its one-reply replay cache and does not run it again.

When an earlier command's reply was lost and is recovered before the next one runs, the next result carries a `command.recovered` notice with that `reply`. Read it: it is the real outcome of the earlier command.

A lost reply cannot be replayed once the session that ran it ends. The client then:

- writes the request to `pc/unresolved.jsonl` (next to `state.json`) with its `id`, `op`, `args`, `reason` and an `instruction`;
- never resends it by itself;
- returns `unconfirmed` with an `unresolved` record if it was the current command, or attaches a `command.unresolved` notice to the next result;
- lists recent records in `server status` (`unresolved`) and in `session recover` (`unresolved_recent`);
- carries on with new commands.

The `instruction` depends on the operation. Filesystem writes, `app install`, `decrypt start`, `acl request` and content-delete requests are deduplicated on the Vita by their operation/request ID, so repeating the identical command with the same ID returns the recorded outcome instead of acting twice. Session-bound requests (watches, input leases, performance recording, runs) ended with their session; issue them again if they are still needed. For anything else (input, app launch/close, screen and similar control), check the resulting state before repeating it. Reads are never recorded; they are simply sent again.

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
| Missing config, or wrong Vita or name | Check `VITA_AGENT_CONFIG_DIR` and its `config.json`. It must name the directory containing the intended config and `pc/`; when unset, only this checkout's `agent/vita-agent-use/` is tried. Export it in the agent/server process environment. Old pointer files are unsupported; select the directory containing the actual config. Never copy the client once per Vita. |
| Private JSON rejected | Loose permissions are tightened automatically. A rejection means the file is a symlink, not a regular file, owned by another user, too large, or not valid JSON of the expected shape (duplicate keys included). Fix the file; never loosen the checks. |
| `bootstrap` fails for the agent | It needs a human at a terminal. |
| Server socket missing | Commands run directly. Start `serve` with the same config when you need pushed events or runs. |
| Stale server socket after a crash | Commands notice that no `serve` holds the lock and run directly. Restart `serve` with the same config; it replaces the socket. Never start duplicates or delete live state. |
| `connected:false` in `server status` | The server keeps reconnecting by itself with a backoff of at most 15 s; read `connection_error`. A command sent now also tries for up to 90 s. If it persists, check the Vita is awake and on Wi-Fi, `vita_ip`, and that `VITA_AGENT_CONFIG_DIR` and `device_dir` select the intended, paired PC identity (certificates under `pc/` do not prove pairing). Run one diagnostics query. Do not regenerate identities or delete recovery state. |
| Command fails after "Kept retrying for N s." | The Vita stayed unreachable or kept refusing for the whole window. The message says what failed last, including any renewal error. Fix that cause (network, IP, plugin not running, identity not paired), then rerun the same command; a request that might have run is replayed under its original ID first. |
| 8847 refused but 8848 active | This can occur on older builds. The multi-identity build keeps admission listening. Finish work and stop the current `serve` before switching identities; keep credentials and recovery state. |
| Command port refused | Handled automatically: right after a new token, or within 10 s of a dropped connection (the plugin reopening its listener after a network reset), the client waits for the listener; otherwise the session is gone (reboot, expiry, plugin restart) and it is renewed from the saved pairing. |
| Wi-Fi disabled/re-enabled or the Vita slept | Nothing to do if it returns within 90 s: the command in flight reconnects and replays, `serve` reconnects and resumes its watches. With a plugin that keeps session state, the session survives a Wi-Fi reconnect (the plugin reopens its listeners after `SCE_NET_ERROR_EIPADDRCHANGED`), and watches, performance recording and runs survive a gap of up to 5 minutes; a longer gap re-arms watches (`log.resumed`). Its `runtime.log` shows `command network reset` and `commands listening again`. Keep the same identity and recovery state; rebooting or pairing again is not the normal recovery path. |
| Timeout, reset or truncated response | Handled automatically by exact-ID replay. If the result is `unconfirmed` with `unresolved`, follow its `instruction`. |
| TLS unknown CA during pairing/session connect | This PC certificate was rejected. Older Shell builds accept only one peer; update to the multi-identity build and use `session pair` for each new identity. Do not delete existing trust. A rejected handshake cannot expose the trusted peer name/fingerprint. |
| TLS pin mismatch | Stop. Check whether the IP or device is wrong, or the identity was deliberately reset. Never disable pinning or send tokens to the unexpected device. Re-pair only as a deliberate reset with human approval. |
| HTTP 401 or expired grant | Renewed automatically from the saved pairing. Without `device_dir`, run `session connect`. If the human stopped access, respect that. |
| HTTP 503 | The command service was momentarily busy and nothing ran; the client waits and resends. |
| `command.recovered` notice | An earlier command's lost reply arrived late. Use its `reply` as that command's outcome. |
| `unconfirmed` with `unresolved`, or a `command.unresolved` notice | The session ended before the reply could be replayed. Follow the record's `instruction`; check the resulting state before repeating anything that is not deduplicated. Never delete `state.json` or `unresolved.jsonl`, edit counters or mint a new ID for a deduplicated operation. |
| `session recover` | Rarely needed: commands settle a pending request first. It replays one now, or returns the last reply, or reports that nothing is pending together with recent unresolved records. |
| PS+SELECT / "Agent stopped." | Stop. Keep pending effects and wait for the user. An old lease never resumes by itself. |
| Screen off | Normal access wakes it. Check the evidence before blaming the display. |
| `frame_unavailable` | Captures retry for 3 s by themselves. If it persists, report it; wait about 2 s after a launch or wake and capture again. Never fake a frame. |
| Output path already exists | Captures and downloads replace an existing file atomically and report `replaced:true`. Directories and symlinks are refused; choose another path. |
| "File kept changing during download", or a file read that "changed while it was being read" (native `-5`) or "shrank or was replaced" | Something on the Vita is writing the file; the plugin refuses a chunk whose size or modification time changed while it read it. For a log a running app appends to, use `fs download --live`. For any other file, wait for the writer to finish or close the app, then download again. |
| Launch accepted but wrong or no title in foreground | Unconfirmed. Check `app running`, the snapshot, dialog events and a capture, and handle any dialog with the user. Never bypass the confirmation. |
| VPK still installing | Query the same ID. Never start overlapping installs or free resources the installer is using. |
| ACL pending or denied | Wait for the physical decision and query the same ID. Only `approved` grants access. |
| Write denied despite ACL | Check the immutable and core-plugin rules, the private storage and tai-root rules, which tai directory is active, narrower denies, and `--yes`. |
| Original-hash mismatch | The target changed. Keep the old plan and make a fresh one; never force it. |
| ux0 free space keeps shrinking after uploads | Overwrite copies (`.old`) and abandoned stages (`.part`) collect in `<mount>:data/vita-agent-use/transactions/`; see [upload storage](commands.md#fs). No command can list or delete them, so tell the user. A human can delete them with VitaShell or FTP. The exception is files whose name contains the operation ID of an upload that is not finished: one whose transfer-state file's `phase` is not `done`, or that has an `unresolved` record. Recovery still needs those. Never ask for the whole folder to be deleted. |
| "Run … finished, but its crash dump … is still saving", or commands conflict with a run that already finished | The run's `coredump.complete` event was lost. The server settles the dump from its files after it reconnects (`coredump.reconciled`). Run `run cancel`, which checks the files right away. If it reports that the `.tmp` still exists and the Vita rebooted or lost power after the crash, use `run cancel --yes`. Never edit `run.json`. |
| Interrupted upload | A connection lost mid-upload is resumed from the Vita's confirmed offset within the same command. If the 90 s window runs out, read the error’s `result` for phase/action, last confirmed `received` bytes, total bytes, operation ID and transfer-state path, then rerun exactly the same command with the same state file, source, config and flags. Never change the source mid-upload. |
| Transfer state from a finished upload | A state file whose upload completed is reused for a new, different upload automatically. Only an unfinished one must match the source, device and options. |
| Upload succeeds with `verified:false` | With `--skip-hash`, `code:0`, `complete:true`, `hash_verified:false` and `verification:"size_only"` mean a completed upload checked by size, without content hashing. Do not describe it as hash-verified. Download and compare on the PC if content verification is needed. |
| Skip-hash transfer state rejected | Keep the saved state and operation ID. Check that the source was not modified or replaced and that the same `--skip-hash` mode and other flags are used. Hashed and size-only transfers cannot share an operation/state file. An older plugin needs updating before it can accept skip mode. |
| Config guard or prerequisite failure | Leave the config alone. Check the host guard, protected lines, which tai directory is active and the recovery VitaShell. |
| Config readback failed | Unacknowledged. Rerun `apply` with the same plan and state; never reboot until it is verified. |
| `effect_started` but uncertain | Inspect both paths and the audit. A deletion may have partly succeeded. Never replay with a new ID or assume a rollback happened. |
| Dump saving | Wait for completion; keep the server alive. Captures may fail during crash handling. |
| Run failed with `coredump` | Check the path, the terminal state and `cleanup_errors`. This can be a correct result. |
| Log literal never arrives | The watch started at the end of the file. Check the exact bytes, the path, whether the app launched and flushed its log, and reset, connection or overflow events. Never match an old line. |
| Metrics null, wrong process or dropped | Keep the error, foreground-process and window evidence; never invent values. |
| IPC timeout after 65 s of silence | The server sends a keepalive every 10 s while a command runs, so this means the server itself is stuck. The job may still be running. Check `server status` and events before resubmitting; restart `serve` if it does not answer. |
| IPC reply over 1 MiB | Use `--limit` and handle `has_more` (`livearea layout` needs `--section` first). Say the result is limited. |
| Event `lost` or overflow | Report the gap and check the journal. Events lost on the Vita cannot be recovered. |
| Audit sync fails | Keep the mirror and its cursor, and retry into the same mirror. Never reset native journals. |
| Service dead but Vita usable | One UDP diagnostics query, plus the runtime log if you can reach it. If nothing works, ask for a human-opened VitaShell FTP and do one transfer at a time. |
| Vita hangs, crashes or reboots | Stop traffic, keep the dump, event and runtime evidence, and report it. No remote dumper exists. |

## Adding and switching PC identities

The Vita retains every physically approved identity in `ur0:data/vita-agent-use/peers/`, keyed by the certificate's SHA-256 fingerprint. There is no fixed peer-count limit in RAM: lookup reads just that identity's file. The old `peer.der` is migrated automatically, preserving the existing pairing and ACL subject.

1. Finish the current controller's work, wait for dumps to finalize, and stop its `serve` process gracefully. One controller owns the command connection at a time; approving many identities does not allow competing input streams.
2. Select the new identity's config using `VITA_AGENT_CONFIG_DIR`, then run `session pair`. Bootstrap/provision creates its private PC files if needed.
3. Compare the fingerprint and tap OK once. Cancel, timeout or a failed write never replaces or deletes another identity's trust.
4. Start `serve`. For later visits, select this config and start `serve` or run commands directly; they connect from the saved pairing. Repeating `session pair` for an approved identity also reconnects without prompting again.

The admission port stays listening while commands are served. Requests wait for the active connection and native content/install work to finish; after stopping the old server, they proceed without rebooting or waiting an hour for expiry. A timeout can mean another server still owns the connection; it is not evidence that pairing files must be deleted. A request whose PC gave up while waiting (queued for more than 80 s) is dropped instead of ending the current session. An unknown identity using `session connect` receives `identity_not_paired` and instructions to pair once.

Each approval is saved through a synced temporary file and rename, then read back before the token reply. A partial `.tmp` is never trusted. Previously approved PCs retain their ACLs; new identities must separately request protected-path access. Keep each config's `pc/` files together; changing directories does not transfer an identity.

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
