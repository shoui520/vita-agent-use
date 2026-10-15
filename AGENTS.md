# vita-agent-use: operating guide for AI agents

Operate the Vita through `./vita-agent`, the install-less launcher for `client/vita_agent.py`, or invoke that Python entry point directly. Do not use the legacy Python scripts, curl, ad hoc FTP or raw HTTP. The one exception is human `bootstrap`, whose built-in FTP client only reads the tai config. This guide covers what is implemented now, not planned features. Run `--help` at any level for exact syntax; it works without a config.

Read these when needed:

| File | Contents |
|---|---|
| [commands.md](docs/agent-reference/commands.md) | What every CLI command does, its limits and what to do when it fails |
| [formats.md](docs/agent-reference/formats.md) | Input, macro, swipe, run-spec and selection JSON; worked examples for uploads, installs, config edits, deletion and content |
| [events-runs.md](docs/agent-reference/events-runs.md) | `serve`, pushed events, runs, crash tests, performance metrics |
| [recovery.md](docs/agent-reference/recovery.md) | Error codes, recovery by symptom, safe diagnostics, plugin redeploy |
| [call-schemas.md](docs/agent-reference/call-schemas.md) | Low-level `call` operations and their arguments |
| [maintaining.md](docs/agent-reference/maintaining.md) | Source map and conventions for agents changing the code or this guide |

Skills for external tools: [vita-perf](docs/vita-perf/SKILL.md) (CPU profiling with libperf), [vita-gpuprof](docs/vita-gpuprof/SKILL.md) (GPU profiling), [vita-coredump](docs/vita-coredump/SKILL.md) (app crash dumps), [vita-gpucrash](docs/vita-gpucrash/SKILL.md) (GPUCRASH dumps), [vita-err](docs/vita-err/SKILL.md) (error codes).

## Rules

- **Uncertain is not failed.** A timeout, reset or disconnect may hide a completed effect. The client handles this itself: it reconnects, renews the session when the Vita no longer holds it, and replays a request whose reply was lost under its original ID, which the Vita answers from its replay cache without running it again. Keep credentials, `state.json`, transfer state, operation/request/run IDs and reviewed plans. Never mint a new ID to retry an uncertain effect, and never delete state to clear an error.
- **Unresolved means check, then decide.** When a reply is lost and the session it ran under also ends, the outcome cannot be recovered. The command is recorded in `pc/unresolved.jsonl` and never resent; the result is `unconfirmed` with an `unresolved` record, and later results and `server status` show it too. Check the resulting state the record's `instruction` names before repeating it. Writes, installs, decrypts, ACL and content-delete requests are deduplicated by their operation/request ID, so repeating the identical command with the same ID is safe.
- **Accepted is not done.** Only claim success once the result shows completion: confirmed, complete, persisted or verified readback. Report the full JSON error, and state what is known: sent, accepted, effect started, completed.
- **One at a time.** Run filesystem mutations and transfers sequentially, waiting for each result and readback before the next transfer or reboot. Never run two clients against the same state file, or two servers against the same directory.
- **Humans approve.** Agent input cannot approve pairing, ACL or Content Manager dialogs. Tell the human which prompt to approve and wait for their physical OK. Send no button or touch input while approval is pending.
- **PS+SELECT means stop.** The plugin revokes control and shows **"Agent stopped."** Do not reconnect or resume input until the user authorizes it.
- **Ordinary input has no title binding; saved macros do.** Never add a title ID to `input acquire` or readable input events.
- **Crash dumps:** after `coredump.saving`, wait for the matching `coredump.complete`. A `.psp2dmp.tmp` file is still being written; closing the app, rebooting or turning the screen off can interrupt it.
- **Destruction needs consent.** Never run destructive tests against protected paths. This workspace requires explicit user approval before any on-device Content Manager deletion test. `--yes` records intent; it does not replace approval.
- **Show full listings.** The CLI returns every entry by default; never abbreviate silently. Use `--limit` only when the user asks or the 1 MiB IPC reply limit forces it, and then say so.
- **Prefer native operations.** Generic file access does not update the native content registry. Do not edit databases or delete managed content by hand. Do not fabricate commands, CLI flags or `call` names: confirm in the CLI's command handling, the native capability or error response, and the observed result.

## Invocation and config

```sh
export VITA_AGENT_CONFIG_DIR="/absolute/path/chosen-in-bootstrap"
./vita-agent <command> ...
# Equivalent direct invocation:
python3 /path/to/vita-agent-use/client/vita_agent.py <command> ...
```

The launcher requires Python 3 on PATH, forwards every argument and exit code, and preserves the caller's working directory. It can also be invoked by its absolute path from another project directory.

- `VITA_AGENT_CONFIG_DIR` selects the directory chosen in `bootstrap`, containing `config.json` and `pc/`. The client always reads `$VITA_AGENT_CONFIG_DIR/config.json`, regardless of its working directory; a relative value is resolved against the current directory. If the variable is unset, the client uses this checkout's `agent/vita-agent-use/` when it contains a `config.json`, and says so on stderr; with several Vitas, always set the variable. There is no config-path CLI flag or pointer-file support. Help, bootstrap and diagnostics with an explicit `--host` work without a config.
- Bootstrap prints `export VITA_AGENT_CONFIG_DIR=...` after setup. Export it in the shell or configure it in the agent's launch environment; a subprocess cannot change its parent shell. To persist it, add that export to your shell startup file or agent launcher. Existing bootstrap directories can be selected directly without regenerating their identity.
- The config keys are `device_dir` (bootstrap writes `"."`, placing the identity, credentials, state and server under this directory's `pc/`), `vita_ip`, `agent_name` (1–128 UTF-8 bytes; a display label, not an ACL identity), `screen_off_when_done` (default `true`), `macro_store` (default `pc/macros/`), and `credentials`/`state` as advanced explicit paths inside the config. Unknown keys are ignored with a stderr warning. Automatic session renewal needs `device_dir`. The CLI has no `--device-dir`, `--credentials` or `--state` overrides.
- Paths inside a config are relative to that config file, and `~` expands. CLI file arguments are relative to the directory the CLI is run from. `--macro-store` may override macro storage and goes before the command.
- For multiple Vitas, bootstrap each into its own directory and give each agent process its corresponding `VITA_AGENT_CONFIG_DIR`. Processes sharing a directory share the PC identity, state, server and ACL subject. Changing the directory does not transfer pairing. A running server keeps the name and IP it started with.

- Private JSON, TLS identity files and lock files must be regular, user-owned files (never symlinks), and JSON at most about 512 KiB. A group- or world-readable one is tightened to owner-only automatically, with a note on stderr. Never expose tokens, keys, fingerprints, console IDs or real network details in public files.

## Setup and the server

- `bootstrap` is a **human-only** curses TUI (minimum 50×18). It asks for a config directory (default `agent/vita-agent-use/`), IP and name. It reads `ur0:tai/config.txt` over VitaShell FTP on port 1337. VitaCompanion blocks setup; BGFTP, catlog, kvdb, psp2shell_ and vdbtcp produce warnings; NoLockScreen is recommended. It never writes to the Vita. It saves config and PC identity together and prints the environment export; it does not write a pointer file.
- The Vita creates its own identity in `ur0:data/vita-agent-use/` on first boot. Deleting that directory resets peer trust and ACLs; it is not routine troubleshooting.
- The Vita remembers **multiple approved PC identities** across reboots, one certificate file per identity under its private `peers/` directory. `session pair` asks for physical OK once for each new identity; it never replaces another approval. Repeating it for a known identity reconnects without another prompt. Existing `peer.der` trust is migrated automatically. ACLs stay scoped to each identity. See [adding identities](docs/agent-reference/recovery.md#adding-and-switching-pc-identities). There is no agent unpair command.
- First connection: `session pair`, where the human taps OK and the Vita certificate pin is saved, then `serve`. Later, `session connect` reuses the saved session when it still works, otherwise gets a fresh token from the saved pairing; under `serve` it goes through the server. Commands renew an expired or revoked session by themselves, so `session connect` is rarely needed. Pairing survives reboots; a token lasts one hour unless extended, and a connection that sends nothing for 30 minutes is closed. Ports: 8847 pairing/session, 8848 commands, 8846/UDP diagnostics. The admission listener stays open during command sessions; a new request waits for the current controller to disconnect. Only one controller owns the command connection at a time. Finish its work and stop its `serve` before switching identities; no reboot or token-expiry wait is required.
- `serve` runs on the PC and must outlive the agent's tool call: run it in a long-lived process or under a supervisor. It keeps one authenticated connection, receives events the Vita pushes (the PC does not poll), and exposes a Unix socket under `pc/server/`. CLI commands use the server automatically while a `serve` process holds `pc/server/server.lock`; a stale socket left by a crash is ignored and commands run directly. Starting `serve` when one already runs for the directory reports `already_running` and exits 0. There is no `server stop`: finish or cancel any run, wait for any dump, then stop the process with Ctrl+C, SIGTERM or SIGHUP, which shut it down cleanly.
- Every command recovers by itself for up to 90 s from the first failure: it reconnects (TCP keepalive notices a vanished peer in about 40 s), waits out a 503 or a command port that is still starting, renews the session from the saved pairing on a 401 or refused command port, and replays a lost reply under its original ID. A request that certainly did not run is simply sent again. Only when this window ends does it report failure, saying what it tried.
- The server sends a background `session.ping` after 15 s without traffic, extends the token with `session.extend` ten minutes before expiry (same token, replay cache and watches), and reconnects on its own with a backoff of at most 15 s. Check `server status` before starting work: `connected`, `connection_error`, `session` (expiry, `extend_supported`), `features`, `reconnects` and any `unresolved` records. On a plugin that keeps session state across reconnects, a dropped connection, including a Wi-Fi reconnect, keeps the session's replay cache, log watches, performance pushes and the run for 5 minutes, and a run waits up to 90 s for the connection to return. After a new session or a longer gap, the server re-arms its log watches under the same `watch_id` (`log.resumed`; bytes written in the gap are not replayed) and restarts server-started performance recording. A new session ends an active run as `connection_lost`. Older plugins without `session.extend` are renewed while idle, two minutes before expiry.
- Background event subscription, heartbeats, session extension, reconnect and saved-PC session renewal do not wake the display or announce agent use. Actual agent commands wake and announce; physical pairing still wakes its approval dialog.
- Screen: commands turn the display on before access and, when `screen_off_when_done` is set, turn it off afterwards only if the native running-app inventory is empty. Running or suspended applications retain the display across commands until they are closed; an unknown inventory also prevents automatic screen-off. Installations, Content Manager work, queued input/live input leases, performance recording, pending log listeners and unfinished coredumps retain the screen. Busy cleanup is deferred without replacing the operation result. Screen-off is not suspend. Runs keep the screen on until they finish and close their app. Explicit `screen on/off` overrides this cleanup under `serve`, but native screen-off is refused while installation, Content Manager work, input, performance recording, approval or a run is active. Display-on does not mean a frame is ready to capture yet.

## Reading output

The CLI prints JSON, sometimes several newline-delimited objects; read them all until the process exits.

| Result | Meaning |
|---|---|
| `ok` | Returned successfully. Still inspect nested fields; work may still be pending. |
| `accepted` | The Vita accepted the request. Verify the resulting state where it matters. |
| `unconfirmed` | Not yet observed complete. Query status; do not claim success. |
| `error` | Native or protocol rejection: `error.source`/`error.code` (captures use top-level `code`/`stage`/`name`/`message`). |
| `client_error` | Local validation, transport, pin or recovery failure; read `message`. |
| nested `code != 0`, `state` failed/uncertain/denied/pending, `running: true`, `persisted: false` | Not proven complete. |

Results may also carry `notices` (`command.recovered`: an earlier command's lost reply, now recovered, with its `reply`; `command.unresolved`: a lost command whose session ended; `session.renewed`) and `cleanup_error` (automatic screen cleanup failed; the command's own result stands). Read them and report them. Exit 0 is not enough on its own. Exit codes: 1 failure or unconfirmed, 2 bad arguments, 130 interrupted. Helper outputs (config diffs, audits, uploads, performance samples) may have no `status` field. Native microsecond values are **decimal strings** on the Vita clock; keep them as strings. Server `received_at` is UTC receive time, and different event channels can arrive out of native order. `--limit N` enables `--page P` (starting at 1); check `pagination.has_more` and `complete`. A complete listing is still not an atomic snapshot.

## Filesystem policy

The Vita enforces policy; no CLI flag can override an immutable rule.

- `os0: pd0: sa0: tm0: ud0: vd0: vs0:` are always read-only.
- Ordinary `ux0:`/`ur0:` paths are read/write, subject to narrower exclusions, ACL denies and preconditions.
- Uploads hash content by default. `fs upload --skip-hash` skips PC/Vita hashing and checks sizes; successful results have `complete:true`, `verified:false`, `hash_verified:false` and `verification:"size_only"`. Keep the same mode, source and transfer state when resuming. This option does not bypass policy and is unavailable for guarded config or original-hash preconditions. See [upload examples](docs/agent-reference/formats.md#upload-replace-install).
- `ur0:tai/`, the active `ux0:tai/` or `uma0:tai/`, and `ur0:shell/` need a scoped ACL (`acl request <path>`, physically approved, persisted and tied to the PC certificate fingerprint) **and** `--yes`. Broad mount grants do not cover them. Inactive tai directories are blocked even for reads; do not create an alternate tai directory.
- The tai roots themselves, and the core plugins (`henkaku`, `yamt`, `yamt_helper`, `storagemgr` .suprx/.skprx), can never be modified, moved or deleted, and recursive operations check every file beneath. Internal identity, ACL, journal and trash storage is unreadable except `ur0:data/vita-agent-use/runtime.log`. No ACL revoke or edit command exists; never write the policy files.
- `tai/config.txt` changes only through `config plan`, then human review of the diff, then `config apply`. The file must be at most 16 KiB, match the original hash, and pass an exact readback. The tool also requires a validated recovery VitaShell (2.02, hash-checked) at `uma0:app/VITASHELL/`. If any prerequisite fails, report it; do not spoof or weaken the check. Never use `fs upload` for it, and never reboot before the readback is verified.

## Concurrency

- Input timing runs on the Vita; never drive button transitions with network timing or host sleeps.
- During an active run: `server status`, `server events`, `run status`, captures, metadata and read-only filesystem calls work. App, input, touch, macro, config, content (including its read-only queries), `call`, session, performance, filesystem-write and explicit screen commands are rejected.
- Blocking commands (`input submit`, `touch swipe`, `macro run`, foreground watchers and waits) hold the server's command lock. Other RPCs queue behind them; do not promise screenshots during a macro.
- Local IPC carries at most 1 MiB per message. While a command runs, including its automatic recovery, the server sends a keepalive line every 10 s, so only a stuck server reaches the 65 s silence limit. Output a command streams (performance samples, watch events) is forwarded to the CLI. If the CLI goes away, waits it started under `serve` (install, ACL, watch, macro, performance) stop. A server job can keep running after the CLI times out; check status before resubmitting. For long work, prefer `run start`, `server performance-start` and `app install --no-wait`.
- Low-level manual control with `call macro.acquire`, heartbeats and `macro.enqueue` is possible, but requires disciplined lease handling (see call-schemas.md).

## Workspace

Scratch artifacts, private configs, captures, identities, audit mirrors, dumps, plans and host tests belong in the locally ignored `agent/` folder; the shipping client stays in `client/`. Only `agent/` is excluded from Git. Root `AGENTS.md`, its relative `CLAUDE.md` symlink, and all of `docs/`, including the agent reference and Vita skills, are tracked.
