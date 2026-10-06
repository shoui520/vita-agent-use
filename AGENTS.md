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

Skills for external tools: [vita-gpuprof](docs/vita-gpuprof/SKILL.md) (GPU profiling), [vita-coredump](docs/vita-coredump/SKILL.md) (app crash dumps), [vita-gpucrash](docs/vita-gpucrash/SKILL.md) (GPUCRASH dumps), [vita-err](docs/vita-err/SKILL.md) (error codes).

## Rules

- **Uncertain is not failed.** A timeout, reset or disconnect may hide a completed effect. Keep credentials, `state.json`, transfer state, operation/request/run IDs and reviewed plans. Recover with the same ID through the operation's status command or `session recover`. Never mint a new ID to retry an uncertain effect, and never delete state to clear an error.
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

- `VITA_AGENT_CONFIG_DIR` is required for normal commands. Set it to the absolute directory chosen in `bootstrap`, containing `config.json` and `pc/`. The client always reads `$VITA_AGENT_CONFIG_DIR/config.json`, regardless of its working directory. There is no config-path CLI flag, working-directory fallback or pointer-file support. Help, bootstrap and diagnostics with an explicit `--host` work without the variable.
- Bootstrap prints `export VITA_AGENT_CONFIG_DIR=...` after setup. Export it in the shell or configure it in the agent's launch environment; a subprocess cannot change its parent shell. To persist it, add that export to your shell startup file or agent launcher. Existing bootstrap directories can be selected directly without regenerating their identity.
- The config keys are `device_dir` (bootstrap writes `"."`, placing the identity, credentials, state and server under this directory's `pc/`), `vita_ip`, `agent_name` (1–128 UTF-8 bytes; a display label, not an ACL identity), `screen_off_when_done` (default `true`), `macro_store` (default `pc/macros/`), and `credentials`/`state` as advanced explicit paths inside the config. Unknown keys are rejected. The CLI has no `--device-dir`, `--credentials` or `--state` overrides.
- Paths inside a config are relative to that config file, and `~` expands. CLI file arguments are relative to the directory the CLI is run from. `--macro-store` may override macro storage and goes before the command.
- For multiple Vitas, bootstrap each into its own directory and give each agent process its corresponding `VITA_AGENT_CONFIG_DIR`. Processes sharing a directory share the PC identity, state, server and ACL subject. Changing the directory does not transfer pairing. A running server keeps the name and IP it started with.

- Private JSON must be a regular, user-owned file with no group/world permissions (hand-written ones usually need `chmod 600`) and at most about 512 KiB. Never expose tokens, keys, fingerprints, console IDs or real network details in public files.

## Setup and the server

- `bootstrap` is a **human-only** curses TUI (minimum 50×18). It asks for a config directory (default `agent/vita-agent-use/`), IP and name. It reads `ur0:tai/config.txt` over VitaShell FTP on port 1337. VitaCompanion blocks setup; BGFTP, catlog, kvdb, psp2shell_ and vdbtcp produce warnings; NoLockScreen is recommended. It never writes to the Vita. It saves config and PC identity together and prints the environment export; it does not write a pointer file.
- The Vita creates its own identity in `ur0:data/vita-agent-use/` on first boot. Deleting that directory resets peer trust and ACLs; it is not routine troubleshooting.
- The Vita remembers **multiple approved PC identities** across reboots, one certificate file per identity under its private `peers/` directory. `session pair` asks for physical OK once for each new identity; it never replaces another approval. Repeating it for a known identity reconnects without another prompt. Existing `peer.der` trust is migrated automatically. ACLs stay scoped to each identity. See [adding identities](docs/agent-reference/recovery.md#adding-and-switching-pc-identities). There is no agent unpair command.
- First connection: `session pair`, where the human taps OK and the Vita certificate pin is saved, then `serve`. Later, `session connect` gets a fresh temporary token from the saved pairing. Pairing survives reboots; tokens last at most one hour, with a 30-minute idle limit. Ports: 8847 pairing/session, 8848 commands, 8846/UDP diagnostics. The admission listener stays open during command sessions; a new request waits for the current controller to disconnect. Only one controller owns the command connection at a time. Finish its work and stop its `serve` before switching identities; no reboot or token-expiry wait is required.
- `serve` runs on the PC and must outlive the agent's tool call: run it in a long-lived process or under a supervisor. It keeps one authenticated connection, receives events the Vita pushes (the PC does not poll), and exposes a Unix socket under `pc/server/`. CLI commands use the server automatically whenever that socket exists. There is no `server stop`: finish or cancel any run, wait for any dump, then stop the process gracefully.
- A socket existing does not mean the connection is healthy. Check `server status` before starting work. Its `session` reports expiry and idle time remaining; expired sessions report `connected:false`. With a configured `device_dir`, the server renews before the one-hour deadline or idle limit using the saved identity. Older credentials have unknown expiry and are renewed once. Renewal is deferred during active runs/dump finalization; runs do not gain an unlimited token lifetime. Failed snapshots and filesystem/app listings or stats may retry once after renewal; uncertain writes and control actions still require exact-ID recovery.
- Background event subscription, reconnect and saved-PC session renewal do not wake the display or announce agent use. Actual agent commands wake and announce; physical pairing still wakes its approval dialog.
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

Exit 0 is not enough on its own. Exit codes: 1 failure or unconfirmed, 2 bad arguments, 130 interrupted. Helper outputs (config diffs, audits, uploads, performance samples) may have no `status` field. Native microsecond values are **decimal strings** on the Vita clock; keep them as strings. Server `received_at` is UTC receive time, and different event channels can arrive out of native order. `--limit N` enables `--page P` (starting at 1); check `pagination.has_more` and `complete`. A complete listing is still not an atomic snapshot.

## Filesystem policy

The Vita enforces policy; no CLI flag can override an immutable rule.

- `os0: pd0: sa0: tm0: ud0: vd0: vs0:` are always read-only.
- Ordinary `ux0:`/`ur0:` paths are read/write, subject to narrower exclusions, ACL denies and preconditions.
- `ur0:tai/`, the active `ux0:tai/` or `uma0:tai/`, and `ur0:shell/` need a scoped ACL (`acl request <path>`, physically approved, persisted and tied to the PC certificate fingerprint) **and** `--yes`. Broad mount grants do not cover them. Inactive tai directories are blocked even for reads; do not create an alternate tai directory.
- The tai roots themselves, and the core plugins (`henkaku`, `yamt`, `yamt_helper`, `storagemgr` .suprx/.skprx), can never be modified, moved or deleted, and recursive operations check every file beneath. Internal identity, ACL, journal and trash storage is unreadable except `ur0:data/vita-agent-use/runtime.log`. No ACL revoke or edit command exists; never write the policy files.
- `tai/config.txt` changes only through `config plan`, then human review of the diff, then `config apply`. The file must be at most 16 KiB, match the original hash, and pass an exact readback. The tool also requires a validated recovery VitaShell (2.02, hash-checked) at `uma0:app/VITASHELL/`. If any prerequisite fails, report it; do not spoof or weaken the check. Never use `fs upload` for it, and never reboot before the readback is verified.

## Concurrency

- Input timing runs on the Vita; never drive button transitions with network timing or host sleeps.
- During an active run: `server status`, `server events`, `run status`, captures, metadata and read-only filesystem calls work. App, input, touch, macro, config, content (including its read-only queries), `call`, session, performance, filesystem-write and explicit screen commands are rejected.
- Blocking commands (`input submit`, `touch swipe`, `macro run`, foreground watchers and waits) hold the server's command lock. Other RPCs queue behind them; do not promise screenshots during a macro.
- Local IPC allows 65 s of silence and carries at most 1 MiB per message. Uploads stream progress, so their total duration can exceed 65 s. A server job can keep running after the CLI times out; check status before resubmitting. For long work, prefer `run start`, `server performance-start` and `app install --no-wait`.
- Low-level manual control with `call macro.acquire`, heartbeats and `macro.enqueue` is possible, but requires disciplined lease handling (see call-schemas.md).

## Workspace

Scratch artifacts, private configs, captures, identities, audit mirrors, dumps, plans and host tests belong in the locally ignored `agent/` folder; the shipping client stays in `client/`. Only `agent/` is excluded from Git. Root `AGENTS.md`, its relative `CLAUDE.md` symlink, and all of `docs/`, including the agent reference and Vita skills, are tracked.
