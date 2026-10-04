# Command reference

This covers every CLI command. For syntax, run `python3 client/vita_agent.py <group> <cmd> --help`. Global options go before the command. Generated IDs are 32 lowercase hex characters: keep the ones the CLI returns, never invent replacements. The general rules in AGENTS.md (keep IDs, accepted ≠ done, report full errors) apply to every command and are not repeated here.

## system / session

- **bootstrap**: human-only TUI; see AGENTS.md. If FTP fails, the human fixes the IP or VitaShell FTP and retries inside the TUI. Escape cancels.
- **system snapshot**: foreground app/PID, ConsoleID, model, actual and reported (spoofable) firmware, confirm button, language, battery, ux0 free space, Wi-Fi/BT/airplane mode/mic, MAC, IMEI applicability, overlay, Settings-style info, and enabled plugins grouped by tai section. Check each field's `error_code` and nulls. Having no foreground app is normal at LiveArea.
- **system reboot**: cold reset, sent after the accepted reply. It may be refused while installs or content operations are running. Finish all transfers and readbacks first. A disconnect is expected; let `serve` reconnect, or run `session connect`, after boot. Pairing and the tai config are untouched.
- **system capabilities**: native feature list. Use it to confirm the command path works and to check the installed build. A CLI command existing does not mean the firmware supports it.
- **session provision** `[--host] [--name]`: creates the PC certificate, key and `pc/pairing.json` without contacting the Vita, keeping any existing identity. If files are partly present, diagnose; never rotate identities to hide pending work.
- **session pair**: first physical pairing. It provisions if needed, prints the client fingerprint, waits up to 75 s for the human's OK, saves the pin and credentials, then waits up to 15 s for the command listener. If rejected or timed out, check diagnostics and whether another peer or session is active. A pin mismatch means the trusted device changed: never suppress it or silently reset.
- **session connect**: gets a fresh token from the saved pairing on 8847, sending the current name and IP. If a server is already connected, use the server instead; its session may have 8847 closed.
- **session recover**: replays the exact pending command ID and body; clears pending state only when a matching reply arrives. With nothing pending, it returns the last response. If the Vita's replay record is gone, check the operation's own status or audit; never retry with a new effect.

## app

- **app list** `[--query] [--limit --page]`: complete installed-title list from the Shell registry (not a scan of `ux0:app`). Never merge pages from failed attempts.
- **app running**: native app records, including suspended ones; Shell is not listed. An empty list after a crash does not mean the Shell context is gone.
- **app launch** `TITLE_ID` (9 uppercase characters): closes conflicting apps, waits 1 s for the transition, launches, and watches up to 20 s for the title to reach the foreground. Success needs `status: ok` **and** `result.confirmed: true`. If unconfirmed, check dialogs, snapshot and a capture. Some system apps show C2-12570-5; the user dismisses it, then verify before relaunching.
- **app close** `TITLE_ID`: `sceAppMgrDestroyAppByName`, which works even when a crashed process no longer appears in `app running`. Acceptance is not visual confirmation. Never use while a coredump is saving.
- **app install** `PATH --yes [--operation-id] [--no-wait] [--timeout]`: installs a `.vpk` (lowercase) that is already on the Vita: extracts, builds the package head, promotes. By default it waits up to 1800 s. Check `installed`, `state`, `code`, `running` and `title_id`. A timeout does not cancel promotion. Malformed archives or assets can fail promotion; in one test, `0x8010113D` was an icon fixed by repacking it as an indexed 8-bit PNG. Do not assume that cause, and do not retry in a loop.
- **app install-status** `OPERATION_ID`: keep polling while `running: true`. A terminal failure with `code != 0` is real: keep the stage and native error, and validate the package before a new install.

## screen

- **screen on**: display on. Acceptance does not mean a frame is ready.
- **screen off**: display off, clears cached listing resources, ends screen ownership; does not suspend. Never use while a dump is finalizing. Do not toggle power repeatedly to fix failures.
- **screen capture** `--output NEW.jpg`: a fresh, corrected JPEG at the real framebuffer size (up to 960×544). Returns width, height, process, timing and bytes. Not added to Photos. The parent directory must exist and the output must not exist or be a symlink. `frame_unavailable` / `SCE_DISPLAY_ERROR_NO_PIXEL_DATA` is a genuine failure: wait for rendering and capture to a new file. Never substitute an old image.

## fs

- **fs list** `PATH [--sort-by name|modified|date|size] [--order asc|desc|dsc] [--limit --page] [--human]`: the full directory with metadata. Sorting with a limit still scans everything. A stale iterator restarts up to twice; a failure is never a partial complete list. Leave missing size or date unknown. `--human` is tab-separated output for standalone runs only.
- **fs stat** `PATH`: metadata only, not recursive. Missing, denied and private are different results; never infer zero bytes or an empty directory from an error.
- **fs download** `PATH NEW_OUTPUT`: sequential read that checks size and modification time stay consistent, and deletes partial output on failure. The parent must exist. Not resumable; if the source changed, download again to a new file.
- **fs upload** `SRC DEST --transfer-state FILE [--overwrite --yes] [--expected-sha256 OLD_HASH] [--yes]`: staged, SHA-256-verified, audited commit. Risky paths need an ACL plus `--yes`, even for new files. On failure, rerun the **same** command with the same source and state file to resume. Never reuse a state file for different bytes, paths or devices. Do a full readback before any reboot. Use `config plan/apply` for `tai/config.txt`.
- **fs mkdir** `PATH [--yes] [--operation-id]`: creates one directory; the parent must exist; not `mkdir -p`. `--yes` is needed only for risky paths.
- **fs move** `SRC DEST [--yes] [--operation-id]`: same-mount rename. The destination must not exist; checks ACLs on files beneath and on both ends; never overwrites; no cross-mount moves. If you see `effect_started` or `recovery_required`, inspect both paths and the audit before any new mutation.
- **fs trash** `PATH [--yes] [--operation-id]`: moves the target into private trash on the same mount. Its operation ID becomes the trash ID. Frees no space. There is no restore command, and trash internals must never be accessed directly.
- **fs purge** `ORIGINAL_PATH --trash-id TRASH_ID [--yes] [--operation-id]`: **irreversible.** Permanently deletes a completed trash entry, using a separate operation ID. Confirm intent first. Ordinary paths do not always require `--yes`, so do not rely on the flag as the safeguard. Untrashed files cannot be purged. Keep audit evidence if it partially fails.

## plugins

- **plugins list** `[--limit --page]`: enabled tai entries with configured/loaded/module-state/process-count evidence; disabled entries are hidden. Enabled ≠ loaded: per-title plugins unload when their app is not running. A failed module query means unknown, not `loaded=false`.

## input / touch / macro

Input formats are in formats.md.

- **input acquire**: exclusive controller and touch lease for 5 s, with no title argument. For leases spanning several commands, use the server. `BUSY` means another job or an approval prompt owns input; do not compete with it.
- **input heartbeat**: renews the lease; status reads do not. After expiry, observe the system before reacquiring.
- **input status**: numeric state (0 idle, 1 queued, 2 running, 3 finished, 4 cancelled, 5 lease_expired, 6 failed), counters, timing, pad state, lease expiry. `applied_events` proves the Vita applied the input, not that the game acted on it; verify with a capture.
- **input cancel**: stops the scheduled sequence (different from PS+SELECT). Release the lease afterwards when controlling manually.
- **input release**: stops the sequence and returns control to the physical buttons. If release fails, start no further automation; report `release_error`.
- **input submit** `FILE`: a sequence argument object. It acquires the lease, replaces the timing field with a 150 ms delay, sends heartbeats, waits and releases. The file must have exactly one of `start_us`/`start_delay_us`. Use a file, not `-`, under the server.
- **touch panels**: front and back geometry (active/display min-max, force range, contact limit). Native units are not pixels; always use the returned geometry.
- **touch swipe** `--panel front|back --from X Y --to X Y --duration-ms 16..60000 [--coordinate-space screenshot|native] [--width W --height H]`: drag then release, sampled every 16 ms at force 128. Screenshot coordinates need the **current capture's** width and height. Back-panel mapping uses normalized geometry. Split overlong swipes. There is no tap command; use input JSON.
- **macro save** `FILE`: validates and stores a per-title macro privately on the PC (at most 16 MiB, 65,536 steps, a 7-day cycle).
- **macro load** `TITLE_ID NAME`: validates one stored macro. Never substitute another title's macro.
- **macro run** `TITLE_ID NAME [--repeats N]`: binds to the title's current foreground process, streams one-hour/1,024-state segments with two resident on the Vita, sends heartbeats and releases. A title or process change, lease expiry, missed continuation or release failure stops it; do not restart across a title change without observing the new state. Holds the server command lock until done.
- **macro compile** `TITLE_ID NAME --start-us US [--repeats N]`: offline only. Accepts macros that fit one segment (1,024 states, one hour). Not for live execution of long macros.

## performance

- **performance measure** `--window-ms 100..60000`: one CPU/FPS/memory sample measured on the Vita (not part of the snapshot). Check per-metric errors, `window_us` and `dropped_samples`.
- **performance watch** `--seconds 1..3600`: about 1 sample/s as JSON lines, polled. Under the server, long watches exceed the 65 s IPC wait, so use `server performance-start`. An interrupted watch tries `performance.cancel`.
- **performance cancel**: stops your own measurement. Blocked while a run owns metrics; cancel the run instead.

## livearea (read-only)

- **livearea layout** `[--section pages|icons|all] [--limit --page]`: the default `all` returns pages with nested icons, orphan icons and `ux0:iconlayout.ini`, and cannot be paginated. `pages`/`icons` can be. Reads `ur0:shell/db/app.db` read-only. Identify folders versus app bubbles by type, command and page IDs, never by labels. There is no command to move bubbles.
- **livearea schema** `[--limit --page]`: table and schema metadata; no SQL. A schema error is not an empty layout.
- **livearea blob** `SELECTION.json`: streams a `reserved01..05` blob to a new file with SHA-256, using descriptors taken from the layout output. Aborts and cleans up if the blob's identity or size changes mid-read.

## events / dialogs / watch (legacy polling)

Prefer `serve` plus `server events`.

- **watch dumps**, **watch dialogs**: the same foreground poller, which watches both the coredump and dialog rings every 0.5 s until Ctrl+C. The native crash listener stays active.
- **watch log** `PATH --marker LITERAL`: the poller plus a log tail from the end of the file (the file may not exist yet). Literal match, no regex. Does not exit on a match.
- **events start**: starts or queries coredump publication. The default listener is already on and hooks **new** dumps only; old dumps are not reported.
- **events stop**: stops only an explicit request; the default listener stays on.
- **events read** `[--after N]`: the raw native dump ring (not PC history). Advance with `next`, drain while `more`, report overflow. `coredump.saving` is no reason to close or reboot.
- **dialogs start / stop / read** `[--after N]`: native error-callback events (`code`, `raw_hex`, `observed_us`, `display_confirmed`). A callback does not prove a dialog was visible; capture to confirm. `stop` does not dismiss dialogs; do not use it to silence errors a run is expecting. Keep raw codes even when they are unmapped.

## acl

- **acl request** `PATH [--request-id ID] [--timeout 90]`: physical OK/Cancel prompt for write access to an existing path. Passing `--request-id` resumes polling that request rather than prompting again. A timeout can return `pending`. Only `approved` grants access. Never request immutable scopes.
- **acl status** `REQUEST_ID`: the retained decision, with no new prompt. `STALE` can mean the record is gone; check before prompting again. Only one request can be pending at a time.
- **acl sync** `--output FILE`: appends ACL audit text, using the output's existing size as the cursor. Use one file per device; never delete evidence to fix an offset mismatch.

## config (tai/config.txt)

- **config plan** `PATH CANDIDATE --plan PLAN.json`: reads the current file, runs the host C guard (`agent/build-host/agent/tests/libtai_config_guard_host.so`; see formats.md to build it), saves a private plan bound to this Vita, and prints a diff with `applied=false`. No changes, bad syntax, protected-plugin changes or a file over 16 KiB are errors. Show the diff to the human.
- **config apply** `--plan PLAN.json --transfer-state FILE --yes`: requires the ACL, the original-hash precondition, the Vita's own guard and recovery-VitaShell check, a staged commit and an exact readback. Writes `.candidate` and `.readback.json` files next to the plan. If the config changed since review, make a new plan. On uncertainty, rerun the **same** plan and state; never reboot before the readback is verified.

## content / savedata

- **content list** `CATEGORY [--limit --page]`: photo, music, video, theme, psp_application, playstation_application, psp_savedata, playstation_savedata. Vita titles come from `app list` and Vita saves from `savedata list`. E-mail and PSM are unsupported.
- **content export** `photo|music|video ID --output NEW`: by positive numeric catalog ID. Checks the catalog entry and file revision before and after, and returns the hash. No sidecars, decryption or albums.
- **content preview** `IDENTIFIER [--kind application|vita_savedata|photo|music|video] [--user 0..63] [--operation-id]`: read-only deletion plan (`execution_started=false`). The default kind is application, which needs a non-system title ID. Save the full JSON as the plan. Media plans are `execution_supported=false`.
- **content delete** `PLAN --yes [--timeout 180]`: **requires explicit user approval in this workspace**, plus the physical prompt on the Vita. Applications and Vita saves only. Pending, denied, uncertain or `persisted=false` are not success. Never apply a plan to another device or target.
- **content status** `OPERATION_ID`: deletion record plus before/after changes. Use it after a timeout or disconnect; report `effect_started`, `native_result` and `persisted`.
- **savedata list** `[--user-id 00] [--limit --page]`: save folders under `ux0:user/<id>/savedata`, matched to installed titles. Sizes are not measured (`size_measured=false`). No decrypted export.

## audit

- **audit fs** `--output DB.sqlite [--max-pages 1000]`: mirrors the filesystem write audit into SQLite with a per-device cursor. Rerun while `more=true`. Keep malformed records visible; never delete native audit files.
- **audit content** `--output DB.sqlite [--max-pages]`: mirrors the content-deletion audit and the scopes it references, transactionally. Do not call it complete until drained. Investigate binding errors; never merge mismatched histories.

## diagnostics (one read-only UDP query to 8846; no auth or retry)

- **diagnostics status** `[--host IP]`: runtime phase, result, log result and kernel stop evidence. A timeout means diagnostics are unavailable; it says nothing about the cause of a crash.
- **diagnostics input** `[--host IP]`: input sampling evidence. A stopped sample or `observation_error` needs recovery; never disable stop monitoring.
- **diagnostics log** `[--host IP]`: runtime.log open/write/close codes, not the log text. Use `fs download ur0:data/vita-agent-use/runtime.log`, or ask the human to open FTP.

## server / run

Details are in events-runs.md.

- **serve**: the persistent server. One per state directory.
- **server status**: PC-side state only; does not wake the Vita. `connected=true` is cached; confirm with a read-only snapshot if needed.
- **server events** `[--after N] [--wait 0..60] [--limit 1..1024, default 256]`: pass `next` as the following `--after`. Memory holds 4,096 events; older ones are in the `events.jsonl` journal, which is not fsynced per event.
- **server watch-log** `PATH --literal L [--once]`: pushed log tail; 4 slots at most; cleared on reconnect, so re-arm afterwards. Keep `watch_id`.
- **server unwatch-log** `WATCH_ID`: frees the slot. A `--once` watch may already have stopped itself.
- **server performance-start** `--seconds 1..3600 [--interval-ms 100..min(60000,duration)]`: pushed `performance.sample` events. Only one measurement can run, and an active run owns it.
- **server performance-stop**: stops metrics not owned by a run; keeps the events already collected.
- **run start** `FILE [--yes]`: starts a run in the background and returns `run_id` immediately. `--yes` is needed for install or overwrite. One run per server.
- **run status**: the PC coordinator record. `failed: coredump` with `coredump.state=complete` is a correctly detected crash. A dump that is still saving blocks new runs, even after `connection_lost`.
- **run cancel**: asynchronous; wait for `run.finished`. Still waits for any dump to finalize.

## call

- **call** `OP [--args JSON]`: low-level operation with validation and policy still enforced; schemas are in call-schemas.md. Prefer typed commands. Unknown operation names or fields fail. Every `call` is blocked during a run.
