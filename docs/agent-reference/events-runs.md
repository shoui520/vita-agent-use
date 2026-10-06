# Server events, runs and performance

## Receiving events

Start `serve` in a long-lived process, then from another shell:

```sh
python3 client/vita_agent.py server status
python3 client/vita_agent.py server events --after 0 --wait 30      # pass each result's `next` as the next --after
python3 client/vita_agent.py server watch-log ux0:data/my-app/log.txt --literal frames=1000 --once
python3 client/vita_agent.py server performance-start --seconds 60 --interval-ms 1000
```

`--wait` waits on the PC's own event history; it does not poll the Vita. The Vita pushes events over the server's existing connection, so nothing extra listens on the network. The Unix socket is only for local CLI calls. Reconnects back off from 2 to 60 s. Background reconnect, saved-PC token renewal and event subscription remain silent with the screen off; they do not show the agent-use notification. Actual commands still wake the display and announce use. An uncertain write or control command pauses automatic reconnection until it is recovered; read-only observations do not. With `device_dir` configured, sessions renew before the one-hour expiry or idle limit. `server status` includes expiry and reports expired sessions as disconnected. Legacy credentials without a recorded expiry are renewed once when the saved pairing directory is available. Renewal is deferred during runs and dump finalization. Renewal interrupts standalone log listeners and emits `log.interrupted`; re-register them.

| Event | Meaning |
|---|---|
| `connection.ready` / `connection.lost` | Connection lifecycle. Lost does not mean effects were undone. |
| `coredump.saving` | A new `.psp2dmp.tmp` appeared. Record it and wait. |
| `coredump.complete` | Renamed to the final `.psp2dmp`. Match it to the saving event and keep the full path. |
| `dialog.error` | Error callback. Keep the code/hex; it does not prove a dialog was shown. |
| `tty.data` | Automatically captured kernel/user printf output, with `source`, `pid`, native timestamp, lossless hex `data` and a readable `text` preview. |
| `log.data` | Hex-encoded appended bytes with watch ID, path and offset. Decode on the host and handle chunk boundaries. |
| `log.marker` | The exact literal was reached, including across chunk boundaries. |
| `log.reset` | The log was truncated or replaced; offsets start over. |
| `performance.sample` | One sample from the Vita; keep its window, counters and errors. |
| `events.overflow` / `performance.overflow` | Native observations were lost. Report the gap; never fill it in. |
| `run.phase` / `run.finished` | Run coordinator state. |
| `command.progress` | Progress from a blocking server command; check `result`. |

Records add a PC `sequence` and UTC `received_at`. The native sequence and time are stored separately, and event shapes vary. The server keeps 4,096 events in memory; older ones are in the `journal` (`events.jsonl`). After a restart, numbering continues but old events are not reloaded into memory. The dump listener fires only for **new** dumps, and events can be lost during a disconnect or overflow, so never claim "no crashes" when no receiver was connected.

Kernel and user TTY logging starts automatically with `serve`'s authenticated subscription; no log-file watch is needed for `sceClibPrintf`. Inspect `connection.ready.tty`: `kernel_error` and `user_error` must both be zero. Unsupported firmware or a failed hook is reported there while other event sources remain usable. The native dispatchers are verified for retail 3.65, using the callback ABI researched from [CatLog](https://github.com/isage/catlog) and [PrincessLog](https://github.com/TeamFAPS/PSVita-RE-tools/tree/master/PrincessLog).

TTY records are fragments, not guaranteed full lines. The kernel keeps 32 records of up to 256 bytes (about 9 KiB); output is pushed in bounded batches without allocating, writing files or using networking inside the logging callbacks. Capture starts at subscription and remains enabled until reboot, retaining recent output during disconnects. It does not recover older boot output. Existing native debug handlers and crash-dump TTY storage are preserved. Ordinary `printf` is covered when it uses the native debug-output path; a file or custom renderer is not TTY output.

Keep the hex `data` to preserve arbitrary bytes. `text` decodes each fragment as UTF-8 with replacement, so a multibyte character split across records can appear incorrectly in the preview; decode consecutive data fragments on the PC when exact text matters. Long kernel printf calls retain the first 1,023 bytes. TTY `events.overflow` reports `lost` records and `dropped_since_last` bytes omitted through truncation or lock contention. Heavy logging can overflow the ring; capture never blocks the producer waiting for the PC. TTY receipt does not wake the screen or mark the agent as active.

Log watches match an exact UTF-8 literal of 1–128 bytes (no regex) and start at the end of the file. They ignore older matches and allow a file that will be created later. There are 4 slots; free any you no longer need, and re-arm them after a reconnect. `--once` frees its slot after the first match; it does not end a run or close the app.

## Runs

```json
{
  "title_id": "EXAMPLE01",
  "timeout_s": 60,
  "performance_interval_ms": 1000,
  "close_on_completion": true,
  "completion": {"log": {"path": "ux0:data/my-app/log.txt", "literal": "frames=1000"}}
}
```

```sh
python3 client/vita_agent.py run start run.json
python3 client/vita_agent.py run status
```

`run start` returns `run_id` immediately. In order, the coordinator: turns the screen on, records the native run, starts metrics, closes conflicting apps, runs any `prepare` step, starts the log watch **before** launching, confirms the title reached the foreground, then waits for a **new** match. On success it closes the app, stops metrics and the watch, ends the run, saves the result and applies `screen_off_when_done`.

- `timeout_s`: 1–3600, default 120. It limits only the completion wait; preparation, launch and cleanup add to it. Hitting the timeout is a **failure**.
- `performance_interval_ms`: optional, 100–60,000, and no longer than the timeout.
- `close_on_completion`: default true. It also applies to failure and cancel cleanup.
- Never put `yes` in the file; pass `run start --yes` for installs or overwrites.
- `prepare` takes exactly one of these. Source paths are resolved relative to the CLI's working directory and must exist.
  - `{"upload": {"source": "./build/eboot.bin", "destination": "ux0:app/EXAMPLE01/eboot.bin", "overwrite": true}}` uses the guarded staged upload.
  - `{"install": {"source": "./build/example.vpk"}}` stages, installs and checks the installed title matches.

Without `completion`, the run waits for cancel, a coredump, a disconnect or the timeout.

## Crash tests

Use a run without `completion` (for example, `timeout_s` 600 with metrics) and let the user play until the app crashes. On `coredump.saving`, automation stops, and the run **must not** close the app, turn off the screen or end the native run until the matching completion arrives. The result is `failed` with error `coredump` and a complete dump path. That counts as a successful crash-detection test. Cleanup destroys the app by title even if its process is gone, because Shell can keep the app context alive.

Check `run status`, `run.finished` and `cleanup_errors`. `run cancel` during a dump also waits. If the connection drops, keep the saving record and let it reconnect; start no new run and do not force a reboot. If the final event arrives after the worker has exited, verify cleanup and finish anything left only after the dump is complete.

## Performance

`performance measure` and `performance watch` poll in the foreground. `server performance-start` and runs use pushed samples. CPU0–3 is system-wide per-core activity, computed from idle clocks over the **actual** window; it does not belong to the game alone. FPS counts primary framebuffer submissions from the foreground process; it is not GPU load or a count of unique frames. Memory gives totals, free and used for foreground USER_RW, CDRAM, PHYCONT and CDLG. The ring holds 64 samples. Report `dropped_samples`, overflows, foreground-process changes and the real window length. Never treat missing samples as zero, and never assume a window was exactly 1 s. Only one measurement can run at a time, and an active run owns it.
