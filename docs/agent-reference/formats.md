# JSON formats and workflows

`EXAMPLE01` is an invented title ID; take real ones from `app list`. Example operation IDs are placeholders: use the IDs the CLI returns. Write outputs, plans and transfer state into a private host directory (here `./private-work/`). JSON files the CLI loads must be at most 16 MiB, with no duplicate keys, NaN or Infinity. Every native request is limited to 128 KiB, so a request under 1,024 states can still be too large; the client checks the size.

## Ordinary input (`input submit FILE`)

The file is an argument object, not a `v/id/op` envelope.

```json
{
  "start_delay_us": 150000,
  "duration_us": 2000000,
  "repeats": 1,
  "max_lateness_us": 100000,
  "events": [
    {"at_us": 0, "buttons": ["UP", "CROSS"], "left_stick": [128, 128],
     "front": [{"id": 0, "x": 400, "y": 300, "force": 128}, {"id": 1, "x": 800, "y": 300, "force": 128}]},
    {"at_us": 200000, "buttons": ["UP"]},
    {"at_us": 350000, "front": []},
    {"at_us": 500000, "buttons": [], "left_stick": [200, 128]},
    {"at_us": 800000, "left_stick": [128, 128]},
    {"at_us": 1200000, "buttons": ["RIGHT", "R"]},
    {"at_us": 1500000, "buttons": []}
  ]
}
```

| Field | Rules |
|---|---|
| `start_delay_us` / `start_us` | Exactly one. A delay is 10,000–1,000,000. `start_us` is a decimal **string** on the Vita clock. The high-level runner replaces either with a 150 ms delay. |
| `duration_us` | 1–3,600,000,000 (one hour per segment). Time after the last event is an idle wait. |
| `repeats` | 1–1,000,000; the total must fit in 64-bit time. |
| `max_lateness_us` | 1–1,000,000; exceeding it stops execution rather than shifting the timing. |
| `events` | Not empty. Starts at 0, never decreases, stays below the duration. At most 1,024 distinct states. |
| `at_us` | Offset within the cycle, not time since the previous event. |
| `buttons` | Uppercase, unique: SELECT START UP RIGHT DOWN LEFT L R TRIANGLE CIRCLE CROSS SQUARE. PS, power and system buttons cannot be injected. The list **replaces** whatever is held; `[]` releases all. |
| `left_stick`, `right_stick` | `[x,y]`, 0–255, where 128 is centred. |
| `front`, `back` | Up to 6 front / 4 rear contacts `{id 0–127 unique, x, y 0–32767 within the panel's geometry, force 0–255, default 128}`. `[]` releases; omitting a channel keeps its state. |

A channel that is omitted keeps its state. Several events may share a timestamp only if they change different channels. Every event must change at least one channel; express waits as gaps. A tap is a contact followed by `[]`; a drag keeps the same `id` and moves it. Touch values are **native panel units**: check `touch panels` first.

Compact form: events are `[at_us, button_bitmask, lx, ly, rx, ry]` with strictly increasing times starting at 0. An optional `touch` array has one entry per event, `[enabled_bits(front=1, back=2), front_contacts, back_contacts]`, with contacts as `[id, force, x, y]`. An enabled empty panel releases its contacts; a disabled panel leaves physical touch alone. Never mix this with readable-form contacts. CROSS is 16384.

```json
{"start_delay_us": 150000, "duration_us": 500000, "repeats": 1, "max_lateness_us": 100000,
 "events": [[0, 16384, 128, 128, 128, 128], [200000, 0, 128, 128, 128, 128]],
 "touch": [[1, [[0, 128, 400, 300]], []], [1, [], []]]}
```

## Swipe from a capture

Take a fresh capture, look at it, read its real size, and pass that size:

```sh
python3 client/vita_agent.py touch swipe --panel front --from 850 272 --to 100 272 --duration-ms 450 --width 960 --height 544
```

The mapping is `native = min + round(screen * (max - min) / (size - 1))` per axis, using the panel's display geometry. `--coordinate-space native` uses the active geometry and needs no size. Points are interpolated on the Vita, held briefly at the end, then released. For several contacts, buttons during a drag, or a custom sampling rate, use input JSON instead.

## Saved macros

```json
{"v": 1, "name": "menu-cycle", "title_id": "EXAMPLE01", "steps": [
  {"duration_us": 150000, "buttons": ["down"]},
  {"duration_us": 250000, "buttons": []},
  {"duration_us": 100000, "buttons": ["cross"], "axes": [128, 128, 128, 128]},
  {"duration_us": 10000000, "buttons": []}
]}
```

```sh
python3 client/vita_agent.py macro save menu-cycle.json
python3 client/vita_agent.py macro run EXAMPLE01 menu-cycle --repeats 3   # after confirming EXAMPLE01 is in the foreground
```

Macro buttons are **lowercase**. Each step is a complete held state with a positive `duration_us` and `buttons`. `axes` `[lx,ly,rx,ry]` defaults to centred. `touch` uses the compact format; if any step uses touch, steps without it release those panels. Macros have no conditions and no vision. A 7-day cycle still depends on the host keeping the lease alive and sending continuations in time.

## LiveArea blob selection

Copy every value from a layout descriptor:

```json
{"section": "icons", "page_id": "1", "position": 0, "column": "reserved01", "output": "./private-work/icon-blob.bin"}
```

`output` is resolved relative to the directory where the operation actually runs. Use an absolute path when the server was started from a different directory.

## Upload, replace, install

Run each step only after the previous one has finished.

```sh
python3 client/vita_agent.py fs mkdir ux0:data/my-app            # only if fs stat says it is missing
python3 client/vita_agent.py fs upload ./build/data.bin ux0:data/my-app/data.bin --transfer-state ./private-work/data-upload.json
python3 client/vita_agent.py fs download ux0:data/my-app/data.bin ./private-work/data-readback.bin   # compare hashes
```

To replace an executable: `app close EXAMPLE01`, optionally back it up with `fs download`, then `fs upload ... --overwrite --yes --transfer-state ...`, read it back and compare, then `app launch`. No ACL is needed for ordinary paths. `--expected-sha256` takes the **old** file's hash, never the new source's.

To install a VPK, upload it to the Vita first, then:

```sh
python3 client/vita_agent.py app install ux0:data/my-app/example.vpk --yes --no-wait
python3 client/vita_agent.py app install-status <operation_id from install>
python3 client/vita_agent.py app list --query EXAMPLE01
```

## Guarded tai/config.txt edit

```sh
python3 client/vita_agent.py fs download ur0:tai/config.txt ./private-work/config-before.txt
# edit a separate candidate file; keep every protected plugin's behavior
python3 client/vita_agent.py config plan ur0:tai/config.txt ./private-work/config-candidate.txt --plan ./private-work/config-plan.json
python3 client/vita_agent.py acl request ur0:tai/        # wait for the human's OK and state=approved
python3 client/vita_agent.py config apply --plan ./private-work/config-plan.json --transfer-state ./private-work/config-upload.json --yes
```

The command prints a diff for review; the `--plan` file holds the bytes and hashes. Never save the printed diff and pass it as the plan. An approved ACL does not satisfy the other checks. Success writes `config-plan.json.readback.json`: check `verified`, the hash, the bytes and the full `text`. Keep the `.candidate` and transfer-state files for recovery. If the file on the Vita matches neither the original nor the candidate, make a fresh plan.

If the host guard library is missing, build it:

```sh
cmake -S . -B agent/build-host -DVAU_TESTS=ON
cmake --build agent/build-host --target tai_config_guard_host
```

This needs the local, git-ignored `agent/tests/` folder. Without it, report that the guard can't be built; never skip the guard.

## Trash and purge

```sh
python3 client/vita_agent.py fs trash ux0:data/my-app/obsolete.bin                       # authorized targets only
python3 client/vita_agent.py fs purge ux0:data/my-app/obsolete.bin --trash-id <trash op id> --yes
python3 client/vita_agent.py audit fs --output ./private-work/filesystem-audit.sqlite
```

Review the trash result before purging. Purge takes the **original** path. Never run this on protected paths to "test safety".

## Content

```sh
python3 client/vita_agent.py content list photo        # also music video theme psp_savedata playstation_savedata ...
python3 client/vita_agent.py content export photo 123 --output ./private-work/exported-photo.jpg
python3 client/vita_agent.py content preview EXAMPLE01 > ./private-work/application-delete-plan.json
python3 client/vita_agent.py content preview EXAMPLE01 --kind vita_savedata --user 0 > ./private-work/save-delete-plan.json
# Only with explicit user approval; the Vita also prompts:
python3 client/vita_agent.py content delete ./private-work/application-delete-plan.json --yes
```

Review the plan's full target, scope and changes before deleting. Afterwards, check the terminal state, native result, persistence and before/after changes, then run `audit content`. Media plans cannot be executed; never work around this by deleting files or editing catalogs.
