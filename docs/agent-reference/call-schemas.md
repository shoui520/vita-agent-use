# Low-level `call` operations

Prefer typed commands: they handle IDs, pagination, waiting, recovery, binary transfer and cleanup. `call OP --args '{...}'` sends only the **args** object; the client builds the request envelope and assigns its ID.

```sh
python3 client/vita_agent.py call performance.read --args '{"after":0}'
python3 client/vita_agent.py call log.start --args '{"path":"ux0:data/my-app/log.txt","marker":"frames=1000"}'
```

Conventions: `ID` is 32 lowercase hex characters. Title IDs are 9 uppercase alphanumeric characters. Paths are Vita paths of at most about 511 UTF-8 bytes. Counter strings are canonical non-negative decimals that fit in signed 64-bit; positive scopes and media IDs cannot be `"0"`. Event cursors are uint32. Unknown arguments are rejected. Native replies are at most 4 KiB, and the last response on each authenticated connection is cached for replay.

| Operation | Args and notes |
|---|---|
| `capabilities`, `system.snapshot`, `system.reboot`, `screen.on`, `app.running`, `touch.panels` | `{}`. Note that `system.snapshot` returns the raw snapshot without plugins. |
| `screen.off` | `{}`. The server's automatic screen cleanup does not account for a generic call the way it does for typed screen commands. |
| `app.launch` / `app.close` | `{title_id}`. Launch uses the host's close-and-confirm wrapper. |
| `app.list` | Optional `after` and `query` for one raw batch. Without a cursor, the host returns the complete list with query/limit/page. |
| `decrypt.start` | `{operation_id, path}`. Stable 32-character lower-case hex ID and normalized source SELF path. Starts or returns the same peer-owned job. Prefer typed `decrypt` for verified host download. |
| `decrypt.status` | `{operation_id}`. Returns running/complete/failed/uncertain, native phase/result, output path, bytes and SHA-256. |
| `app.install` | `{operation_id:ID, path, yes:true}`. Starts the install without waiting. |
| `app.install.status` | `{operation_id:ID}` |
| `input.acquire`, `input.heartbeat`, `input.status`, `input.cancel`, `input.release` | `{}`. Ordinary input is not bound to a title; the lease lasts 5 s. |
| `input.submit` | A sequence args object. Does **not** acquire, heartbeat or wait. |
| `macro.acquire` | `{title_id}`. Binds to the title's current foreground process. |
| `macro.enqueue` | Sequence args with `start_us:"0"`. Continues from the end of the previous segment and needs the macro lease. |
| `fs.stat` | `{path}` |
| `fs.list` | Raw `{path, offset}`. Omit `offset` for the complete listing with limit/page/sort_by/order. |
| `fs.mkdir`, `fs.trash` | `{operation_id:ID, path, yes:bool}` |
| `fs.move` | `{operation_id:ID, path, destination, yes:bool}` |
| `fs.purge` | `{operation_id:ID, path, trash_id:ID, yes:bool}`. The two IDs must differ. |
| `acl.request` / `acl.status` | `{request_id:ID, path}` / `{request_id:ID}` |
| `acl.audit` | `{offset}`, 0..2³²−1025 |
| `plugins.list` | Raw `{offset}`. Omit it for the complete enabled-only listing. |
| `performance.measure` | `{window_ms}`, 100..60000 |
| `performance.watch` | `{duration_s 1..3600, interval_ms?}`. Interval defaults to 1000 and must fit within the duration. |
| `performance.read` | `{after}` |
| `performance.cancel`, `events.start`, `events.stop`, `dialog.events.start`, `dialog.events.stop` | `{}`. `events.stop` leaves the default crash listener on. |
| `events.read`, `dialog.events.read` | `{after}` |
| `events.subscribe` | `{}`. Owned by the server; never call it behind a running server. |
| `log.start` | `{path, marker}`. Literal of 1..128 bytes; starts at the end of the file. |
| `log.read` / `log.stop` | `{watch_id}`, a positive uint32 |
| `livearea.schema` | Optional `{after}`. Omit for the complete metadata. |
| `livearea.layout` | Raw `{section: pages/icons, offset 0..100000}`. Omit `offset` to list that section; omit both for the grouped layout. |
| `livearea.blob` | `{section, page_id: signed 64-bit decimal string, position, column: reserved01..05, offset}`. Returns one hex chunk. |
| `content.list` | `{category, after?}`. Omit `after` for the complete list. |
| `content.delete.preview` | App: `{operation_id, title_id}`. Save: add `kind:"vita_savedata", user 0..63`. Media: `{operation_id, kind: photo/music/video, media_id}`. |
| `content.delete.request` | `{operation_id, title_id, preview_scope, yes:true}` (saves also need kind and user). Needs the physical prompt. Prefer the typed `content delete`. |
| `content.delete.status` | `{operation_id}` |
| `content.delete.changes` | `{operation_id, before_scope, after_scope, cursor}`. Omit `cursor` for all changes. |
| `content.scope` | `{operation_id, scope_sequence, cursor}`. Omit `cursor` for all. |
| `content.albums` | `{operation_id, scope_sequence, cursor, list_cursor}`. Omit both cursors for all. |
| `content.audit` | `{cursor}` |
| `run.begin` / `run.update` / `run.end` | `{run_id, title_id}` / `{run_id, phase: preparing/armed/launching/running/closing}` / `{run_id, phase: completed/cancelled/failed/connection_lost}`. Owned by the run coordinator; `begin` does **not** execute a run spec. |
| `run.status` | `{}`. This session's native run record, not the typed `run status`. |

Host-only operations: `savedata.list` (`user_id` default `"00"`, limit, page); `content.export` (`{category, id, output}`); and the combined `livearea.layout` (`{include_iconlayout_ini}`, default true, with no pagination).

These do **not** exist as `call` operations: `fs.upload`, `fs.download`, `frame`, `touch.swipe`, `macro.run`, and any way to call arbitrary Sony functions. Use the typed commands; never invent names.
