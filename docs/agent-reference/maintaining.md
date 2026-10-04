# Maintaining the code and this guide

Before changing behavior, read both the host wrapper and the native code path. Keep the guide in line with the CLI's flags, real return fields, limits and recovery behavior. The always-loaded core is the root `AGENTS.md`; keep it short, and put reference detail in this folder.

| Subsystem | Code |
|---|---|
| CLI, config, routing, output | `vita-agent` launcher; `client/vita_agent.py`, `client/config.example.json` |
| Bootstrap, PC identity, pairing | `client/bootstrap.py`, `client/pair_vita.py`; `src/pairing_worker.c`, `pairing_activation.c`, `pairing_ui.c`, `pairing_tls.c` |
| Transport, recovery, command schemas | `client/vita_client.py`; `src/protocol.c`, `protocol.h`, `service.c`, `tls_server.c` |
| Server, events, runs | `client/server.py`, `client/event_listener.py`; `src/shell_runtime.c`, `events_vita.c`, `events_kernel.c`, `dialog_events.c`, `log_watch_vita.c`, `log_marker.c` |
| Apps, launch, install | `client/launch.py`; `src/app_registry.c`, `native_vita.c`, `package_install.c` |
| Metadata, plugins | `client/system_metadata.py`; `src/system_vita.c`, `metadata_vita.c`, `plugins_vita.c`, `modules_kernel.c` |
| Input, macros, touch, emergency stop | `client/input_sequence.py`, `macros.py`, `macro_runner.py`, `swipes.py`; `include/vita_agent.h`; `src/timeline.c`, `input_sequence.c`, `input_owner.c`, `kernel.c`, `touch_kernel.c`, `stop_monitor.c` |
| Frames, display | `src/frames_shell.c`, `shell_jpeg.c`, `capture_kernel.c`, `system_vita.c`; entry points in `vita_client.py` and `vita_agent.py` |
| Performance | `client/performance.py`; `src/performance.c`, `performance_vita.c`, `performance_kernel.c`; `include/vau_performance.h` |
| Filesystem, transfers, policy, audit | `client/upload.py`, `audit_sync.py`; `src/files_vita.c`, `file_ops.c`, `policy.c`, `write_ops.c`, `write_journal.c`, `staged_upload.c`, `upload_commit.c`, `file_mutations.c`, `trash_purge.c` |
| ACLs, guarded config | `client/request_acl.py`, `tai_config.py`; `src/acl_vita.c`, `acl_approval.c`, `acl_config.c`, `tai_config_guard.c`, `config_native.c` |
| Content, saves | `client/content.py`, `content_delete.py`, `savedata.py`; `src/content_inventory.c`, `content_media_vita.c`, `content_runtime.c`, `content_sdk_vita.c`, `content_scope.c`, `content_journal.c`, `content_export.c` |
| LiveArea | `client/livearea.py`; `src/livearea_layout.c`, `livearea_blob.c`, `livearea.c` |
| Diagnostics, loader, build | `client/diagnose_vita.py`; `src/diagnostics_vita.c`, `shell_loader.c`; `CMakeLists.txt`, `native365.yml` |

Conventions: keep the kernel bridge small and heavy work on the PC. Bound every native allocation and queue, release borrowed JPEG and file resources, and keep startup and cleanup non-blocking. Prefer audited native code paths. Firmware-specific hooks must fail with evidence when unsupported, never by guessing addresses. Never add a hardware test that could damage protected paths.
