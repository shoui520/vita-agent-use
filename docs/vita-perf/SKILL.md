---
name: vita-perf
description: "Profile PS Vita homebrew CPU cycles, cache misses and other Cortex-A9 PMU events with libperf. Use when instrumenting functions or threads and analyzing libperf captures."
---

# vita-perf

Use [libperf](https://github.com/shoui520/libperf). Its README and docs explain usage; start with [docs/AGENTS.md](https://github.com/shoui520/libperf/blob/main/docs/AGENTS.md).

**Local path:** `UNSET`

If the local path is `UNSET` or missing, clone it with `git clone https://github.com/shoui520/libperf agent/tools/libperf` (from the repo root; `agent/` is git-ignored), then replace `UNSET` above with the repo-relative path. Never write an absolute or personal path here.

It uses a kernel plugin, `libperf.skprx`, listed under `*KERNEL` in the tai config, and a user module, `libperf.suprx`, packaged with the application. Add the kernel plugin only with the user's approval, through the guarded `config plan` → `config apply` workflow in AGENTS.md, and reboot only after the readback is verified.
