---
name: vita-coredump
description: "Analyze PS Vita psp2core-*.psp2dmp application crash dumps: crashing thread, registers, backtrace, modules. Use for CPU-side app crashes; use vita-gpucrash for GPUCRASH dumps."
---

# vita-coredump

Use [psp2_core_parse](https://github.com/shoui520/psp2_core_parse). Its README and docs explain usage.

**Local path:** `UNSET`

If the local path is `UNSET` or missing, clone it with `git clone https://github.com/shoui520/psp2_core_parse agent/tools/psp2_core_parse` (from the repo root; `agent/` is git-ignored), then replace `UNSET` above with the repo-relative path. Never write an absolute or personal path here.

Only analyze a dump after `coredump.complete`; get it with `fs download`. For symbols, pass the matching decrypted ELF under its real runtime module name.
