---
name: vita-gpucrash
description: "Analyze PS Vita psp2core-GPUCRASH-*.psp2dmp GPU crash dumps: GPU faults, contexts, pipeline, resources. Use when a Vita GPU crash dump is involved."
---

# vita-gpucrash

Use [psp2_gpucrash_parse](https://github.com/shoui520/psp2_gpucrash_parse). Its README and docs explain usage.

**Local path:** `UNSET`

If the local path is `UNSET` or missing, clone it with `git clone https://github.com/shoui520/psp2_gpucrash_parse agent/tools/psp2_gpucrash_parse` (from the repo root; `agent/` is git-ignored), then replace `UNSET` above with the repo-relative path. Never write an absolute or personal path here.

Only analyze a dump after `coredump.complete`; get it with `fs download`. Pass the original ELF or SELF to get CPU address analysis.
