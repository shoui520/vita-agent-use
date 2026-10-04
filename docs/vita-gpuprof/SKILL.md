---
name: vita-gpuprof
description: "Profile PS Vita GPU performance on retail consoles. Use when measuring GPU load, timings or bottlenecks of a Vita app."
---

# vita-gpuprof

Use [psp2-cex-gpues4-prof](https://github.com/shoui520/psp2-cex-gpues4-prof). Its README and docs explain usage.

**Local path:** `UNSET`

If the local path is `UNSET` or missing, clone it with `git clone https://github.com/shoui520/psp2-cex-gpues4-prof agent/tools/psp2-cex-gpues4-prof` (from the repo root; `agent/` is git-ignored), then replace `UNSET` above with the repo-relative path. Never write an absolute or personal path here.

It runs as a kernel plugin, `psp2_gpuprof.skprx`, listed under `*KERNEL` in the tai config. Add it only with the user's approval, through the guarded `config plan` → `config apply` workflow in AGENTS.md, and reboot only after the readback is verified.
