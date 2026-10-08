---
name: vita-perf
description: "Profile PS Vita homebrew CPU cycles, cache misses and other Cortex-A9 PMU events with libperf. Use when instrumenting functions or threads and analyzing libperf captures."
---

# vita-perf

Use [libperf](https://github.com/shoui520/libperf). Read its [agent guide](https://github.com/shoui520/libperf/blob/main/docs/AGENTS.md) and the relevant topic links; the [programming guide](https://github.com/shoui520/libperf/blob/main/docs/guide.md) covers application integration and examples.

**Checkout:** `agent/tools/libperf`. If missing, clone with `git clone https://github.com/shoui520/libperf agent/tools/libperf` from the repository root. Keep builds and captures under the ignored `agent/` directory.

- Retail 3.65 with taiHEN is the validated platform. The kernel plugin is `libperf.skprx`; applications package and load `libperf.suprx` using generated weak imports. Check module ID and start status before calling it, and keep it loaded while profiling. Follow the guarded `config plan` → `config apply` workflow for kernel plugin installation.
- Counters follow threads; they are not whole-core utilization metrics. Counter IDs `0..5` select event slots; `31` reads cycles. The 48-bit timebase runs at 1 MHz, while PMU counters are 32-bit. Account for wrapping and preserve measurement boundaries, clock settings, baselines and raw samples.
- Transfer completed reports through `./vita-agent fs download` into `agent/`, then run `python3 agent/tools/libperf/tools/analyze.py CAPTURE --json`. The analyzer accepts function CSVs and stress logs, not the correctness-test report. Successful parsing does not mean a recorded stress test passed.

For GPU profiling use [vita-gpuprof](../vita-gpuprof/SKILL.md). For system CPU utilization/FPS use vita-agent-use's `performance` commands.
