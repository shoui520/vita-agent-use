# Agent Use for Vita

**Let an AI agent use your PS Vita.**

vita-agent-use is like computer use for AI agents, but for a PS Vita. An agent such as Claude, Codex or Gemini can see the screen, press buttons, touch the screen, launch apps, move files and watch for crashes. It is built for agentic PS Vita development: the agent builds your homebrew, deploys it, launches it, plays it, reads the logs and crash dumps, then fixes the code and does it again, without you touching the console.

It **replaces [VitaCompanion](https://github.com/devnoname120/vitacompanion)** with an authenticated, auditable control channel designed for agents.

## What the agent can do

| | |
|---|---|
| 👀 **See** | Take screenshots of games and LiveArea; read console info, installed apps, plugins, LiveArea layout and content |
| 🎮 **Play** | Precisely timed button, stick and multi-touch input on the front and rear panels, swipes, and saved per-game macros |
| 📦 **Deploy** | Verified file upload and download, VPK installs, launching and closing apps |
| 🐞 **Debug** | Real-time crash-dump, error-dialog and log events pushed to the PC; CPU, FPS and memory metrics |
| 🔁 **Run** | One command does a whole test run: deploy, launch, wait for a log line or a crash, collect metrics, clean up |

## Built to be safe

You stay in control of your console:

- **You approve pairing.** A new PC can only connect after you tap OK on the Vita.
- **Press PS + SELECT at any time** to stop the agent immediately.
- **Risky changes need your OK on the Vita.** Before the agent can write to `tai/` or `shell/`, or delete apps and saves, the Vita asks you to confirm. The agent cannot press OK for you.
- **Some things can't be changed at all.** System partitions are read-only, and core plugins such as HENkaku, YAMT and storagemgr can never be overwritten or deleted.
- **`config.txt` edits are guarded.** The agent must show you a diff to review, the edit is checked so it can't break your plugins, and the file is read back to confirm it was written correctly.
- **Deletions are reversible until confirmed.** Files go to trash before they are permanently removed, and every write is recorded in an audit log on the Vita.
- **The connection is secure.** It uses mutual TLS with a pinned device certificate and short-lived tokens.

## How it works

```
┌──────────── PC ─────────────┐        TLS        ┌────────────── PS Vita ──────────────┐
│ AI agent                    │                   │ vita_agent_loader.suprx  (*main)    │
│   └─ client/vita_agent.py   │ ◀───────────────▶ │   └─ vita_agent_shell.suprx         │
│        └─ serve (events)    │  commands/events  │ vita_agent_kernel.skprx  (*KERNEL)  │
└─────────────────────────────┘                   └─────────────────────────────────────┘
```

- **On the Vita:** the plugin has a small kernel bridge, a loader for Shell, and a runtime that runs inside Shell.
- **On the PC:** the agent drives a Python command-line tool that returns JSON. An optional `serve` process stays connected so the Vita can push events (crashes, dialogs, log lines, metrics) as they happen, rather than the agent polling for them.

## Requirements

- A PS Vita or PS TV with HENkaku/Ensō and taiHEN
- [VitaShell](https://github.com/TheOfficialFloW/VitaShell), used for setup over FTP and as the recovery copy that guarded config edits require
- A PC with Python 3 and the [`cryptography`](https://pypi.org/project/cryptography/) package
- To build the plugin yourself: [VitaSDK](https://vitasdk.org), CMake and the [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) 3.6.7 source

## Installation

### 1. Build the plugin

```sh
cmake -S . -B build
cmake --build build
```

### 2. Install it on the Vita

Copy `vita_agent_kernel.skprx`, `vita_agent_loader.suprx` and `vita_agent_shell.suprx` to `ur0:tai/`, then add two lines to `ur0:tai/config.txt`:

```
*KERNEL
ur0:tai/vita_agent_kernel.skprx

*main
ur0:tai/vita_agent_loader.suprx
```

The Shell runtime isn't listed in `config.txt`; the loader starts it. Reboot the Vita.

### 3. Set up the PC

```sh
pip install cryptography
python3 client/vita_agent.py bootstrap
```

`bootstrap` is an interactive setup wizard. It asks for your Vita's IP address and the name of the agent that will use it. It reads your `config.txt` over VitaShell FTP to check for incompatible plugins, but never writes anything to the Vita.

### 4. Pair

```sh
python3 client/vita_agent.py session pair   # tap OK on the Vita
python3 client/vita_agent.py serve          # optional: leave running for live events
```

That's it. Now point your agent at this repository.

## Plugin compatibility

**Recommended alongside vita-agent-use:**

| Plugin | Why |
|---|---|
| **NoSleep** | Stops the Vita from sleeping during long agent sessions |
| **NoLockScreen** | Skips the lock screen, so the agent can reach LiveArea after a reboot or wake |

**Incompatible or not recommended.** `bootstrap` checks for these and warns you:

| Plugin | Status |
|---|---|
| **VitaCompanion** | ❌ Incompatible; disable it (vita-agent-use replaces it) |
| BGFTP | ⚠️ Not recommended alongside |
| catlog | ⚠️ Not recommended alongside |
| kvdb | ⚠️ Not recommended alongside |
| psp2shell | ⚠️ Not recommended alongside |
| vdbtcp | ⚠️ Not recommended alongside |

## Try it yourself

The CLI is meant for agents, but you can run it too:

```sh
python3 client/vita_agent.py system snapshot
python3 client/vita_agent.py screen capture --output screen.jpg
python3 client/vita_agent.py app list
python3 client/vita_agent.py --help
```

## Companion tools

The agent can also use these tools when profiling or debugging:

- [psp2-cex-gpues4-prof](https://github.com/shoui520/psp2-cex-gpues4-prof): GPU profiling on retail consoles
- [psp2_core_parse](https://github.com/shoui520/psp2_core_parse): analyze app crash dumps
- [psp2_gpucrash_parse](https://github.com/shoui520/psp2_gpucrash_parse): analyze GPU crash dumps
- [psp2_err](https://github.com/shoui520/psp2_err): look up error codes offline

## License

vita-agent-use is licensed under the [GNU General Public License v3.0](LICENSE).
