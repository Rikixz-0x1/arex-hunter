# arex-hunter

**AREX** — a free, open-source AI agent for bug hunters, pentesters and small
project researchers. Runs 100% on your machine, forever.

Built by [Rikixz](https://khmersec.com) · [rikixz.dev](https://rikixz.dev)

> No API keys. No token bills. No rate limits. No telemetry. Your prompts never
> leave your machine.

Cloud AIs charge you per token, cut you off mid-recon, and see everything you
send. AREX runs entirely through [Ollama](https://ollama.com) on your own
hardware — unlimited tokens, private by default, and still useful when you're
offline or working in a locked-down environment.

## What it's for

**Bug hunting & security research**
- Research targets: people, companies, domains, CVEs via `web_search` + `fetch_url`
- Recon a scope folder: `grep`, `read_file`, `list_dir` across a codebase
- Write and run PoCs, decoders, fuzzers — `write_file` + `run_command`
- CTF: analyze challenges, decode flags, test exploits locally

**Small project research**
- Drop AREX into any repo and ask: *"what does this do?", "where is the auth logic?", "why does this test fail?"*
- Explore code with regex search and file reads without dumping everything into context
- Build features, fix bugs, run builds/tests — all in one chat

**When other AIs are limited**
- Out of tokens at midnight? AREX doesn't have a quota.
- No internet? Everything except `web_search` works fully offline.
- Sensitive data? Nothing is sent to a cloud provider, ever.

## Features

- **Streaming TUI** — glamour-rendered markdown, live token/s rate, spinner,
  tool results shown in-chat so you always see the raw ground truth
- **26 tools** — file ops, regex search, shell, web research, recon
  (DNS/WHOIS/port scan/subdomain/geoip/CVE), payload generation,
  encoding/hashing, HTTP testing, memory
- **Slash commands** — `/model`, `/tools`, `/tokens`, `/new`, `/host`, `/exit`, ...
- **Model picker** — `ctrl+p` / `tab`, swap between any installed Ollama models
- **Sessions** — `ctrl+l` or `/new` for a clean context; per-session token stats
- **Anti-loop & truncation guards** — repeated tool calls are stopped, replies are
  flagged when the model cuts itself off
- **One-shot mode** — `arex.exe "prompt"` for scripts and automation

## Platforms

One binary, same interface everywhere — Windows, Linux and macOS:

- **Windows** — PowerShell shell, detects scoop / chocolatey / winget, checks
  admin elevation, `run_elevated` triggers a UAC prompt
- **Linux** — detects the distro from `/etc/os-release` (Arch, Ubuntu, Kali,
  Fedora, Debian, Alpine, ...) and picks the right package manager (pacman, apt,
  dnf, apk, zypper); `run_elevated` uses passwordless sudo/doas, or runs
  directly when AREX is started as root
- **macOS** — zsh shell, `sw_vers` kernel & version, Homebrew detection

The agent knows which platform and privilege level it's on (`system_info`) and
adapts its commands. Kernel-level work (loading modules, device changes,
service management) goes through `run_elevated` — ordinary dev and file work
never needs it.

## Requirements

- [Go](https://go.dev/dl/) 1.23+
- [Ollama](https://ollama.com/download) running on `http://localhost:11434`
- A code model — recommended: `qwen2.5-coder:7b` (or `14b` for bigger jobs)

```powershell
ollama pull qwen2.5-coder:7b
```

Small models (3b/7b) run fine on 8 GB RAM and give you an unlimited-token
assistant on basically any laptop — even one without internet.

## Build & run

```powershell
go build -o arex.exe .
.\arex.exe
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-model` | `qwen2.5-coder:3b` | Ollama model to use |
| `-host` | `http://localhost:11434` | Ollama server URL |
| `-dir` | current dir | Working directory for the agent |
| `-ctx` | `16384` | Context window size (`num_ctx`) |
| `-temp` | `0.2` | Sampling temperature |
| `-version` | | Print version and exit |

### One-shot mode

```powershell
.\arex.exe "research CVE-2024-1234 and fetch the advisory"
.\arex.exe -model qwen2.5-coder:14b -dir .\project "add tests for the api package"
```

## Keybindings

| Key | Action |
|-----|--------|
| `enter` | Send message |
| `ctrl+j` | Newline (multiline prompt) |
| `ctrl+p` / `tab` | Model picker |
| `ctrl+l` | New session (reset context) |
| `esc` | Stop generation |
| `ctrl+c` | Quit |
| `↑` / `↓` / `pgup` / `pgdn` / `home` / `end` | Scroll chat history |

## Slash commands

| Command | Action |
|---------|--------|
| `/model <name>` | Switch model instantly (bare `/model` opens the picker) |
| `/tools` | List available tools |
| `/tokens` | Show token usage for this session |
| `/new`, `/clear` | Clear the session |
| `/host` | Show Ollama host, model and working dir |
| `/version` | Show AREX version |
| `/help`, `/?` | Show help |
| `/exit`, `/quit` | Quit |

## Tools

| Tool | Description |
|------|-------------|
| `list_dir` | List files in a directory |
| `read_file` | Read a file |
| `write_file` | Create or overwrite a file |
| `mkdir` | Create a directory |
| `grep` | Regex search inside files (skips `.git`, `node_modules`, binaries) |
| `cd` | Change the working directory |
| `run_command` | Run a shell command (60s timeout, right shell per platform) |
| `run_elevated` | Run a command as admin/root — UAC prompt on Windows, passwordless sudo/doas on Linux, direct when already root |
| `web_search` | Multi-engine search with automatic fallback (DuckDuckGo → Bing RSS → DDG lite → Mojeek → DDG instant → Wikipedia), dedup, clean snippets |
| `fetch_url` | Fetch a page and extract the main article text (skips nav, ads, scripts); detects binary content |
| `http_request` | Custom HTTP calls (GET/POST/PUT/DELETE) with headers & body for API/web-app testing |
| `learn` | Save a note to long-term memory (`.arex-memory.md`) so future sessions remember it |
| `recall` | Read back what AREX has learned in past sessions |
| `system_info` | Detect OS, distro, kernel, shell, package manager, installed tools |
| `project_info` | Read project manifests (go.mod, package.json, ...) to understand the codebase |
| `encode` / `decode` | base64 / base64url / hex / URL encoding — payload crafting, CTF flags |
| `hash` | md5 / sha1 / sha256 / sha512 hashing |
| `dns_lookup` | A, AAAA, MX, TXT, NS, CNAME records (pure Go) |
| `whois` | Domain registration & OSINT (IANA referral, auto-clean) |
| `port_scan` | TCP connect scan — 30 common ports or custom list/range |
| `reverse_shell` | Payload generator: bash, nc, ncat, socat, python, perl, ruby, php, powershell, telnet, golang |
| `cve_lookup` | NVD API — CVE details by ID or keyword (severity, CVSS, vector, references) |
| `subdomain_scan` | DNS brute-force of 130+ common subdomains (admin, api, dev, vpn, git...) |
| `geoip` | IP geolocation: country, city, ISP, org, ASN, proxy/hosting flags |
| `security_headers` | HTTP security header audit (HSTS, CSP, XFO, COOP/CORP...) |

> Only `web_search` and `fetch_url` need internet. Everything else — file
> exploration, coding, command execution — works fully offline.

## Architecture

```
main.go                 flags, TUI entry, one-shot mode
internal/ollama/        Ollama streaming chat client, model list, token stats
internal/agent/         Tool definitions + agent loop (tool calls, fallback JSON
                        parser, anti-loop guard, truncation detection)
internal/ui/            bubbletea TUI: streaming, markdown, picker, slash commands
```

### Agent loop

AREX uses native Ollama `tool_calls` when the model supports them, and a fallback
JSON parser when the model emits tool calls as plain text (common with 3b models).
Guards include:

- **Anti-loop** — the same tool call 3× in a row stops the turn
- **Tool cap** — max 4 tool calls per turn
- **Placeholder detection** — if the model echoes `<tool_response>` instead of
  answering, it's nudged to write a real reply
- **Truncation flag** — incomplete replies are marked `*(reply may have been cut
  off)*`
- **Long-term memory** — facts saved with `learn` are loaded into every future
  session, so AREX gets smarter about your project and preferences over time

## Tips

- The default `qwen2.5-coder:3b` works but is limited — upgrade to `7b` or `14b`
  for reliable multi-step tasks:

  ```powershell
  .\arex.exe -model qwen2.5-coder:14b
  ```

- On a mid-range gaming laptop (RTX 3060+) try a `7b` or `14b` model at full speed;
  on CPU-only machines a `3b` quantized model still gives unlimited-token research.
- Web access is only used by `web_search` and `fetch_url`; if the search engine
  blocks the request, AREX falls back to the DuckDuckGo instant-answer API.
- Use `/new` between different tasks to keep context clean and replies fast.

## License

MIT