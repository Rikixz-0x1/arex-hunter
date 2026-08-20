# arex-hunter

**AREX** — a local AI cyber security research & coding agent that runs in your terminal.

Built by [Rikixz](https://khmersec.com) · [rikixz.dev](https://rikixz.dev)

AREX is a fully-local terminal agent powered by [Ollama](https://ollama.com). It can
research people/companies/CVEs on the web, read and edit files, run commands, search
code, and write complete projects — all from one chat window with a streaming,
markdown-rendering TUI.

No cloud, no API keys, no telemetry. Everything runs on your machine.

## Features

- **Streaming TUI** — glamour-rendered markdown, live token/s rate, spinner
- **9 tools** — file ops, regex search, shell, web search, page fetching
- **Slash commands** — `/model`, `/tools`, `/tokens`, `/new`, `/host`, `/exit`, ...
- **Model picker** — `ctrl+p` / `tab`, swap between any installed Ollama models
- **Sessions** — `ctrl+l` or `/new` for a clean context; per-session token stats
- **Anti-loop & truncation guards** — repeated tool calls are stopped, replies are
  flagged when the model cuts itself off
- **One-shot mode** — `arex.exe "prompt"` for scripts and automation
- **Offline by default** — only `web_search` / `fetch_url` touch the internet

## Requirements

- [Go](https://go.dev/dl/) 1.23+
- [Ollama](https://ollama.com/download) running on `http://localhost:11434`
- A code model — recommended: `qwen2.5-coder:7b` (or `14b` for bigger jobs)

```powershell
ollama pull qwen2.5-coder:7b
```

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
| `run_command` | Run a shell command (60s timeout) |
| `web_search` | Web search with result dedup (DuckDuckGo, instant-answer fallback) |
| `fetch_url` | Fetch a page's readable text |

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

## Tips

- The default `qwen2.5-coder:3b` works but is limited — upgrade to `7b` or `14b`
  for reliable multi-step tasks:

  ```powershell
  .\arex.exe -model qwen2.5-coder:14b
  ```

- Web access is only used by `web_search` and `fetch_url`; if the search engine
  blocks the request, AREX falls back to the DuckDuckGo instant-answer API.

## License

MIT