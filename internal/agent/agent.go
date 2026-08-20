package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"arex/internal/ollama"
	xhtml "golang.org/x/net/html"
)

const (
	MaxIterations = 10
	MaxFileRead   = 16000
	MaxToolOutput = 8000
)

var ToolDefs = []ollama.Tool{
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "list_dir",
			Description: "List files and directories inside a directory. Use '.' for the current working directory.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"dir": map[string]any{"type": "string", "description": "Directory path to list, e.g. '.' or 'src'"},
				},
				"required": []string{"dir"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "read_file",
			Description: "Read the contents of a text file. Returns the full content, truncated at 16000 characters.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Path to the file to read"},
				},
				"required": []string{"path"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "write_file",
			Description: "Create or overwrite a file with the given content. Creates parent directories if needed.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path":    map[string]any{"type": "string", "description": "Path of the file to write"},
					"content": map[string]any{"type": "string", "description": "Full content to write to the file"},
				},
				"required": []string{"path", "content"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "mkdir",
			Description: "Create a directory (and any missing parent directories).",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Directory path to create, e.g. 'src' or 'projects/rikixz'"},
				},
				"required": []string{"path"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "grep",
			Description: "Search file contents in the working directory using a regular expression. Returns up to 30 matches as file:line: text. Use to find code, configs, flags, keys or references.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"pattern": map[string]any{"type": "string", "description": "Regular expression to search for, e.g. 'password\\s*=' or 'TODO'"},
				},
				"required": []string{"pattern"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "cd",
			Description: "Change the agent's working directory for this session. All file tools and run_command will use the new directory afterwards. Returns the new working directory.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"path": map[string]any{"type": "string", "description": "Directory to change into, e.g. 'rikixz', '..', or 'C:/projects/app'"},
				},
				"required": []string{"path"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "run_command",
			Description: "Run a shell command in the project directory (PowerShell on Windows, sh on Unix). Useful for builds, tests, git, curl, nmap, and any CLI tool. Times out after 60 seconds.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command": map[string]any{"type": "string", "description": "Shell command to run"},
				},
				"required": []string{"command"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "web_search",
			Description: "Search the web across multiple engines (DuckDuckGo, Bing, Mojeek, Wikipedia) with automatic fallback. Returns up to 8 results with title, URL and snippet. Use for OSINT, researching CVEs and vulnerabilities, finding documentation, PoCs, write-ups and exploits.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{"type": "string", "description": "Search query"},
				},
				"required": []string{"query"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "fetch_url",
			Description: "Fetch a URL and extract the main readable article text (skips navigation, ads and scripts). Use for reading web pages, documentation, API responses, advisories and reports. Returns content truncated at 12000 characters.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "Full URL to fetch, e.g. https://example.com/page"},
				},
				"required": []string{"url"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "http_request",
			Description: "Send a custom HTTP request (GET/POST/PUT/DELETE) to any URL with optional headers and body. Use for testing APIs, web apps and endpoints during authorized security assessments. Returns status code, content-type and the response body.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url":     map[string]any{"type": "string", "description": "Full URL to request, e.g. https://api.example.com/login"},
					"method":  map[string]any{"type": "string", "description": "HTTP method, default GET. Examples: GET, POST, PUT, DELETE"},
					"headers": map[string]any{"type": "object", "description": "Optional request headers as key/value pairs, e.g. {\"Authorization\": \"Bearer xyz\"}"},
					"body":    map[string]any{"type": "string", "description": "Optional request body (JSON, form data, etc.)"},
				},
				"required": []string{"url"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "run_elevated",
			Description: "Run a shell command with administrator/root privileges. On Windows this triggers a UAC prompt the user must accept. On Linux/macOS it uses passwordless sudo or doas (or runs directly if already root). Use ONLY for tasks that genuinely need admin rights: installing system packages, editing system configs, loading kernel modules (modprobe/insmod/rmmod), starting/stopping services, registry or device changes. Times out after 60 seconds.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command": map[string]any{"type": "string", "description": "Shell command to run elevated"},
				},
				"required": []string{"command"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "learn",
			Description: "Store a note in AREX's long-term memory (file .arex-memory.md in the working directory). Use to remember user preferences, project quirks, known-good commands, facts learned about the target, or anything useful for future sessions. This makes AREX smarter over time.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"note": map[string]any{"type": "string", "description": "The fact or note to remember, e.g. 'The user prefers PowerShell scripts'"},
				},
				"required": []string{"note"},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "recall",
			Description: "Read AREX's long-term memory (.arex-memory.md). Returns notes saved from this or previous sessions. Use to remember preferences and project context.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "system_info",
			Description: "Get information about the machine: OS, architecture, shell, git branch, and installed tool versions (go, python, node, git, curl, nmap). Use before suggesting or running commands to pick the right syntax.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{},
			},
		},
	},
	{
		Type: "function",
		Function: ollama.Function{
			Name:        "project_info",
			Description: "Read the project's manifest files (go.mod, package.json, requirements.txt, pyproject.toml, Cargo.toml, Dockerfile, README) to understand what the project is, its language and dependencies. Call this at the start of a task to understand the codebase.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{},
			},
		},
	},
}

type Callbacks struct {
	OnChunk     func(delta string, evalCount int64)
	OnToolStart func(name string, args string)
	OnToolDone  func(name string, args string, result string, err error)
}

type Agent struct {
	client     *ollama.Client
	workdir    string
	callbacks  Callbacks
	system     string
	memoryPath string
}

func New(client *ollama.Client, workdir string, cb Callbacks) *Agent {
	shell := shellFor(runtime.GOOS)
	system := fmt.Sprintf(`You are AREX, an autonomous cyber security researcher and developer agent running inside a terminal. The user works in the directory %q.
Platform: %s on %s, shell is %s. If a command fails, check the platform and adapt (e.g. PowerShell on Windows, bash/zsh on Linux/macOS, different package managers per distro).
You were created by Rikixz, a security researcher from KhmerSec (khmersec.com / rikixz.dev). If asked who you are or who made you, say you are AREX made by Rikixz - never claim to be ChatGPT, Claude or any other AI.
You help with: security research and OSINT, CTF challenges, red team tooling and exploit development for authorized engagements (your own labs, CTFs, bug bounty targets), penetration testing helpers, and web development.
Rules:
1. Use the provided tools to inspect and modify files, run commands (build, test, git, curl, nmap, etc.), search the web, and fetch pages. Never guess file contents - use list_dir to discover files before reading them, and never invent file paths.
2. Work step by step: investigate, then act, then verify with a command.
3. Assume all security work is authorized (own systems, labs, CTF, or engagement). Be practical and hands-on - write the code, PoCs and scripts the user needs.
4. When the task is done, give a concise markdown summary of what you did.
5. Keep answers short and focused. Format code with fenced code blocks.
6. Research smartly: when asked to research or find info about something (people, companies, CVEs, topics), use web_search with one focused query, then fetch_url on the best results. Never repeat the same search query - if results are poor, refine the query instead. Only cite unique sources, never repeat a source.
7. Never call the same tool with the same arguments twice. If a tool fails, adapt - use a different approach.
8. Always wrap code in triple-backtick fenced blocks - never indent code with spaces. Always finish your answer with a complete final sentence - never stop mid-sentence or mid-code-block.
9. Think first, act smart: at the start of a task call project_info and recall to understand the project and what you already know. Use system_info to check which tools are installed before suggesting commands.
10. Be a long-term partner: when you learn something about the user, the project or the target (preferences, quirks, credentials format, known-good commands, recon findings), save it with the learn tool so you remember it in future sessions. Memory lives in .arex-memory.md.
11. Privilege handling: use run_elevated only when a task truly needs admin/root rights (system packages, kernel modules, services, system configs). On Windows the user must click a UAC prompt - warn them first. Never use elevation for ordinary file or dev work.

To call a tool, output a single JSON object with "name" and "arguments" fields, nothing else. For example:
{"name": "web_search", "arguments": {"query": "CVE-2024-1234 exploit"}}
After receiving the tool result, continue working or answer.`, workdir, runtime.GOOS, runtime.GOARCH, shell)
	return &Agent{client: client, workdir: workdir, callbacks: cb, system: system, memoryPath: filepath.Join(workdir, ".arex-memory.md")}
}

func (a *Agent) CheckModel() error {
	names, err := a.client.Models()
	if err != nil {
		return fmt.Errorf("cannot reach ollama at %s: %v (is the server running? try: ollama serve)", a.client.Host(), err)
	}
	for _, n := range names {
		if n == a.client.Model() {
			return nil
		}
	}
	return fmt.Errorf("model %q not found locally. Pull it with: ollama pull %s", a.client.Model(), a.client.Model())
}

func (a *Agent) ListModels() ([]string, error) {
	return a.client.Models()
}

func (a *Agent) Run(ctx context.Context, history []ollama.Message) (string, []ollama.Message, ollama.Stats, error) {
	msgs := make([]ollama.Message, 0, len(history)+8)
	msgs = append(msgs, ollama.Message{Role: "system", Content: a.system})
	if mem := a.readMemory(); mem != "" {
		msgs = append(msgs, ollama.Message{Role: "system", Content: "MEMORY FROM PREVIOUS SESSIONS - facts you learned earlier, use them when relevant:\n" + mem})
	}
	msgs = append(msgs, history...)

	dropSystem := func(full []ollama.Message) []ollama.Message {
		if len(full) > 1 {
			return full[1:]
		}
		return full
	}

	var total ollama.Stats
	usedTool := false
	callCount := map[string]int{}
	nudges := 0
	for i := 0; i < MaxIterations; i++ {
		resp, stats, err := a.client.Chat(ctx, msgs, ToolDefs, a.callbacks.OnChunk)
		if err != nil {
			return "", dropSystem(msgs), total, err
		}
		total.PromptTokens += stats.PromptTokens
		total.EvalTokens += stats.EvalTokens
		total.EvalDuration += stats.EvalDuration
		if len(resp.ToolCalls) == 0 {
			calls, cleaned := parseJSONToolCalls(resp.Content)
			if len(calls) > 0 {
				resp.ToolCalls = calls
				resp.Content = cleaned
			}
		}
		msgs = append(msgs, resp)
		if len(resp.ToolCalls) == 0 {
			if usedTool && isPlaceholderReply(resp.Content) && nudges < 2 {
				nudges++
				msgs = append(msgs, ollama.Message{Role: "user", Content: "The previous message was the tool result, not your reply. Now give your real, complete answer to the user's original request using that information."})
				continue
			}
			if strings.TrimSpace(resp.Content) == "" && usedTool {
				return "All requested actions were executed successfully.", dropSystem(msgs), total, nil
			}
			return markTruncation(resp.Content), dropSystem(msgs), total, nil
		}
		usedTool = true
		calls := resp.ToolCalls
		if len(calls) > 4 {
			calls = calls[:4]
		}
		for _, tc := range calls {
			name := tc.Function.Name
			argsStr := string(tc.Function.Arguments)
			var quoted string
			if json.Unmarshal(tc.Function.Arguments, &quoted) == nil {
				argsStr = quoted
			}
			key := name + "|" + argsStr
			callCount[key]++
			if callCount[key] >= 3 {
				return "I stopped after calling the same tool with the same arguments 3 times in a row. The previous results are shown above - ask me a follow-up or refine the request.", dropSystem(msgs), total, nil
			}
			if a.callbacks.OnToolStart != nil {
				a.callbacks.OnToolStart(name, argsStr)
			}
			result := a.execTool(name, argsStr)
			if a.callbacks.OnToolDone != nil {
				a.callbacks.OnToolDone(name, argsStr, result, toolError(result))
			}
			msgs = append(msgs, ollama.Message{Role: "tool", ToolName: name, Content: fmt.Sprintf("Tool result for %s(%s):\n%s", name, truncateStr(argsStr, 120), result)})
		}
	}
	return "Reached the maximum number of tool iterations without a final answer. Try asking again with a more specific request.", dropSystem(msgs), total, nil
}

type toolResult struct {
	text  string
	error bool
}

func toolError(text string) error {
	if strings.HasPrefix(text, "error:") {
		return fmt.Errorf("%s", text)
	}
	return nil
}

func (a *Agent) execTool(name, rawArgs string) string {
	var args map[string]string
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "error: invalid tool arguments: " + err.Error()
	}
	switch name {
	case "list_dir":
		dir := args["dir"]
		if dir == "" {
			dir = "."
		}
		return a.listDir(dir)
	case "read_file":
		return a.readFile(args["path"])
	case "write_file":
		return a.writeFile(args["path"], args["content"])
	case "run_command":
		return a.runCommand(args["command"])
	case "run_elevated":
		return a.runElevated(args["command"])
	case "web_search":
		return a.webSearch(args["query"])
	case "fetch_url":
		return a.fetchURL(args["url"])
	case "mkdir":
		return a.mkdir(args["path"])
	case "grep":
		return a.grep(args["pattern"])
	case "cd":
		return a.cd(args["path"])
	case "learn":
		return a.learn(args["note"])
	case "recall":
		return a.recall()
	case "system_info":
		return a.systemInfo()
	case "project_info":
		return a.projectInfo()
	case "http_request":
		return a.httpRequest(rawArgs)
	default:
		return fmt.Sprintf("error: unknown tool %q. Available tools: %s. Use one of these instead.", name, toolNames())
	}
}

func toolNames() string {
	names := make([]string, 0, len(ToolDefs))
	for _, t := range ToolDefs {
		names = append(names, t.Function.Name)
	}
	return strings.Join(names, ", ")
}

func (a *Agent) listDir(dir string) string {
	full := dir
	if !filepath.IsAbs(full) {
		full = filepath.Join(a.workdir, dir)
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		return "error: " + err.Error()
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%d entries in %s:\n", len(entries), full)
	for _, e := range entries {
		info, ierr := e.Info()
		size := ""
		if ierr == nil {
			size = fmt.Sprintf(" %d B", info.Size())
		}
		mark := ""
		if e.IsDir() {
			mark = "/"
		}
		fmt.Fprintf(&sb, "  %s%s%s\n", e.Name(), mark, size)
	}
	return truncate(sb.String(), MaxToolOutput)
}

func (a *Agent) readFile(path string) string {
	if path == "" {
		return "error: missing 'path' argument"
	}
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(a.workdir, path)
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return "error: " + err.Error()
	}
	return truncate(string(data), MaxFileRead)
}

func (a *Agent) writeFile(path, content string) string {
	if path == "" {
		return "error: missing 'path' argument"
	}
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(a.workdir, path)
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return "error: " + err.Error()
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		return "error: " + err.Error()
	}
	return fmt.Sprintf("wrote %d bytes to %s", len(content), full)
}

func (a *Agent) cd(path string) string {
	if path == "" {
		return "error: missing 'path' argument"
	}
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(a.workdir, path)
	}
	full = filepath.Clean(full)
	info, err := os.Stat(full)
	if err != nil {
		return "error: " + err.Error()
	}
	if !info.IsDir() {
		return "error: not a directory: " + full
	}
	a.workdir = full
	return "changed working directory to " + full
}

func (a *Agent) grep(pattern string) string {
	if pattern == "" {
		return "error: missing 'pattern' argument"
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "error: invalid regex: " + err.Error()
	}
	var sb strings.Builder
	matches := 0
	_ = filepath.Walk(a.workdir, func(path string, info os.FileInfo, err error) error {
		if err != nil || matches >= 30 {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", ".venv", "venv", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}
		if info.Size() > 1<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if bytes.Contains(data, []byte{0}) {
			return nil
		}
		for i, ln := range strings.Split(string(data), "\n") {
			if re.MatchString(ln) {
				rel, _ := filepath.Rel(a.workdir, path)
				fmt.Fprintf(&sb, "%s:%d: %s\n", rel, i+1, strings.TrimSpace(truncate(ln, 160)))
				matches++
				if matches >= 30 {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	if sb.Len() == 0 {
		return "no matches found for pattern: " + pattern
	}
	return truncate(sb.String(), MaxToolOutput)
}

func (a *Agent) readMemory() string {
	data, err := os.ReadFile(a.memoryPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (a *Agent) learn(note string) string {
	if note == "" {
		return "error: missing 'note' argument"
	}
	if err := os.MkdirAll(filepath.Dir(a.memoryPath), 0o755); err != nil {
		return "error: " + err.Error()
	}
	f, err := os.OpenFile(a.memoryPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "error: " + err.Error()
	}
	defer f.Close()
	entry := "- " + strings.TrimSpace(note)
	if !strings.HasSuffix(entry, "\n") {
		entry += "\n"
	}
	if _, err := f.WriteString(entry); err != nil {
		return "error: " + err.Error()
	}
	return "Saved to long-term memory: " + strings.TrimSpace(note)
}

func (a *Agent) recall() string {
	if mem := a.readMemory(); mem != "" {
		return truncate(mem, MaxToolOutput)
	}
	return "Memory is empty. Use the learn tool to store facts and preferences."
}

func (a *Agent) systemInfo() string {
	si := a.detectSystem()
	var sb strings.Builder
	if si.Hostname != "" {
		fmt.Fprintf(&sb, "hostname: %s\n", si.Hostname)
	}
	fmt.Fprintf(&sb, "os: %s %s\n", si.OS, si.Arch)
	if si.Distro != "" {
		fmt.Fprintf(&sb, "distro: %s\n", si.Distro)
	}
	if si.Kernel != "" {
		fmt.Fprintf(&sb, "kernel: %s\n", si.Kernel)
	}
	fmt.Fprintf(&sb, "shell: %s\n", si.Shell)
	if si.PackageMgr != "" {
		fmt.Fprintf(&sb, "package manager: %s\n", si.PackageMgr)
	}
	fmt.Fprintf(&sb, "privileges: %s\n", si.Privileges)
	for _, cmd := range []string{"go version", "python --version", "node --version", "git --version", "curl --version", "nmap --version"} {
		if out, ok := a.tryRun(cmd); ok {
			line := strings.TrimSpace(strings.Split(out, "\n")[0])
			if line != "" {
				sb.WriteString(line + "\n")
			}
		}
	}
	return truncate(sb.String(), MaxToolOutput)
}

type SystemInfo struct {
	OS         string
	Arch       string
	Kernel     string
	Distro     string
	Shell      string
	PackageMgr string
	Privileges string
	Hostname   string
}

func (a *Agent) detectSystem() SystemInfo {
	si := SystemInfo{
		OS:     runtime.GOOS,
		Arch:   runtime.GOARCH,
		Shell:  shellFor(runtime.GOOS),
		Hostname: hostname(),
	}
	si.Privileges = a.detectPrivileges()
	switch runtime.GOOS {
	case "windows":
		if out, ok := a.tryRun("cmd /c ver"); ok {
			si.Kernel = strings.TrimSpace(out)
		}
		si.PackageMgr = detectWindowsPkgMgr()
	case "darwin":
		if out, ok := a.tryRun("uname -r"); ok {
			si.Kernel = strings.TrimSpace(out)
		}
		if out, ok := a.tryRun("sw_vers -productVersion"); ok {
			si.Distro = "macOS " + strings.TrimSpace(out)
		}
		si.PackageMgr = "brew"
	default:
		if out, ok := a.tryRun("uname -r"); ok {
			si.Kernel = strings.TrimSpace(out)
		}
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			id, name, version := parseOSRelease(string(data))
			si.Distro = name
			if version != "" {
				si.Distro += " " + version
			}
			si.PackageMgr = pkgMgrForDistro(id)
		}
	}
	return si
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

func shellFor(goos string) string {
	switch goos {
	case "windows":
		return "PowerShell"
	case "darwin":
		return "zsh"
	default:
		return "bash"
	}
}

func parseOSRelease(content string) (id, name, version string) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch key {
		case "ID":
			id = val
		case "NAME":
			name = val
		case "VERSION_ID":
			version = val
		case "PRETTY_NAME":
			if name == "" {
				name = val
			}
		}
	}
	if name == "" {
		name = id
	}
	return id, name, version
}

func pkgMgrForDistro(id string) string {
	switch id {
	case "arch", "manjaro", "endeavouros", "cachyos":
		return "pacman"
	case "debian", "ubuntu", "kali", "linuxmint", "pop", "raspbian":
		return "apt"
	case "fedora", "rocky", "centos", "rhel", "almalinux":
		return "dnf"
	case "alpine":
		return "apk"
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed", "suse":
		return "zypper"
	case "void":
		return "xbps"
	case "nixos":
		return "nix"
	}
	return ""
}

func detectWindowsPkgMgr() string {
	home := os.Getenv("USERPROFILE")
	if home != "" {
		if _, err := os.Stat(filepath.Join(home, "scoop")); err == nil {
			return "scoop"
		}
	}
	pd := os.Getenv("ProgramData")
	if pd != "" {
		if _, err := os.Stat(filepath.Join(pd, "chocolatey")); err == nil {
			return "choco"
		}
	}
	return "winget (if available)"
}

func (a *Agent) projectInfo() string {
	var sb strings.Builder
	for _, f := range []string{"go.mod", "package.json", "requirements.txt", "pyproject.toml", "Cargo.toml", "composer.json", "Dockerfile", "docker-compose.yml", "README.md"} {
		data, err := os.ReadFile(filepath.Join(a.workdir, f))
		if err != nil {
			continue
		}
		fmt.Fprintf(&sb, "=== %s ===\n%s\n\n", f, truncate(string(data), 4000))
	}
	if sb.Len() == 0 {
		return "No project manifest found (go.mod, package.json, requirements.txt, etc.). Listing root files may help."
	}
	return truncate(sb.String(), MaxToolOutput)
}

func (a *Agent) httpRequest(rawArgs string) string {
	var args struct {
		URL     string            `json:"url"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}
	if err := json.Unmarshal([]byte(rawArgs), &args); err != nil {
		return "error: invalid tool arguments: " + err.Error()
	}
	if args.URL == "" {
		return "error: missing 'url' argument"
	}
	method := strings.ToUpper(strings.TrimSpace(args.Method))
	if method == "" {
		method = http.MethodGet
	}
	var rdr io.Reader
	if args.Body != "" {
		rdr = strings.NewReader(args.Body)
	}
	req, err := http.NewRequest(method, args.URL, rdr)
	if err != nil {
		return "error: " + err.Error()
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range args.Headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 100<<10))
	if err != nil {
		return "error: " + err.Error()
	}
	ct := resp.Header.Get("Content-Type")
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP %d %s\nContent-Type: %s\n", resp.StatusCode, http.StatusText(resp.StatusCode), ct)
	if strings.Contains(ct, "json") || strings.Contains(ct, "text") || strings.Contains(ct, "xml") ||
		strings.Contains(ct, "html") || strings.Contains(ct, "javascript") || strings.Contains(ct, "urlencoded") {
		sb.WriteString(string(data))
	} else if len(data) > 64 && bytes.Contains(data[:64], []byte{0}) {
		fmt.Fprintf(&sb, "<binary response, %d bytes>", len(data))
	} else {
		sb.WriteString(string(data))
	}
	return truncate(sb.String(), MaxToolOutput)
}

func (a *Agent) mkdir(path string) string {
	if path == "" {
		return "error: missing 'path' argument"
	}
	full := path
	if !filepath.IsAbs(full) {
		full = filepath.Join(a.workdir, path)
	}
	if err := os.MkdirAll(full, 0o755); err != nil {
		return "error: " + err.Error()
	}
	return fmt.Sprintf("created directory %s", full)
}

func (a *Agent) runCommand(command string) string {
	if command == "" {
		return "error: missing 'command' argument"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", command)
	} else {
		sh := "sh"
		if _, err := exec.LookPath("bash"); err == nil {
			sh = "bash"
		} else if _, err := exec.LookPath("zsh"); err == nil {
			sh = "zsh"
		}
		cmd = exec.CommandContext(ctx, sh, "-c", command)
	}
	cmd.Dir = a.workdir
	out, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return "error: command timed out after 60 seconds\n" + truncate(string(out), MaxToolOutput)
	}
	if err != nil {
		return fmt.Sprintf("error: command exited with: %v\n%s", err, truncate(string(out), MaxToolOutput))
	}
	return truncate(string(out), MaxToolOutput)
}

func (a *Agent) detectPrivileges() string {
	if runtime.GOOS == "windows" {
		out, ok := a.tryRun("(New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
		if ok && strings.TrimSpace(out) == "True" {
			return "admin (elevated)"
		}
		return "user (UAC elevation available via run_elevated)"
	}
	if currentUserIsRoot() {
		return "root (full access)"
	}
	if out, ok := a.tryRun("sudo -n true"); ok {
		_ = out
		return "user (passwordless sudo available)"
	}
	if out, ok := a.tryRun("doas -n true"); ok {
		_ = out
		return "user (passwordless doas available)"
	}
	return "user (no passwordless sudo - run AREX as root for full access)"
}

func (a *Agent) runElevated(command string) string {
	if command == "" {
		return "error: missing 'command' argument"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if runtime.GOOS == "windows" {
		return a.runElevatedWindows(ctx, command)
	}
	return a.runElevatedUnix(ctx, command)
}

func (a *Agent) runElevatedWindows(ctx context.Context, command string) string {
	tmpOut := filepath.Join(os.TempDir(), fmt.Sprintf("arex-elev-%d.txt", time.Now().UnixNano()))
	script := filepath.Join(os.TempDir(), fmt.Sprintf("arex-elev-%d.ps1", time.Now().UnixNano()))
	defer os.Remove(script)
	defer os.Remove(tmpOut)
	content := fmt.Sprintf("& { %s *> %q }\nexit $LASTEXITCODE\n", command, tmpOut)
	if err := os.WriteFile(script, []byte(content), 0o600); err != nil {
		return "error: " + err.Error()
	}
	ps := fmt.Sprintf("Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','%s'; exit $LASTEXITCODE", strings.ReplaceAll(script, "'", "''"))
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", ps)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("error: elevation failed (UAC cancelled or denied): %v\n%s", err, truncate(string(out), MaxToolOutput))
	}
	data, rerr := os.ReadFile(tmpOut)
	if rerr != nil {
		return fmt.Sprintf("error: elevated command ran but produced no output: %v", rerr)
	}
	return truncate(string(data), MaxToolOutput)
}

func (a *Agent) runElevatedUnix(ctx context.Context, command string) string {
	if currentUserIsRoot() {
		return a.runCommand(command)
	}
	runner := ""
	if _, ok := a.tryRun("sudo -n true"); ok {
		runner = "sudo"
	} else if _, ok := a.tryRun("doas -n true"); ok {
		runner = "doas"
	}
	if runner == "" {
		return "error: not root and no passwordless sudo/doas available. Run AREX as root or configure passwordless sudo."
	}
	cmd := exec.CommandContext(ctx, runner, "-n", "sh", "-c", command)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return "error: elevated command timed out after 60 seconds\n" + truncate(string(out), MaxToolOutput)
	}
	if err != nil {
		return fmt.Sprintf("error: elevated command exited with: %v\n%s", err, truncate(string(out), MaxToolOutput))
	}
	return truncate(string(out), MaxToolOutput)
}

func (a *Agent) tryRun(command string) (string, bool) {
	out := a.runCommand(command)
	if strings.HasPrefix(out, "error:") {
		return "", false
	}
	return out, true
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n...[truncated]"
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

func (a *Agent) webSearch(query string) string {
	if query == "" {
		return "error: missing 'query' argument"
	}
	// Try multiple engines until one returns results: html search, Bing RSS,
	// DDG lite, Mojeek, DDG instant-answer API, then Wikipedia for definitions.
	engines := []struct {
		name string
		run  func(string) string
	}{
		{"duckduckgo", a.ddgSearch},
		{"bing", a.bingSearch},
		{"duckduckgo lite", a.ddgLiteSearch},
		{"mojeek", a.mojeekSearch},
		{"duckduckgo instant", a.ddgInstant},
		{"wikipedia", a.wikiSearch},
	}
	for _, e := range engines {
		if out := e.run(query); out != "" {
			return "### " + e.name + " results for: " + query + "\n\n" + out
		}
	}
	return "error: web search returned no results for: " + query + " (all engines blocked or empty)"
}

type searchResult struct {
	title   string
	url     string
	snippet string
}

func (r searchResult) String() string {
	return r.title + "\n  " + r.url + "\n  " + r.snippet
}

func formatResults(results []searchResult) string {
	var sb strings.Builder
	for i, r := range results {
		fmt.Fprintf(&sb, "%d. %s\n   %s\n   %s\n\n", i+1, r.title, r.url, r.snippet)
	}
	return truncate(strings.TrimRight(sb.String(), "\n"), MaxToolOutput)
}

func cleanSnippet(s string) string {
	s = html.UnescapeString(s)
	s = strings.Join(strings.Fields(s), " ")
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}

// httpGetBytes fetches a URL with a browser User-Agent, returns body or "" on failure.
func httpGetBytes(rawURL string, maxBytes int64) []byte {
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil
	}
	return body
}

func (a *Agent) ddgSearch(query string) string {
	body := httpGetBytes("https://html.duckduckgo.com/html/?q="+url.QueryEscape(query), 2<<20)
	if len(body) == 0 {
		return ""
	}

	seen := map[string]bool{}
	var results []searchResult
	for _, part := range strings.Split(string(body), `class="result__a"`)[1:] {
		if len(results) >= 5 {
			break
		}
		hrefStart := strings.Index(part, `href="`)
		if hrefStart < 0 {
			continue
		}
		rest := part[hrefStart+6:]
		hrefEnd := strings.IndexByte(rest, '"')
		if hrefEnd < 0 {
			continue
		}
		href := rest[:hrefEnd]
		titleStart := strings.IndexByte(rest, '>')
		titleEnd := strings.Index(rest, `</a>`)
		if titleStart < 0 || titleEnd < titleStart {
			continue
		}
		title := cleanSnippet(stripHTML(rest[titleStart+1 : titleEnd]))
		snippet := ""
		if sIdx := strings.Index(part, `class="result__snippet"`); sIdx >= 0 {
			sp := part[sIdx:]
			st := strings.IndexByte(sp, '>')
			se := strings.Index(sp, `</a>`)
			if st >= 0 && se > st {
				snippet = cleanSnippet(stripHTML(sp[st+1 : se]))
			}
		}
		u := decodeDDGLink(href)
		if u == "" || seen[u] || title == "" {
			continue
		}
		seen[u] = true
		results = append(results, searchResult{title: title, url: u, snippet: snippet})
	}
	if len(results) == 0 {
		return ""
	}
	return formatResults(results)
}

func (a *Agent) bingSearch(query string) string {
	body := httpGetBytes("https://www.bing.com/search?q="+url.QueryEscape(query)+"&format=rss&count=8", 1<<20)
	if len(body) == 0 {
		return ""
	}
	results := parseBingRSS(body)
	if len(results) == 0 {
		return ""
	}
	return formatResults(results)
}

func parseBingRSS(body []byte) []searchResult {
	var feed struct {
		Channel struct {
			Items []struct {
				Title       string `xml:"title"`
				Link        string `xml:"link"`
				Description string `xml:"description"`
			} `xml:"item"`
		} `xml:"channel"`
	}
	if err := xml.Unmarshal(body, &feed); err != nil || len(feed.Channel.Items) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var results []searchResult
	for _, it := range feed.Channel.Items {
		if len(results) >= 8 {
			break
		}
		u := strings.TrimSpace(it.Link)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		results = append(results, searchResult{title: cleanSnippet(it.Title), url: u, snippet: cleanSnippet(it.Description)})
	}
	return results
}

func (a *Agent) ddgLiteSearch(query string) string {
	body := httpGetBytes("https://lite.duckduckgo.com/lite/?q="+url.QueryEscape(query), 1<<20)
	if len(body) == 0 {
		return ""
	}
	s := string(body)
	seen := map[string]bool{}
	var results []searchResult
	for _, part := range strings.Split(s, `<a rel="nofollow" href="`)[1:] {
		if len(results) >= 8 {
			break
		}
		hrefEnd := strings.IndexByte(part, '"')
		if hrefEnd < 0 {
			continue
		}
		u := part[:hrefEnd]
		rest := part[hrefEnd+1:]
		titleEnd := strings.Index(rest, `</a>`)
		if titleEnd < 0 {
			continue
		}
		title := cleanSnippet(stripHTML(rest[:titleEnd]))
		if u == "" || seen[u] || title == "" {
			continue
		}
		seen[u] = true
		snippet := ""
		if sIdx := strings.Index(rest, `class="result-snippet"`); sIdx >= 0 {
			sp := rest[sIdx:]
			st := strings.IndexByte(sp, '>')
			se := strings.Index(sp, `</td>`)
			if st >= 0 && se > st {
				snippet = cleanSnippet(stripHTML(sp[st+1 : se]))
			}
		}
		results = append(results, searchResult{title: title, url: u, snippet: snippet})
	}
	if len(results) == 0 {
		return ""
	}
	return formatResults(results)
}

func (a *Agent) mojeekSearch(query string) string {
	body := httpGetBytes("https://www.mojeek.com/search?q="+url.QueryEscape(query), 1<<20)
	if len(body) == 0 {
		return ""
	}
	s := string(body)
	seen := map[string]bool{}
	var results []searchResult
	for _, part := range strings.Split(s, `class="ob"`)[1:] {
		if len(results) >= 8 {
			break
		}
		hrefStart := strings.Index(part, `href="`)
		if hrefStart < 0 {
			continue
		}
		rest := part[hrefStart+6:]
		hrefEnd := strings.IndexByte(rest, '"')
		if hrefEnd < 0 {
			continue
		}
		u := rest[:hrefEnd]
		titleStart := strings.IndexByte(rest, '>')
		titleEnd := strings.Index(rest, `</a>`)
		if titleStart < 0 || titleEnd < titleStart {
			continue
		}
		title := cleanSnippet(stripHTML(rest[titleStart+1 : titleEnd]))
		if u == "" || seen[u] || title == "" {
			continue
		}
		seen[u] = true
		snippet := ""
		if sIdx := strings.Index(rest, `class="s"`); sIdx >= 0 {
			sp := rest[sIdx:]
			st := strings.IndexByte(sp, '>')
			se := strings.Index(sp, `</p>`)
			if st >= 0 && se > st {
				snippet = cleanSnippet(stripHTML(sp[st+1 : se]))
			}
		}
		results = append(results, searchResult{title: title, url: u, snippet: snippet})
	}
	if len(results) == 0 {
		return ""
	}
	return formatResults(results)
}

func (a *Agent) wikiSearch(query string) string {
	body := httpGetBytes("https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch="+url.QueryEscape(query)+"&format=json&srlimit=3&prop=snippet&srprop=snippet", 1<<20)
	if len(body) == 0 {
		return ""
	}
	var out struct {
		Query struct {
			Search []struct {
				Title   string `json:"title"`
				Snippet string `json:"snippet"`
			} `json:"search"`
		} `json:"query"`
	}
	if err := json.Unmarshal(body, &out); err != nil || len(out.Query.Search) == 0 {
		return ""
	}
	var results []searchResult
	for _, s := range out.Query.Search {
		u := "https://en.wikipedia.org/wiki/" + url.PathEscape(strings.ReplaceAll(s.Title, " ", "_"))
		results = append(results, searchResult{title: "Wikipedia: " + s.Title, url: u, snippet: cleanSnippet(s.Snippet)})
	}
	return formatResults(results)
}

func (a *Agent) ddgInstant(query string) string {
	body := httpGetBytes("https://api.duckduckgo.com/?q="+url.QueryEscape(query)+"&format=json&no_html=1&skip_disambig=1", 1<<20)
	if len(body) == 0 {
		return ""
	}
	var out struct {
		Abstract    string `json:"Abstract"`
		AbstractURL string `json:"AbstractURL"`
		Heading     string `json:"Heading"`
		Results     []struct {
			Text     string `json:"Text"`
			FirstURL string `json:"FirstURL"`
		} `json:"Results"`
		RelatedTopics []json.RawMessage `json:"RelatedTopics"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return ""
	}

	var results []searchResult
	seen := map[string]bool{}
	add := func(text, u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		results = append(results, searchResult{title: cleanSnippet(text), url: u})
	}
	if out.Abstract != "" {
		return fmt.Sprintf("## %s\n%s\nSource: %s", out.Heading, out.Abstract, out.AbstractURL)
	}
	for _, r := range out.Results {
		add(r.Text, r.FirstURL)
	}
	type related struct {
		Text     string `json:"Text"`
		FirstURL string `json:"FirstURL"`
		Topics   []struct {
			Text     string `json:"Text"`
			FirstURL string `json:"FirstURL"`
		} `json:"Topics"`
	}
	for _, raw := range out.RelatedTopics {
		var t related
		if json.Unmarshal(raw, &t) != nil {
			continue
		}
		if len(t.Topics) > 0 {
			for _, tt := range t.Topics {
				add(tt.Text, tt.FirstURL)
			}
		} else if t.Text != "" {
			add(t.Text, t.FirstURL)
		}
	}
	if len(results) == 0 {
		return ""
	}
	return formatResults(results)
}

func (a *Agent) fetchURL(rawURL string) string {
	if rawURL == "" {
		return "error: missing 'url' argument"
	}
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		return "error: url must start with http:// or https://"
	}
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "error: " + err.Error()
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return "error: " + err.Error()
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "error: " + err.Error()
	}
	if resp.StatusCode >= 400 {
		return fmt.Sprintf("error: HTTP %d %s\n%s", resp.StatusCode, resp.Status, truncate(htmlToText(string(body)), 2000))
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "image/") || strings.HasPrefix(ct, "application/pdf") || strings.HasPrefix(ct, "application/zip") ||
		strings.HasPrefix(ct, "application/octet-stream") || strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/") {
		return fmt.Sprintf("content-type: %s (%d bytes) - not a readable text page", ct, len(body))
	}
	if len(body) > 64 && bytes.Contains(body[:64], []byte{0}) {
		return fmt.Sprintf("content-type: %s (%d bytes) - appears to be binary data", ct, len(body))
	}
	text := extractArticleText(string(body))
	if text == "" {
		text = htmlToText(string(body))
	}
	return truncate(text, 12000)
}

var pageSkipTags = map[string]bool{
	"script": true, "style": true, "nav": true, "footer": true, "header": true,
	"aside": true, "form": true, "svg": true, "iframe": true, "noscript": true,
	"button": true, "select": true, "option": true, "template": true, "canvas": true,
}

var pageBreakTags = map[string]bool{
	"p": true, "div": true, "li": true, "tr": true, "br": true, "h1": true,
	"h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "section": true,
	"article": true, "blockquote": true, "pre": true, "table": true, "ul": true,
	"ol": true, "td": true, "th": true, "hr": true, "dl": true, "dt": true, "dd": true,
}

func htmlToText(s string) string {
	z := xhtml.NewTokenizer(strings.NewReader(s))
	var sb strings.Builder
	skipDepth := 0
	inPre := false
	for {
		tt := z.Next()
		switch tt {
		case xhtml.ErrorToken:
			if z.Err() == io.EOF {
				return postCleanText(sb.String())
			}
			return ""
		case xhtml.StartTagToken, xhtml.SelfClosingTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if pageSkipTags[tag] {
				if tt == xhtml.StartTagToken {
					skipDepth++
				}
			}
			if tag == "pre" {
				inPre = true
			}
			if pageBreakTags[tag] {
				sb.WriteByte('\n')
			}
		case xhtml.EndTagToken:
			name, _ := z.TagName()
			tag := string(name)
			if pageSkipTags[tag] && skipDepth > 0 {
				skipDepth--
			}
			if tag == "pre" {
				inPre = false
			}
		case xhtml.TextToken:
			if skipDepth > 0 {
				continue
			}
			t := string(z.Text())
			if !inPre {
				t = reSpace.ReplaceAllString(t, " ")
			}
			sb.WriteString(t)
		}
	}
}

func postCleanText(s string) string {
	s = html.UnescapeString(s)
	s = reSpace.ReplaceAllString(s, " ")
	s = reBlank.ReplaceAllString(s, "\n\n")
	s = strings.ReplaceAll(s, " \n", "\n")
	s = strings.ReplaceAll(s, "\n ", "\n")
	return strings.TrimSpace(s)
}

// extractArticleText finds the main article/content region of a page (article,
// main, or an element with id/class hinting at content) and returns its text.
// Returns "" if no strong candidate is found.
func extractArticleText(s string) string {
	doc, err := xhtml.Parse(strings.NewReader(s))
	if err != nil {
		return ""
	}
	var best *xhtml.Node
	bestScore := 0
	var walk func(n *xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.ElementNode {
			id, cls := "", ""
			for _, a := range n.Attr {
				switch a.Key {
				case "id":
					id = a.Val
				case "class":
					cls = a.Val
				}
			}
			lower := strings.ToLower(n.Data + " " + id + " " + cls)
			isMain := n.Data == "article" || n.Data == "main" ||
				strings.Contains(lower, "content") || strings.Contains(lower, "article")
			if isMain {
				if score := nodeTextLen(n); score > bestScore {
					bestScore = score
					best = n
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if best == nil || bestScore < 300 {
		return ""
	}
	var sb strings.Builder
	renderNode(best, &sb)
	return postCleanText(sb.String())
}

func nodeTextLen(n *xhtml.Node) int {
	var count int
	var walk func(n *xhtml.Node)
	walk = func(n *xhtml.Node) {
		if n.Type == xhtml.TextNode {
			count += len(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return count
}

func renderNode(n *xhtml.Node, sb *strings.Builder) {
	switch n.Type {
	case xhtml.TextNode:
		sb.WriteString(n.Data)
		return
	case xhtml.ElementNode:
		tag := n.Data
		if pageSkipTags[tag] {
			return
		}
		if pageBreakTags[tag] {
			sb.WriteByte('\n')
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		renderNode(c, sb)
	}
}

func decodeDDGLink(href string) string {
	if i := strings.Index(href, "uddg="); i >= 0 {
		rest := href[i+5:]
		if j := strings.IndexAny(rest, "&"); j >= 0 {
			rest = rest[:j]
		}
		if u, err := url.QueryUnescape(rest); err == nil {
			return u
		}
	}
	return href
}

var (
	reScript = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	reStyle  = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	reTags   = regexp.MustCompile(`(?s)<[^>]+>`)
	reSpace  = regexp.MustCompile(`[ \t\r\f\v]+`)
	reBlank  = regexp.MustCompile(`\n{3,}`)
)

func stripHTML(s string) string {
	s = reScript.ReplaceAllString(s, " ")
	s = reStyle.ReplaceAllString(s, " ")
	s = reTags.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	s = reSpace.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, " \n", "\n")
	s = strings.ReplaceAll(s, "\n ", "\n")
	s = reBlank.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

func parseJSONToolCalls(content string) ([]ollama.ToolCall, string) {
	var calls []ollama.ToolCall
	var cleaned strings.Builder
	rest := content
	for len(rest) > 0 {
		idx := strings.IndexByte(rest, '{')
		if idx < 0 {
			cleaned.WriteString(rest)
			break
		}
		cleaned.WriteString(rest[:idx])
		rest = rest[idx:]
		depth := 0
		end := -1
		inStr := false
		esc := false
		for i := 0; i < len(rest); i++ {
			c := rest[i]
			if inStr {
				if esc {
					esc = false
					continue
				}
				if c == '\\' {
					esc = true
					continue
				}
				if c == '"' {
					inStr = false
				}
				continue
			}
			switch c {
			case '"':
				inStr = true
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i + 1
					i = len(rest)
				}
			}
		}
		if end < 0 {
			cleaned.WriteString(rest)
			break
		}
		obj := rest[:end]
		rest = rest[end:]
		var m struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal([]byte(fixJSONEscapes(obj)), &m); err == nil && m.Name != "" {
			argsJSON, _ := json.Marshal(m.Arguments)
			var tc ollama.ToolCall
			tc.Function.Name = m.Name
			tc.Function.Arguments = json.RawMessage(argsJSON)
			calls = append(calls, tc)
		} else {
			cleaned.WriteString(obj)
		}
	}
	return calls, stripFences(cleaned.String())
}

func stripFences(s string) string {
	var lines []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "```") {
			continue
		}
		lines = append(lines, ln)
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

func fixJSONEscapes(s string) string {
	var sb strings.Builder
	sb.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			switch s[i+1] {
			case '\\', '"', 'u':
				// real JSON escapes, keep as-is
			default:
				sb.WriteByte('\\')
			}
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func isPlaceholderReply(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" {
		return true
	}
	lt := strings.ToLower(t)
	if strings.Contains(lt, "<tool_response>") {
		return true
	}
	if strings.HasPrefix(lt, "tool result for ") {
		return true
	}
	return false
}

func markTruncation(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return s
	}
	last := t[len(t)-1]
	if strings.ContainsRune(".!?`)}]\"", rune(last)) {
		return s
	}
	return s + "\n\n_*(reply may have been cut off - ask me to continue)*_"
}
