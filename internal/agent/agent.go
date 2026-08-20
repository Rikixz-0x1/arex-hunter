package agent

import (
	"bytes"
	"context"
	"encoding/json"
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
			Description: "Search the web for information. Returns up to 8 results with title, URL and snippet. Use for OSINT, researching CVEs and vulnerabilities, finding documentation, PoCs, write-ups and exploits.",
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
			Description: "Fetch a URL and return its readable text content. Use for reading web pages, documentation, API responses, advisories and reports. Returns content truncated at 12000 characters.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url": map[string]any{"type": "string", "description": "Full URL to fetch, e.g. https://example.com/page"},
				},
				"required": []string{"url"},
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
	client   *ollama.Client
	workdir  string
	callbacks Callbacks
	system   string
}

func New(client *ollama.Client, workdir string, cb Callbacks) *Agent {
	shell := "sh"
	if runtime.GOOS == "windows" {
		shell = "PowerShell"
	}
	system := fmt.Sprintf(`You are AREX, an autonomous cyber security researcher and developer agent running inside a terminal. The user works in the directory %q. The shell for commands is %s.
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

To call a tool, output a single JSON object with "name" and "arguments" fields, nothing else. For example:
{"name": "web_search", "arguments": {"query": "CVE-2024-1234 exploit"}}
After receiving the tool result, continue working or answer.`, workdir, shell)
	return &Agent{client: client, workdir: workdir, callbacks: cb, system: system}
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
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
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
	if out := a.ddgSearch(query); out != "" {
		return out
	}
	if out := a.ddgInstant(query); out != "" {
		return out
	}
	return "error: web search returned no results (search engine may have blocked the request)"
}

func (a *Agent) ddgSearch(query string) string {
	client := &http.Client{Timeout: 20 * time.Second}
	req, err := http.NewRequest(http.MethodGet, "https://html.duckduckgo.com/html/?q="+url.QueryEscape(query), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}

	parts := strings.Split(string(body), `class="result__a"`)
	if len(parts) < 2 {
		return ""
	}
	type entry struct{ title, url, snippet string }
	seen := map[string]bool{}
	var entries []entry
	for i := 1; i < len(parts) && len(entries) < 5; i++ {
		part := parts[i]
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
		title := strings.TrimSpace(stripHTML(rest[titleStart+1 : titleEnd]))
		snippet := ""
		if sIdx := strings.Index(part, `class="result__snippet"`); sIdx >= 0 {
			sp := part[sIdx:]
			st := strings.IndexByte(sp, '>')
			se := strings.Index(sp, `</a>`)
			if st >= 0 && se > st {
				snippet = strings.TrimSpace(stripHTML(sp[st+1 : se]))
			}
		}
		u := decodeDDGLink(href)
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		entries = append(entries, entry{title: title, url: u, snippet: snippet})
	}
	var sb strings.Builder
	for i, e := range entries {
		fmt.Fprintf(&sb, "%d. %s\n   %s\n   %s\n\n", i+1, e.title, e.url, e.snippet)
	}
	if sb.Len() == 0 {
		return ""
	}
	return truncate(sb.String(), MaxToolOutput)
}

func (a *Agent) ddgInstant(query string) string {
	client := &http.Client{Timeout: 20 * time.Second}
	u := "https://api.duckduckgo.com/?q=" + url.QueryEscape(query) + "&format=json&no_html=1&skip_disambig=1"
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "arex-agent/0.1")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
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
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ""
	}

	var sb strings.Builder
	seen := map[string]bool{}
	add := func(text, u string) {
		if u == "" || seen[u] {
			return
		}
		seen[u] = true
		fmt.Fprintf(&sb, "- %s\n  %s\n", text, u)
	}
	if out.Abstract != "" {
		fmt.Fprintf(&sb, "## %s\n%s\nSource: %s\n\n", out.Heading, out.Abstract, out.AbstractURL)
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
	if sb.Len() == 0 {
		return ""
	}
	return truncate(sb.String(), MaxToolOutput)
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
		return fmt.Sprintf("error: HTTP %d\n%s", resp.StatusCode, truncate(stripHTML(string(body)), 2000))
	}
	return truncate(stripHTML(string(body)), 12000)
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