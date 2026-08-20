package ui

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"

	"arex/internal/agent"
	"arex/internal/ollama"
)

const (
	headerH = 2
	hintH   = 1
	brandH  = 1
)

type Config struct {
	Model   string
	Host    string
	Dir     string
	Version string
	Options ollama.Options
}

type msgKind int

const (
	kindUser msgKind = iota
	kindAI
	kindTool
	kindError
)

type item struct {
	kind msgKind
	raw  string
}

type Model struct {
	cfg      Config
	agent    *agent.Agent
	program  *tea.Program
	spinner  spinner.Model
	viewport viewport.Model
	input    textarea.Model
	md       *glamour.TermRenderer

	items    []item
	rendered []string
	history  []ollama.Message

	streamingRaw string
	streamingIdx int
	toolIdx      int

	busy   bool
	stopped bool
	ctx    context.Context
	cancel context.CancelFunc
	width  int
	height int

	session int

	// token stats
	totalPrompt  int64
	totalEval    int64
	rate         float64
	lastEval     int64
	lastChunkAt  time.Time

	// model picker
	pickerOpen bool
	models     []string
	modelIdx   int
}

type chunkMsg struct {
	delta     string
	evalCount int64
}
type toolMsg struct {
	name  string
	args  string
	start bool
	err   error
}
type doneMsg struct {
	reply   string
	history []ollama.Message
	stats   ollama.Stats
	err     error
}
type modelCheckMsg struct{ err error }
type modelsMsg struct {
	names []string
	err   error
}

func New(cfg Config) *Model {
	client := ollama.New(cfg.Host, cfg.Model, cfg.Options)
	if cfg.Version == "" {
		cfg.Version = "dev"
	}
	wd := cfg.Dir
	if wd == "" {
		wd, _ = os.Getwd()
	}

	m := &Model{
		cfg:          cfg,
		session:      1,
		streamingIdx: -1,
		toolIdx:      -1,
		history:      []ollama.Message{},
		models:       []string{cfg.Model},
	}

	m.agent = agent.New(client, wd, m.agentCallbacks())

	m.spinner = spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(statusBusyStyle))

	m.input = textarea.New()
	m.input.Placeholder = "Ask AREX to build, fix, explain, or run something in this project..."
	m.input.Prompt = "❯ "
	m.input.ShowLineNumbers = false
	m.input.SetHeight(3)
	m.input.FocusedStyle.CursorLine = lipgloss.NewStyle()
	m.input.FocusedStyle.Prompt = userLabelStyle
	m.input.BlurredStyle.Prompt = userLabelStyle
	m.input.KeyMap.InsertNewline = key.NewBinding(key.WithKeys("ctrl+j"))
	m.input.CharLimit = 0
	m.input.Focus()

	m.viewport = viewport.New(0, 0)
	m.viewport.MouseWheelEnabled = true

	hero := "**AREX AI** - cyber security research agent\n" +
		"made by **Rikixz** · security researcher · [khmersec.com](https://khmersec.com) · [rikixz.dev](https://rikixz.dev)\n\n" +
		"model: `" + cfg.Model + "` via [ollama](http://localhost:11434) - fully local\n\n" +
		"tools: files · commands · `web_search` · `fetch_url` · `cd`\n\n" +
		"- `enter` send  ·  `ctrl+j` newline  ·  `ctrl+p` model picker  ·  `ctrl+l` new session  ·  `esc` stop  ·  `ctrl+c` quit\n\n" +
		"_Try: \"search for CVE-2024-1234 and fetch the advisory\"_"
	m.items = append(m.items, item{kind: kindAI, raw: hero})

	return m
}

func (m *Model) agentCallbacks() agent.Callbacks {
	return agent.Callbacks{
		OnChunk: func(d string, evalCount int64) {
			m.program.Send(chunkMsg{delta: d, evalCount: evalCount})
		},
		OnToolStart: func(name, args string) {
			m.program.Send(toolMsg{name: name, args: args, start: true})
		},
		OnToolDone: func(name, args, result string, err error) {
			m.program.Send(toolMsg{name: name, args: args, err: err})
		},
	}
}

func (m *Model) Run() error {
	m.program = tea.NewProgram(m, tea.WithAltScreen())
	_, err := m.program.Run()
	return err
}

func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		spinner.Tick,
		textarea.Blink,
		func() tea.Msg { return modelCheckMsg{err: m.agent.CheckModel()} },
	)
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - headerH - hintH - brandH - m.input.Height()
		if m.viewport.Height < 1 {
			m.viewport.Height = 1
		}
		m.input.SetWidth(msg.Width)
		m.md, _ = glamour.NewTermRenderer(glamour.WithAutoStyle(), glamour.WithWordWrap(msg.Width-6))
		m.renderAll()
		return m, nil

	case modelCheckMsg:
		if msg.err != nil {
			m.appendItem(item{kind: kindError, raw: msg.err.Error()})
		}
		return m, nil

	case modelsMsg:
		if msg.err != nil {
			m.appendItem(item{kind: kindError, raw: msg.err.Error()})
			return m, nil
		}
		m.models = msg.names
		m.modelIdx = 0
		for i, n := range m.models {
			if n == m.cfg.Model {
				m.modelIdx = i
				break
			}
		}
		m.pickerOpen = true
		m.input.Blur()
		return m, nil

	case tea.KeyMsg:
		k := msg.String()
		if m.pickerOpen {
			switch k {
			case "up", "k":
				m.modelIdx = (m.modelIdx - 1 + len(m.models)) % len(m.models)
			case "down", "j":
				m.modelIdx = (m.modelIdx + 1) % len(m.models)
			case "enter":
				if !m.busy {
					m.selectModel(m.models[m.modelIdx])
				}
				m.closePicker()
			case "esc":
				m.closePicker()
			}
			return m, nil
		}
		switch {
		case k == "ctrl+c":
			if m.busy && m.cancel != nil {
				m.cancel()
			}
			return m, tea.Quit
		case k == "ctrl+l":
			m.resetSession()
			return m, nil
		case k == "ctrl+p" || k == "tab":
			return m, m.openPicker()
		case k == "esc":
			if m.busy && m.cancel != nil {
				m.stopped = true
				m.cancel()
			}
			return m, nil
		case k == "up" || k == "down":
			if m.busy || m.input.Value() == "" {
				var cmd tea.Cmd
				m.viewport, cmd = m.viewport.Update(msg)
				return m, cmd
			}
		case k == "pgup" || k == "pgdown" || k == "home" || k == "end":
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		case !m.busy && k == "enter":
			text := strings.TrimSpace(m.input.Value())
			if text == "" {
				return m, nil
			}
			return m, m.send(text)
		case !m.busy:
			var cmd tea.Cmd
			m.input, cmd = m.input.Update(msg)
			return m, cmd
		}
		return m, nil

	case chunkMsg:
		now := time.Now()
		if !m.lastChunkAt.IsZero() {
			if dt := now.Sub(m.lastChunkAt); dt > 0 && msg.evalCount > m.lastEval {
				m.rate = float64(msg.evalCount-m.lastEval) / dt.Seconds()
			}
		}
		m.lastChunkAt = now
		m.lastEval = msg.evalCount
		if m.streamingIdx < 0 {
			m.streamingIdx = len(m.items)
			m.streamingRaw = ""
			m.appendItem(item{kind: kindAI, raw: ""})
		}
		m.streamingRaw += msg.delta
		m.updateItem(m.streamingIdx, item{kind: kindAI, raw: m.streamingRaw})
		return m, nil

	case toolMsg:
		if msg.start {
			if m.streamingIdx >= 0 {
				m.items = m.items[:m.streamingIdx]
				m.rendered = m.rendered[:m.streamingIdx]
				m.streamingIdx = -1
				m.streamingRaw = ""
			}
			shown := "⚡ " + msg.name + "(" + truncateStr(msg.args, 90) + ")"
			m.toolIdx = len(m.items)
			m.appendItem(item{kind: kindTool, raw: shown})
			return m, nil
		}
		shown := "✔ " + msg.name + "(" + truncateStr(msg.args, 90) + ")"
		if msg.err != nil {
			shown = "✖ " + msg.name + " failed - " + msg.err.Error()
		}
		if m.toolIdx >= 0 && m.toolIdx < len(m.items) {
			m.updateItem(m.toolIdx, item{kind: kindTool, raw: shown})
		}
		return m, nil

	case doneMsg:
		m.busy = false
		m.cancel = nil
		m.input.Focus()
		m.totalPrompt += msg.stats.PromptTokens
		m.totalEval += msg.stats.EvalTokens
		m.rate = 0
		if m.stopped {
			m.stopped = false
			m.streamingIdx = -1
			m.streamingRaw = ""
			m.toolIdx = -1
			m.history = msg.history
			m.appendItem(item{kind: kindTool, raw: "⏹ generation stopped by user"})
			m.viewport.GotoBottom()
			return m, nil
		}
		switch {
		case msg.err != nil:
			m.appendItem(item{kind: kindError, raw: "error: " + msg.err.Error()})
		case m.streamingIdx >= 0 && strings.TrimSpace(msg.reply) == m.streamingRaw:
			m.streamingIdx = -1
			m.streamingRaw = ""
		case strings.TrimSpace(msg.reply) == "":
			m.appendItem(item{kind: kindError, raw: "error: model returned an empty reply"})
		default:
			m.appendItem(item{kind: kindAI, raw: msg.reply})
		}
		m.history = msg.history
		m.streamingIdx = -1
		m.streamingRaw = ""
		m.toolIdx = -1
		m.viewport.GotoBottom()
		return m, nil
	}
	return m, nil
}

func (m *Model) openPicker() tea.Cmd {
	return func() tea.Msg {
		names, err := m.agent.ListModels()
		if err != nil {
			return modelsMsg{err: err}
		}
		return modelsMsg{names: names}
	}
}

func (m *Model) closePicker() {
	m.pickerOpen = false
	if !m.busy {
		m.input.Focus()
	}
}

func (m *Model) selectModel(name string) {
	if name == m.cfg.Model {
		return
	}
	client := ollama.New(m.cfg.Host, name, m.cfg.Options)
	wd := m.cfg.Dir
	if wd == "" {
		wd, _ = os.Getwd()
	}
	m.agent = agent.New(client, wd, m.agentCallbacks())
	m.cfg.Model = name
	m.appendItem(item{kind: kindAI, raw: "Switched model to **" + name + "**."})
}

func (m *Model) resetSession() {
	m.items, m.rendered = nil, nil
	m.history = nil
	m.totalPrompt, m.totalEval = 0, 0
	m.rate = 0
	m.session++
	m.syncViewport()
}

func (m *Model) handleSlash(text string) tea.Cmd {
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return nil
	}
	cmd := strings.ToLower(fields[0])
	switch cmd {
	case "/model":
		if len(fields) > 1 {
			m.selectModel(fields[1])
		} else {
			return m.openPicker()
		}
	case "/new", "/clear":
		m.resetSession()
	case "/help", "/?":
		m.appendItem(item{kind: kindAI, raw: helpReply()})
	case "/tools":
		m.appendItem(item{kind: kindAI, raw: toolsReply()})
	case "/tokens":
		m.appendItem(item{kind: kindAI, raw: fmt.Sprintf("session tokens: %s prompt + %s output = **%s** total", fmtTokens(m.totalPrompt), fmtTokens(m.totalEval), fmtTokens(m.totalPrompt+m.totalEval))})
	case "/version":
		m.appendItem(item{kind: kindAI, raw: "**arex** " + m.cfg.Version})
	case "/host":
		m.appendItem(item{kind: kindAI, raw: "ollama: `" + m.cfg.Host + "` · model: `" + m.cfg.Model + "` · dir: `" + m.cfg.Dir + "`"})
	case "/exit", "/quit":
		if m.busy && m.cancel != nil {
			m.cancel()
		}
		return tea.Quit
	default:
		m.appendItem(item{kind: kindError, raw: "unknown command " + cmd + " (try /help)"})
	}
	return nil
}

func toolsReply() string {
	return "**Available tools:**\n\n" +
		"- `list_dir` - list files in a directory\n" +
		"- `read_file` - read a file\n" +
		"- `write_file` - create or overwrite a file\n" +
		"- `mkdir` - create a directory\n" +
		"- `grep` - regex search inside files\n" +
		"- `cd` - change the working directory\n" +
		"- `run_command` - run a shell command (60s timeout)\n" +
		"- `run_elevated` - run a command as admin/root (UAC prompt on Windows, sudo/doas on Linux)\n" +
		"- `web_search` - search the web (OSINT, CVEs, docs)\n" +
		"- `fetch_url` - fetch a page's readable text\n" +
		"- `http_request` - custom HTTP calls (GET/POST/PUT/DELETE) for API & web app testing\n" +
		"- `learn` / `recall` - long-term memory (.arex-memory.md)\n" +
		"- `system_info` - OS, shell, installed tools\n" +
		"- `project_info` - project manifest & dependencies"
}

func (m *Model) send(text string) tea.Cmd {
	m.appendItem(item{kind: kindUser, raw: text})

	if strings.HasPrefix(text, "/") {
		return m.handleSlash(text)
	}

	m.history = append(m.history, ollama.Message{Role: "user", Content: text})

	if isGreeting(text) {
		m.appendItem(item{kind: kindAI, raw: greetingReply()})
		return nil
	}

	if isHelpRequest(text) {
		m.appendItem(item{kind: kindAI, raw: helpReply()})
		return nil
	}

	m.busy = true
	m.rate = 0
	m.lastChunkAt = time.Time{}
	m.lastEval = 0
	m.input.Reset()
	m.input.Blur()

	ctx, cancel := context.WithCancel(context.Background())
	m.ctx, m.cancel = ctx, cancel

	go func() {
		reply, msgs, stats, err := m.agent.Run(ctx, m.history)
		m.program.Send(doneMsg{reply: reply, history: msgs, stats: stats, err: err})
	}()
	return nil
}

func (m *Model) renderItem(it item) string {
	switch it.kind {
	case kindUser:
		return userLabelStyle.Render("❯ you") + "\n" +
			userBubbleStyle.Render(it.raw)
	case kindAI:
		if strings.TrimSpace(it.raw) == "" {
			return aiLabelStyle.Render("◆ arex")
		}
		out, err := m.md.Render(it.raw)
		if err != nil {
			return it.raw
		}
		return aiLabelStyle.Render("◆ arex") + "\n" + out
	case kindTool:
		return toolStyle.Render(it.raw)
	case kindError:
		return errStyle.Render("✖ " + it.raw)
	}
	return it.raw
}

func (m *Model) appendItem(it item) {
	m.items = append(m.items, it)
	m.rendered = append(m.rendered, m.renderItem(it))
	m.syncViewport()
}

func (m *Model) updateItem(idx int, it item) {
	if idx < 0 || idx >= len(m.items) {
		return
	}
	m.items[idx] = it
	m.rendered[idx] = m.renderItem(it)
	m.syncViewport()
}

func (m *Model) renderAll() {
	m.rendered = m.rendered[:0]
	for _, it := range m.items {
		m.rendered = append(m.rendered, m.renderItem(it))
	}
	m.syncViewport()
}

func (m *Model) syncViewport() {
	if m.rendered == nil {
		m.rendered = []string{}
	}
	m.viewport.SetContent(strings.Join(m.rendered, "\n\n"))
	m.viewport.GotoBottom()
}

func (m *Model) tokenSummary() string {
	total := m.totalPrompt + m.totalEval
	base := "⚡ " + fmtTokens(total)
	if m.busy && m.rate > 0 {
		base += fmt.Sprintf(" · %.1f tok/s", m.rate)
	}
	return base
}

func (m *Model) header() string {
	left := lipgloss.JoinHorizontal(lipgloss.Left,
		titleStyle.Render(" AREX "),
		titleAccentStyle.Render(" AI "),
	)
	mid := modelStyle.Render(m.cfg.Model + "  ·  session " + fmt.Sprint(m.session))
	tokens := tokensStyle.Render(m.tokenSummary())
	status := statusStyle.Render(" ● idle")
	if m.busy {
		status = statusBusyStyle.Render(" " + m.spinner.View() + " working")
	}
	pad := m.width - lipgloss.Width(left) - lipgloss.Width(mid) - lipgloss.Width(tokens) - lipgloss.Width(status)
	if pad < 1 {
		pad = 1
	}
	line1 := lipgloss.JoinHorizontal(lipgloss.Left, left, mid, strings.Repeat(" ", pad), tokens, status)
	line2 := sepStyle.Render(strings.Repeat("━", m.width))
	return lipgloss.JoinVertical(lipgloss.Left, line1, line2)
}

func (m *Model) pickerView() string {
	title := pickerTitleStyle.Render(" model picker · ↑/↓ choose · enter select · esc close ")
	var sb strings.Builder
	sb.WriteString(title)
	for i, name := range m.models {
		cur := "  "
		if i == m.modelIdx {
			cur = "❯ "
		}
		st := pickerItemStyle
		if i == m.modelIdx {
			st = pickerSelStyle
		}
		sb.WriteString("\n" + cur + st.Render(name))
	}
	box := pickerBoxStyle.Render(sb.String())
	lines := strings.Count(box, "\n") + 1
	pad := m.viewport.Height - lines
	if pad < 1 {
		pad = 1
	}
	return box + strings.Repeat("\n", pad)
}

func (m *Model) View() string {
	if m.width == 0 {
		return loadingStyle.Render("loading...")
	}
	body := m.viewport.View()
	if m.pickerOpen {
		body = m.pickerView()
	}
	hint := hintStyle.Render("enter send · ctrl+j newline · ctrl+p model picker · ctrl+l new session · esc stop · ctrl+c quit")
	brand := brandStyle.Render("arex by Rikixz · security researcher · khmersec.com · rikixz.dev")
	footer := lipgloss.JoinVertical(lipgloss.Left, hint, brand, m.input.View())
	return lipgloss.JoinVertical(lipgloss.Left, m.header(), body, footer)
}

func fmtTokens(n int64) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprint(n)
}

func isHelpRequest(s string) bool {
	t := strings.ToLower(strings.Trim(strings.TrimSpace(s), "!?. "))
	switch t {
	case "help", "help me", "help me please", "help please", "what can you do", "what can u do",
		"what do you do", "how do you work", "how do i use you", "how do i use this", "how to use",
		"what are your tools", "what tools do you have":
		return true
	}
	return false
}

func helpReply() string {
	return "I'm **AREX**, a cyber security research agent running 100% locally via Ollama.\n\n" +
		"**What I can do:**\n" +
		"- 🔍 Research & OSINT — `web_search` + `fetch_url` for CVEs, people, companies, docs\n" +
		"- 🛠️ Code & files — read/write files, create folders, run commands (build, test, git, curl, nmap...)\n" +
		"- 🏴 CTF — write PoCs, decode flags, analyze challenges\n" +
		"- 🌐 Web dev — build apps, fix bugs, explain code\n\n" +
		"**Keybindings:**\n" +
		"- `enter` send  ·  `ctrl+j` newline  ·  `ctrl+p` / `tab` model picker  ·  `ctrl+l` new session  ·  `esc` stop  ·  `ctrl+c` quit\n\n" +
		"**Slash commands:**\n" +
		"- `/model <name>` switch model (or open the picker)  ·  `/tools` list tools  ·  `/tokens` show token usage  ·  `/new` clear session  ·  `/host` show connection  ·  `/version`  ·  `/exit` quit\n\n" +
		"**Try asking:**\n" +
		"- \"research CVE-2024-1234 and fetch the advisory\"\n" +
		"- \"create a folder called rikixz and a hello.py inside it, then run it\"\n" +
		"- \"write a port scanner for my CTF lab box\""
}

func isGreeting(s string) bool {
	t := strings.ToLower(strings.Trim(strings.TrimSpace(s), "!?. "))
	switch t {
	case "hi", "hii", "hello", "helloo", "hey", "yo", "hai", "halo", "helo",
		"hi there", "hello there", "hey there", "hi arex", "hello arex", "hey arex", "hi rikixz":
		return true
	}
	return false
}

func greetingReply() string {
	h := time.Now().Hour()
	part := "Hello"
	switch {
	case h >= 5 && h < 12:
		part = "Good morning"
	case h >= 12 && h < 17:
		part = "Good afternoon"
	case h >= 17 && h < 22:
		part = "Good evening"
	}
	variants := []string{
		part + "! I'm **AREX** - your local cyber security research agent, made by **Rikixz** (khmersec.com / rikixz.dev). What can I help you with?",
		part + "! **AREX** here, built by **Rikixz** for security research, CTF and web dev. What do you need?",
	}
	return variants[rand.Intn(len(variants))]
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}