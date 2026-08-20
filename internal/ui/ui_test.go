package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"

	"arex/internal/ollama"
)

func TestUpdatePaths(t *testing.T) {
	m := New(Config{Model: "qwen2.5-coder:3b", Host: "http://localhost:11434", Dir: "."})
	m.md, _ = glamour.NewTermRenderer(glamour.WithAutoStyle(), glamour.WithWordWrap(94))

	// resize (previously panicked in renderAll)
	m2, _ := m.Update(tea.WindowSizeMsg{Width: 100, Height: 30})
	m = m2.(*Model)

	// model check
	m2, _ = m.Update(modelCheckMsg{err: nil})
	m = m2.(*Model)

	// simulate a streamed assistant turn
	for i := 0; i < 50; i++ {
		m2, _ = m.Update(chunkMsg{delta: "hello chunk ", evalCount: int64(i)})
		m = m2.(*Model)
	}

	// tool start replaces streamed garbage, then done
	m2, _ = m.Update(toolMsg{name: "write_file", args: `{"path":"a.txt","content":"x"}`, start: true})
	m = m2.(*Model)
	m2, _ = m.Update(toolMsg{name: "write_file", args: `{"path":"a.txt","content":"x"}`})
	m = m2.(*Model)

	// final reply streamed equal to accumulated
	m.streamingIdx = -1
	m2, _ = m.Update(doneMsg{reply: "all done", history: m.history, stats: ollama.Stats{PromptTokens: 100, EvalTokens: 200}})
	m = m2.(*Model)

	if len(m.items) == 0 {
		t.Fatal("no items rendered")
	}
	if m.busy {
		t.Fatal("still busy after done")
	}
	out := m.View()
	if !strings.Contains(out, "AREX") {
		t.Fatal("header missing")
	}

	// resize again (re-renders all items)
	m2, _ = m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = m2.(*Model)
	m.View()

	// clear session
	m2, _ = m.Update(tea.KeyMsg{Type: tea.KeyCtrlL})
	m = m2.(*Model)
	m.View()

	// error path
	m2, _ = m.Update(doneMsg{err: errTest})
	m = m2.(*Model)
	if len(m.items) == 0 {
		t.Fatal("error item missing")
	}
}

var errTest = &fakeErr{}

type fakeErr struct{}

func (f *fakeErr) Error() string { return "boom" }

func TestIsGreeting(t *testing.T) {
	greets := []string{"hi", "Hello!", "hey arex", "hi there", "hello??", "   yo   ", "Hello Arex"}
	nots := []string{"build a web app", "hi how do i exploit", "search for cves", "what is xss"}
	for _, g := range greets {
		if !isGreeting(g) {
			t.Errorf("isGreeting(%q) = false, want true", g)
		}
	}
	for _, n := range nots {
		if isGreeting(n) {
			t.Errorf("isGreeting(%q) = true, want false", n)
		}
	}
}

func TestFmtTokens(t *testing.T) {
	if got := fmtTokens(500); got != "500" {
		t.Errorf("fmtTokens(500) = %q", got)
	}
	if got := fmtTokens(1500); got != "1.5k" {
		t.Errorf("fmtTokens(1500) = %q", got)
	}
	if got := fmtTokens(1500000); got != "1.5M" {
		t.Errorf("fmtTokens(1500000) = %q", got)
	}
}