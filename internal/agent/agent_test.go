package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseJSONToolCalls(t *testing.T) {
	input := "```json\n" +
		"{\n  \"name\": \"write_file\",\n  \"arguments\": {\n    \"path\": \"hello.py\",\n    \"content\": \"print('hello')\"\n  }\n}\n" +
		"{\"name\": \"run_command\", \"arguments\": {\"command\": \"python hello.py\"}}\n```"
	calls, cleaned := parseJSONToolCalls(input)
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d: %+v", len(calls), calls)
	}
	if calls[0].Function.Name != "write_file" {
		t.Errorf("call 0 name = %q", calls[0].Function.Name)
	}
	if !strings.Contains(string(calls[0].Function.Arguments), "hello.py") {
		t.Errorf("call 0 args = %s", calls[0].Function.Arguments)
	}
	if calls[1].Function.Name != "run_command" {
		t.Errorf("call 1 name = %q", calls[1].Function.Name)
	}
	if cleaned != "" {
		t.Errorf("cleaned = %q, want empty", cleaned)
	}
}

func TestParseJSONToolCallsMixed(t *testing.T) {
	input := "Let me check the file.\n{\"name\": \"read_file\", \"arguments\": {\"path\": \"main.go\"}}\nBased on that:"
	calls, cleaned := parseJSONToolCalls(input)
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if !strings.Contains(cleaned, "Let me check the file.") || !strings.Contains(cleaned, "Based on that:") {
		t.Errorf("cleaned lost surrounding text: %q", cleaned)
	}
}

func TestParseJSONToolCallsNoCalls(t *testing.T) {
	input := "just a normal reply, nothing here"
	calls, cleaned := parseJSONToolCalls(input)
	if len(calls) != 0 {
		t.Fatalf("expected 0 calls, got %d", len(calls))
	}
	if cleaned != input {
		t.Errorf("cleaned = %q, want unchanged", cleaned)
	}
}

func TestStripFences(t *testing.T) {
	got := stripFences("```json\n\n```\n\n```\nhello")
	if got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestStripHTML(t *testing.T) {
	in := "<html><head><script>var x=1;</script><style>.a{}</style></head><body><h1>Hi</h1> <p>there\n\n   &amp;   bye</p></body></html>"
	got := stripHTML(in)
	if strings.Contains(got, "script") || strings.Contains(got, "style") || strings.Contains(got, "<") {
		t.Errorf("HTML leaked through: %q", got)
	}
	if !strings.Contains(got, "Hi there") || !strings.Contains(got, "& bye") {
		t.Errorf("content wrong: %q", got)
	}
}

func TestDecodeDDGLink(t *testing.T) {
	got := decodeDDGLink("//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fpage&rut=abc")
	if got != "https://example.com/page" {
		t.Errorf("got %q", got)
	}
}

func TestMarkTruncation(t *testing.T) {
	if got := markTruncation("Replace the URL."); strings.Contains(got, "cut off") {
		t.Errorf("complete sentence marked truncated: %q", got)
	}
	if got := markTruncation("Replace `'https://example.com/page'"); !strings.Contains(got, "cut off") {
		t.Errorf("fragment not marked: %q", got)
	}
	if got := markTruncation("```\ncode\n```"); strings.Contains(got, "cut off") {
		t.Errorf("closed fence marked truncated: %q", got)
	}
}

func TestFixJSONEscapes(t *testing.T) {
	got := fixJSONEscapes(`{"path":"C:\Users\rikixz\file.txt"}`)
	if !strings.Contains(got, `C:\\Users\\rikixz`) {
		t.Errorf("backslashes not doubled: %q", got)
	}
	var m struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal([]byte(got), &m); err != nil {
		t.Errorf("unmarshal failed: %v", err)
	}
	if m.Path != `C:\Users\rikixz\file.txt` {
		t.Errorf("path = %q", m.Path)
	}
}

func TestParseOSRelease(t *testing.T) {
	cases := []struct {
		content string
		id, name, version string
	}{
		{
			`NAME="Arch Linux"
ID=arch
PRETTY_NAME="Arch Linux"
VERSION_ID="2026.08.01"`,
			"arch", "Arch Linux", "2026.08.01",
		},
		{
			`NAME="Ubuntu"
ID=ubuntu
VERSION_ID="24.04"`,
			"ubuntu", "Ubuntu", "24.04",
		},
		{
			`NAME="Kali GNU/Linux"
ID=kali
VERSION_ID="2025.1"`,
			"kali", "Kali GNU/Linux", "2025.1",
		},
		{
			`NAME="Fedora Linux"
ID=fedora
VERSION_ID="40"`,
			"fedora", "Fedora Linux", "40",
		},
		{
			`ID=debian`,
			"debian", "debian", "",
		},
	}
	for _, c := range cases {
		id, name, version := parseOSRelease(c.content)
		if id != c.id || name != c.name || version != c.version {
			t.Errorf("parseOSRelease(%q) = (%q,%q,%q), want (%q,%q,%q)", c.content, id, name, version, c.id, c.name, c.version)
		}
	}
}

func TestPkgMgrForDistro(t *testing.T) {
	cases := map[string]string{
		"arch": "pacman", "manjaro": "pacman",
		"ubuntu": "apt", "debian": "apt", "kali": "apt",
		"fedora": "dnf", "rocky": "dnf",
		"alpine": "apk", "opensuse": "zypper", "void": "xbps", "nixos": "nix",
		"": "",
	}
	for id, want := range cases {
		if got := pkgMgrForDistro(id); got != want {
			t.Errorf("pkgMgrForDistro(%q) = %q, want %q", id, got, want)
		}
	}
}

func TestShellFor(t *testing.T) {
	if got := shellFor("windows"); got != "PowerShell" {
		t.Errorf("shellFor(windows) = %q, want PowerShell", got)
	}
	if got := shellFor("darwin"); got != "zsh" {
		t.Errorf("shellFor(darwin) = %q, want zsh", got)
	}
	if got := shellFor("linux"); got != "bash" {
		t.Errorf("shellFor(linux) = %q, want bash", got)
	}
}

func TestIsPlaceholderReply(t *testing.T) {
	bad := []string{"", "   ", "<tool_response>", "<tool_response>\n\n</tool_response>", "Tool result for web_search"}
	good := []string{"KhmerSec is a security community.", "Here are the results:\n- khmersec.com\n- rikixz.dev"}
	for _, b := range bad {
		if !isPlaceholderReply(b) {
			t.Errorf("isPlaceholderReply(%q) = false, want true", b)
		}
	}
	for _, g := range good {
		if isPlaceholderReply(g) {
			t.Errorf("isPlaceholderReply(%q) = true, want false", g)
		}
	}
}

func TestAgentFetchURLErrors(t *testing.T) {
	a := &Agent{}
	if got := a.fetchURL(""); !strings.Contains(got, "error") {
		t.Errorf("empty url should error, got %q", got)
	}
	if got := a.fetchURL("notaurl"); !strings.Contains(got, "error") {
		t.Errorf("bad url should error, got %q", got)
	}
	if got := a.webSearch(""); !strings.Contains(got, "error") {
		t.Errorf("empty query should error, got %q", got)
	}
}

func TestBingRSSParse(t *testing.T) {
	body := `<?xml version="1.0"?>
<rss version="2.0"><channel><item>
<title>SQL injection - Wikipedia</title>
<link>https://en.wikipedia.org/wiki/SQL_injection</link>
<description>SQL injection is a code injection technique used to attack data-driven applications.</description>
</item><item>
<title>CVE-2025-24813 - NVD</title>
<link>https://nvd.nist.gov/vuln/detail/CVE-2025-24813</link>
<description>Path Equivalence in Apache Tomcat leading to RCE.</description>
</item></channel></rss>`
	got := formatResults(parseBingRSS([]byte(body)))
	if !strings.Contains(got, "SQL injection") || !strings.Contains(got, "en.wikipedia.org") {
		t.Errorf("bing parse missing expected content, got:\n%s", got)
	}
	if !strings.Contains(got, "CVE-2025-24813") {
		t.Errorf("bing parse missing second result, got:\n%s", got)
	}
}

func TestHTMLToTextSkipsNoise(t *testing.T) {
	page := `<html><head><style>body{color:red}</style></head><body>
<script>var x = 1;</script>
<nav><a href="/">Home</a><a href="/login">Login</a></nav>
<main><article><h1>Hello World</h1><p>This is the actual content of the page.</p></article></main>
<footer>Copyright 2026</footer>
</body></html>`
	got := htmlToText(page)
	if !strings.Contains(got, "Hello World") || !strings.Contains(got, "actual content") {
		t.Errorf("article text missing, got:\n%s", got)
	}
	if strings.Contains(got, "var x = 1") || strings.Contains(got, "Copyright") || strings.Contains(got, "Login") {
		t.Errorf("noise was not removed, got:\n%s", got)
	}
}

func TestExtractArticleText(t *testing.T) {
	page := `<html><body>
<nav>MENU MENU MENU MENU MENU</nav>
<div id="content"><article><p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur.</p></article></div>
<footer>FOOTER FOOTER FOOTER</footer>
</body></html>`
	got := extractArticleText(page)
	if !strings.Contains(got, "Lorem ipsum") {
		t.Errorf("article extraction failed, got:\n%s", got)
	}
	if strings.Contains(got, "MENU") || strings.Contains(got, "FOOTER") {
		t.Errorf("noise leaked into article, got:\n%s", got)
	}
}

func TestCleanSnippet(t *testing.T) {
	got := cleanSnippet("Hello&nbsp;world  &amp;  friends\n\n   more   text")
	if !strings.Contains(got, "Hello world & friends") {
		t.Errorf("cleanSnippet output wrong: %q", got)
	}
}

func TestFormatResults(t *testing.T) {
	got := formatResults([]searchResult{
		{title: "Title A", url: "https://a.com", snippet: "Snippet A"},
		{title: "Title B", url: "https://b.com", snippet: "Snippet B"},
	})
	if !strings.Contains(got, "1. Title A") || !strings.Contains(got, "https://a.com") || !strings.Contains(got, "2. Title B") {
		t.Errorf("formatResults output wrong:\n%s", got)
	}
}