package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"arex/internal/agent"
	"arex/internal/ollama"
	"arex/internal/ui"
)

var version = "0.3.0"

func main() {
	model := flag.String("model", "qwen2.5-coder:3b", "ollama model to use")
	host := flag.String("host", "http://localhost:11434", "ollama server host")
	dir := flag.String("dir", "", "working directory (default: current)")
	ctxLen := flag.Int("ctx", 16384, "context window size (num_ctx)")
	temp := flag.Float64("temp", 0.2, "sampling temperature")
	v := flag.Bool("version", false, "print version")
	flag.Parse()

	opts := ollama.Options{NumCtx: *ctxLen, Temperature: *temp}

	if *v {
		fmt.Printf("arex %s\n", version)
		return
	}

	if len(flag.Args()) > 0 {
		runOnce(*host, *model, *dir, opts, strings.Join(flag.Args(), " "))
		return
	}

	cfg := ui.Config{Model: *model, Host: *host, Dir: *dir, Version: version, Options: opts}
	if err := ui.New(cfg).Run(); err != nil {
		fmt.Fprintln(os.Stderr, "arex:", err)
		os.Exit(1)
	}
}

func runOnce(host, model, dir string, opts ollama.Options, prompt string) {
	client := ollama.New(host, model, opts)
	workdir := dir
	if workdir == "" {
		workdir, _ = os.Getwd()
	}
	var buf strings.Builder
	flushed := false
	a := agent.New(client, workdir, agent.Callbacks{
		OnChunk: func(d string, _ int64) { buf.WriteString(d) },
		OnToolStart: func(name, args string) {
			flushed = flushBuffered(&buf, true) || flushed
			fmt.Printf("\x1b[35m⚡ %s(%s)\x1b[0m\n", name, truncateStr(args, 80))
		},
	})
	if err := a.CheckModel(); err != nil {
		fmt.Fprintln(os.Stderr, "arex:", err)
		os.Exit(1)
	}
	reply, _, _, err := a.Run(context.Background(), []ollama.Message{{Role: "user", Content: prompt}})
	if err != nil {
		flushBuffered(&buf, false)
		fmt.Fprintln(os.Stderr, "arex:", err)
		os.Exit(1)
	}
	flushed = flushBuffered(&buf, false) || flushed
	if !flushed && reply != "" {
		fmt.Println(reply)
	}
}

func flushBuffered(buf *strings.Builder, checkJSON bool) bool {
	if buf.Len() == 0 {
		return false
	}
	content := buf.String()
	if checkJSON && strings.Contains(content, `"name"`) && strings.Contains(content, `"arguments"`) {
		buf.Reset()
		return false
	}
	fmt.Print(content)
	buf.Reset()
	return true
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}