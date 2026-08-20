package ollama

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Tool struct {
	Type     string   `json:"type"`
	Function Function `json:"function"`
}

type Function struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type Message struct {
	Role      string     `json:"role,omitempty"`
	Content   string     `json:"content,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
	ToolName  string     `json:"tool_name,omitempty"`
}

type ToolCall struct {
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"function"`
}

type chatRequest struct {
	Model    string         `json:"model"`
	Messages []Message      `json:"messages"`
	Tools    []Tool         `json:"tools,omitempty"`
	Stream   bool           `json:"stream"`
	Options  map[string]any `json:"options,omitempty"`
}

type chatResponse struct {
	Message          Message `json:"message"`
	Done             bool    `json:"done"`
	Error            string  `json:"error"`
	PromptEvalCount  int64   `json:"prompt_eval_count,omitempty"`
	EvalCount        int64   `json:"eval_count,omitempty"`
	EvalDuration     int64   `json:"eval_duration,omitempty"`
}

type Stats struct {
	PromptTokens int64
	EvalTokens   int64
	EvalDuration int64 // nanoseconds
}

type Options struct {
	NumCtx      int
	Temperature float64
}

type Client struct {
	host   string
	model  string
	numCtx int
	temp   float64
	http   *http.Client
}

func New(host, model string, opts Options) *Client {
	if opts.NumCtx <= 0 {
		opts.NumCtx = 16384
	}
	return &Client{
		host:   strings.TrimRight(host, "/"),
		model:  model,
		numCtx: opts.NumCtx,
		temp:   opts.Temperature,
		http:   &http.Client{Timeout: 30 * time.Minute},
	}
}

func (c *Client) Host() string  { return c.host }
func (c *Client) Model() string { return c.model }

func (c *Client) Models() ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, c.host+"/api/tags", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}
	var out struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out.Models))
	for _, m := range out.Models {
		names = append(names, m.Name)
	}
	return names, nil
}

func (c *Client) Chat(ctx context.Context, messages []Message, tools []Tool, onChunk func(string, int64)) (Message, Stats, error) {
	payload := chatRequest{
		Model:    c.model,
		Messages: messages,
		Tools:    tools,
		Stream:   true,
		Options: map[string]any{
			"temperature": c.temp,
		},
	}
	if c.numCtx > 0 {
		payload.Options["num_ctx"] = c.numCtx
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Message{}, Stats{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.host+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return Message{}, Stats{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Message{}, Stats{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		return Message{}, Stats{}, fmt.Errorf("ollama: status %d: %s", resp.StatusCode, strings.TrimSpace(buf.String()))
	}

	var final Message
	var stats Stats
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var cr chatResponse
		if err := json.Unmarshal(line, &cr); err != nil {
			continue
		}
		if cr.Error != "" {
			return final, stats, fmt.Errorf("ollama: %s", cr.Error)
		}
		if cr.Message.Content != "" {
			final.Content += cr.Message.Content
			if onChunk != nil {
				onChunk(cr.Message.Content, cr.EvalCount)
			}
		}
		if len(cr.Message.ToolCalls) > 0 {
			final.ToolCalls = append(final.ToolCalls, cr.Message.ToolCalls...)
		}
		if cr.PromptEvalCount > stats.PromptTokens {
			stats.PromptTokens = cr.PromptEvalCount
		}
		if cr.EvalCount > stats.EvalTokens {
			stats.EvalTokens = cr.EvalCount
		}
		if cr.EvalDuration > stats.EvalDuration {
			stats.EvalDuration = cr.EvalDuration
		}
	}
	if err := scanner.Err(); err != nil {
		return final, stats, err
	}
	final.Role = "assistant"
	return final, stats, nil
}