package ui

import "github.com/charmbracelet/lipgloss"

const (
	cyan   = lipgloss.Color("#22d3ee")
	purple = lipgloss.Color("#a78bfa")
	green  = lipgloss.Color("#34d399")
	red    = lipgloss.Color("#f87171")
	gray   = lipgloss.Color("#6b7280")
	white  = lipgloss.Color("#e5e7eb")
	panel  = lipgloss.Color("#1e293b")
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0f172a")).
			Background(cyan).
			Padding(0, 2)

	titleAccentStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#0f172a")).
				Background(purple).
				Padding(0, 2)

	modelStyle = lipgloss.NewStyle().
			Foreground(gray).
			Padding(0, 1)

	statusStyle = lipgloss.NewStyle().
			Foreground(gray)

	statusBusyStyle = lipgloss.NewStyle().
				Foreground(cyan).
				Bold(true)

	userBubbleStyle = lipgloss.NewStyle().
				Border(lipgloss.RoundedBorder()).
				BorderForeground(cyan).
				Foreground(white).
				Padding(0, 1)

	userLabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(cyan)

	toolStyle = lipgloss.NewStyle().
			Foreground(purple).
			Bold(true)

	toolResultStyle = lipgloss.NewStyle().
			Foreground(gray)

	errStyle = lipgloss.NewStyle().
			Foreground(red).
			Bold(true)

	hintStyle = lipgloss.NewStyle().
			Foreground(gray)

	aiLabelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(green)

	sepStyle = lipgloss.NewStyle().
			Foreground(gray)

	loadingStyle = lipgloss.NewStyle().
			Foreground(cyan).
			Bold(true)

	tokensStyle = lipgloss.NewStyle().
			Foreground(green).
			Padding(0, 1)

	brandStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#475569")).
			Faint(true)

	pickerBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(purple).
			Padding(0, 1).
			MaxWidth(60)

	pickerTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(cyan)

	pickerItemStyle = lipgloss.NewStyle().
			Foreground(white)

	pickerSelStyle = lipgloss.NewStyle().
			Foreground(cyan).
			Bold(true)
)