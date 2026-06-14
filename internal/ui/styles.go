package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Header styles
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12")).
			MarginTop(1).
			MarginBottom(1)

	// Finding type styles
	secretStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("9"))

	endpointStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("11"))

	configStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("13"))

	genericStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("8"))

	// Content styles
	pathStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("6")).
			Italic(true)

	snippetStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("7"))

	tokenStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")).
			Bold(true)

	// Verification styles
	verifiedValidStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("0")).
				Background(lipgloss.Color("9")).
				Padding(0, 1)

	verifiedInvalidStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("8"))

	verifiedUnknownStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("11"))

	// Box styles
	summaryBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("12")).
			Padding(1, 2).
			MarginTop(1).
			MarginBottom(1)
)
