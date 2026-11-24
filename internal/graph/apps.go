package graph

import "strings"

// AppAIWords are words in a GitHub App slug that name an AI coding or
// review tool (a weak, name-only signal: app_ai=name).
var AppAIWords = []string{"claude", "copilot", "codex", "openai", "anthropic", "gemini", "cursor", "devin",
	"coderabbit", "greptile", "qodo", "sweep", "agent", "llm", "-ai", "ai-"}

// AppNamesAI reports whether an App slug names an AI tool.
func AppNamesAI(slug string) bool {
	s := strings.ToLower(slug)
	for _, w := range AppAIWords {
		if strings.Contains(s, w) {
			return true
		}
	}
	return false
}
