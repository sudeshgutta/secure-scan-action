package astgrep

import (
	"fmt"
	"strings"
)

// Position represents a line/column position in source code
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// ByteOffset represents byte positions in a file
type ByteOffset struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Range represents the location of a match in source code
type Range struct {
	ByteOffset ByteOffset `json:"byteOffset"`
	Start      Position   `json:"start"`
	End        Position   `json:"end"`
}

// CharCount represents leading/trailing character counts
type CharCount struct {
	Leading  int `json:"leading"`
	Trailing int `json:"trailing"`
}

// MetaVariableMatch represents a metavariable match within the pattern
type MetaVariableMatch struct {
	Text  string `json:"text"`
	Range Range  `json:"range"`
}

// MetaVariables contains captured metavariables from AST-Grep patterns
type MetaVariables struct {
	Single map[string]interface{} `json:"single"`
	Multi  struct {
		Secondary []MetaVariableMatch `json:"secondary"`
	} `json:"multi"`
	Transformed map[string]interface{} `json:"transformed"`
}

// Label represents a labeled section of a match
type Label struct {
	Text  string `json:"text"`
	Range Range  `json:"range"`
	Style string `json:"style"` // "primary" or "secondary"
}

// Location represents a simple file location
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

// ASTGrepMatch represents a single match found by AST-Grep
type ASTGrepMatch struct {
	Text          string        `json:"text"`
	Range         Range         `json:"range"`
	File          string        `json:"file"`
	Lines         string        `json:"lines"`
	CharCount     CharCount     `json:"charCount"`
	Language      string        `json:"language"`
	MetaVariables MetaVariables `json:"metaVariables"`
	RuleId        string        `json:"ruleId"`
	Severity      string        `json:"severity"`
	Note          *string       `json:"note"`
	Message       string        `json:"message"`
	Labels        []Label       `json:"labels"`
}

// GetPackageName extracts the clean package name from the match text
func (m *ASTGrepMatch) GetPackageName() string {
	return strings.Trim(m.Text, "\" \t\n")
}

// GetVersion extracts version from package path (e.g., "v4", "v5")
func (m *ASTGrepMatch) GetVersion() string {
	packageName := m.GetPackageName()
	parts := strings.Split(packageName, "/")

	for _, part := range parts {
		if strings.HasPrefix(part, "v") && len(part) > 1 {
			if part[1] >= '0' && part[1] <= '9' {
				return part
			}
		}
	}
	return ""
}

// GetLocation returns the file location of this match
func (m *ASTGrepMatch) GetLocation() Location {
	return Location{
		File:   m.File,
		Line:   m.Range.Start.Line,
		Column: m.Range.Start.Column,
	}
}

// GetLocationString returns a human-readable location string
func (m *ASTGrepMatch) GetLocationString() string {
	return fmt.Sprintf("%s:%d:%d", m.File, m.Range.Start.Line, m.Range.Start.Column)
}

// IsInFile checks if this match is in the specified file
func (m *ASTGrepMatch) IsInFile(filename string) bool {
	return m.File == filename
}
