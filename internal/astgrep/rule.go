package astgrep

type ASTGrepRule struct {
	ID       string      `json:"id"`
	Language string      `json:"language"`
	Rule     interface{} `json:"rule"`
}

// Import Spec Kind
type ASTGrepImportSpecRule struct {
	Kind string          `json:"kind,omitempty"`
	Has  ASTGrepHasRegex `json:"has,omitempty"`
}

// Matches regex value/expression
type ASTGrepHasRegex struct {
	Regex string `json:"regex,omitempty"`
}
