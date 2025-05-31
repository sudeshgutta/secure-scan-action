package astgrep

type Report struct {
	Matches []Match `json:"matches"`
}

type Match struct {
	RuleID  string `json:"rule_id"`
	Message string `json:"message"`
	Range   struct {
		Path  string `json:"path"`
		Start struct {
			Line int `json:"line"`
		} `json:"start"`
	} `json:"range"`
}

type ASTGrepRule struct {
	ID       string             `json:"id"`
	Language string             `json:"language"`
	Rule     ASTGrepRuleContent `json:"rule"`
}

type ASTGrepRuleContent struct {
	Pattern string              `json:"pattern,omitempty"`
	Inside  *ASTGrepRuleContent `json:"inside,omitempty"`
	Kind    string              `json:"kind,omitempty"`
}
