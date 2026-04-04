package trivy

type TrivyReport struct {
	Results []*Result `json:"Results,omitempty"`
}

type Result struct {
	Target          string           `json:"Target"`
	Type            string           `json:"Type"`
	Vulnerabilities []*Vulnerability `json:"Vulnerabilities,omitempty"`
}

type Vulnerability struct {
	VulnerabilityID string   `json:"VulnerabilityID"`
	PkgName         string   `json:"PkgName"`
	Severity        string   `json:"Severity"`
	Description     string   `json:"Description"`
	References      []string `json:"References,omitempty"`
}
