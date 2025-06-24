package trivy

type TrivyReport struct {
	Results []*Result `json:"Results,omitempty"`
}

type Result struct {
	Vulnerabilities []*Vulnerability `json:"Vulnerabilities,omitempty"`
}

type Vulnerability struct {
	PkgName string `json:"PkgName"`
}
