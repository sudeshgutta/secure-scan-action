package trivy

type TrivyReport struct {
	SchemaVersion int      `json:"SchemaVersion"`
	CreatedAt     string   `json:"CreatedAt"`
	ArtifactName  string   `json:"ArtifactName"`
	ArtifactType  string   `json:"ArtifactType"`
	Metadata      Metadata `json:"Metadata"`
	Results       []Result `json:"Results"`
}

type Metadata struct {
	ImageConfig ImageConfig `json:"ImageConfig"`
}

type ImageConfig struct {
	Architecture string `json:"architecture"`
	Created      string `json:"created"`
	OS           string `json:"os"`
	RootFS       RootFS `json:"rootfs"`
	Config       any    `json:"config"`
}

type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgID            string          `json:"PkgID"`
	PkgName          string          `json:"PkgName"`
	PkgIdentifier    PkgIdentifier   `json:"PkgIdentifier"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	Status           string          `json:"Status"`
	Layer            any             `json:"Layer"`
	SeveritySource   string          `json:"SeveritySource"`
	PrimaryURL       string          `json:"PrimaryURL"`
	DataSource       DataSource      `json:"DataSource"`
	Title            string          `json:"Title"`
	Description      string          `json:"Description"`
	Severity         string          `json:"Severity"`
	VendorSeverity   map[string]int  `json:"VendorSeverity"`
	CVSS             map[string]CVSS `json:"CVSS"`
	References       []string        `json:"References"`
	PublishedDate    string          `json:"PublishedDate"`
	LastModifiedDate string          `json:"LastModifiedDate"`
}

type PkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

type DataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

type CVSS struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}
