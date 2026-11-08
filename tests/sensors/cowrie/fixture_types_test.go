package cowrie

type Provenance struct {
	Kind          string `json:"kind"`
	Version       string `json:"cowrie_version"`
	SourceCommit  string `json:"cowrie_source_commit"`
	RawSHA256     string `json:"private_raw_sha256"`
	RunSHA256     string `json:"private_run_sha256"`
	OriginalRunID string `json:"original_run_id"`
	LineCount     int    `json:"line_count"`
	Notes         string `json:"notes"`
}
type Fixture struct {
	SchemaVersion int        `json:"schema_version"`
	Provenance    Provenance `json:"provenance"`
	SHA256        string     `json:"fixture_sha256"`
	Redactions    []string   `json:"redactions"`
	Run           Run        `json:"run"`
	Results       []Result   `json:"expected_results"`
}
