package web

type Fixture struct {
	CurrentBuildInputs map[string]string `json:"current_build_inputs_sha256"`
	BuildInputs        map[string]string `json:"build_inputs_sha256"`
	ImageInspectSHA256 string            `json:"image_inspect_sha256"`

	Kind               string   `json:"kind"`
	SourceRunID        string   `json:"source_run_id"`
	OriginalRawSHA256  string   `json:"original_raw_sha256"`
	OriginalRunSHA256  string   `json:"original_run_sha256"`
	OriginalLineSHA256 []string `json:"original_line_sha256"`
	SHA256             string   `json:"fixture_sha256"`
	CasesSHA256        string   `json:"cases_sha256"`
	Redactions         []string `json:"redactions"`
	Run                Run      `json:"run"`
	Report             Report   `json:"report"`
}
