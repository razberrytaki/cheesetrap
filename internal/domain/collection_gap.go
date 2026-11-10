package domain

import "time"

type GapCause string

const (
	GapRetentionCleanup  GapCause = "retention_cleanup"
	GapStorageRestricted GapCause = "storage_restricted"
	GapSourceChange      GapCause = "source_change"
	GapLegacy            GapCause = "legacy"
)

type CollectionGapIncident struct {
	StartedAt       time.Time  `json:"started_at"`
	ObservedThrough time.Time  `json:"observed_through"`
	Causes          []GapCause `json:"causes" nullable:"false" minItems:"1"`
}
