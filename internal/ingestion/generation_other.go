//go:build !darwin && !linux

package ingestion

import (
	"errors"
	"os"
)

// The ingestion adapters remain portable; the file tailer requires Linux or
// Darwin's no-follow/nonblocking descriptor and device/inode semantics.
func openLog(string) (*os.File, os.FileInfo, error) {
	return nil, nil, errors.New("file tailing requires Linux or Darwin")
}
func identifyFile(os.FileInfo) (fileIdentity, error) {
	return fileIdentity{}, errors.New("file tailing requires Linux or Darwin")
}
