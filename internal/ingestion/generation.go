package ingestion

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const fingerprintLimit = 4096

// FileGeneration identifies an observed file incarnation, not a filename or
// content hash. Persist the fingerprint length along with its hash: appending
// to an initially short file must not invalidate its existing fingerprint.
// ObservedSize is the largest extent confirmed by stat or a successful read;
// persist it even when the committed offset is much smaller. It detects the
// disappearance of a previously observed unread suffix.
// Fingerprints are bounded witnesses, not proof against every rewrite or inode
// reuse between polls. Identical truncate/regrow wholly between observations
// can be unobservable.
type FileGeneration struct {
	ID                string    `json:"id"`
	Path              string    `json:"path"`
	Device            uint64    `json:"device"`
	Inode             uint64    `json:"inode"`
	ObservedSize      int64     `json:"observed_size"`
	FingerprintBytes  int       `json:"fingerprint_bytes"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	CreatedAt         time.Time `json:"created_at"`
}

// ResumePoint is supplied by the caller from its durable transaction. ByteOffset
// must be zero or immediately after LF, including EOF only when LF-terminated.
// Neither Poll nor Status acknowledges or persists a record. Persist generation
// metadata with the committed record boundary; unfinished bytes are reread.
type ResumePoint struct {
	Generation FileGeneration `json:"generation"`
	ByteOffset int64          `json:"byte_offset"`
}

type fileIdentity struct{ Device, Inode uint64 }

func newGeneration(f *os.File, info os.FileInfo, identity fileIdentity, path string, now time.Time) (FileGeneration, error) {
	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return FileGeneration{}, errors.New("cannot generate file identity")
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", uuid[:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
	emptyHash := sha256.Sum256(nil)
	metadata := FileGeneration{ID: id, Path: path, Device: identity.Device, Inode: identity.Inode, ObservedSize: info.Size(), FingerprintSHA256: hex.EncodeToString(emptyHash[:]), CreatedAt: now}
	n := int(min(info.Size(), int64(fingerprintLimit)))
	fingerprint, err := fingerprintAt(f, n)
	if err != nil {
		// A reset must retain its fresh UUID even if another truncation races
		// the prefix read. The empty witness can be extended on a later poll.
		return metadata, err
	}
	metadata.FingerprintBytes = n
	metadata.FingerprintSHA256 = fingerprint
	return metadata, nil
}

func fingerprintAt(f *os.File, n int) (string, error) {
	var buffer [fingerprintLimit]byte
	if n > 0 {
		count, err := f.ReadAt(buffer[:n], 0)
		if count != n {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return "", err
		}
	}
	hash := sha256.Sum256(buffer[:n])
	return hex.EncodeToString(hash[:]), nil
}
func fingerprintMatches(f *os.File, g FileGeneration) (bool, error) {
	got, err := fingerprintAt(f, g.FingerprintBytes)
	return err == nil && got == g.FingerprintSHA256, err
}
func isShortRead(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
func validResume(p ResumePoint) bool {
	g := p.Generation
	if p.ByteOffset < 0 || !validUUID(g.ID) || g.Path == "" || g.CreatedAt.IsZero() || g.FingerprintBytes < 0 || g.FingerprintBytes > fingerprintLimit || g.ObservedSize < int64(g.FingerprintBytes) || len(g.FingerprintSHA256) != 64 {
		return false
	}
	_, err := hex.DecodeString(g.FingerprintSHA256)
	return err == nil
}
func validUUID(id string) bool {
	if len(id) != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	return err == nil
}
func resumeBoundary(f *os.File, size, offset int64) (bool, error) {
	if offset < 0 || offset > size {
		return false, nil
	}
	if offset == 0 {
		return true, nil
	}
	var previous [1]byte
	n, err := f.ReadAt(previous[:], offset-1)
	return n == 1 && err == nil && previous[0] == '\n', err
}
