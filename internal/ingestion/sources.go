package ingestion

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var ErrSources = errors.New("collector_sources_invalid")

type Endpoint struct {
	Service      string `json:"service"`
	ObservedIP   string `json:"observed_ip"`
	ObservedPort int    `json:"observed_port"`
	PublicIP     string `json:"public_ip"`
	PublicPort   int    `json:"public_port"`
}

type Source struct {
	SensorID     string     `json:"sensor_id"`
	Name         string     `json:"name"`
	Engine       string     `json:"engine"`
	Path         string     `json:"path"`
	ArchivePaths []string   `json:"archive_paths"`
	Endpoints    []Endpoint `json:"endpoints"`
	IsTest       bool       `json:"is_test"`
}

// LoadSources reads a bounded operator-owned manifest outside the writable log
// tree. Configure it read-only for the collector and inaccessible to engines.
func LoadSources(root, path string) ([]Source, error) {
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) || filepath.Clean(root) != root || filepath.Clean(path) != path {
		return nil, ErrSources
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, ErrSources
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil || within(realRoot, realPath) {
		return nil, ErrSources
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return nil, ErrSources
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrSources
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrSources
	}
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil || len(data) > 64*1024 || !uniqueJSON(data) {
		return nil, ErrSources
	}
	var sources []Source
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&sources) != nil || len(sources) == 0 || len(sources) > 16 {
		return nil, ErrSources
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, ErrSources
	}
	ids, names, paths := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range sources {
		s := &sources[i]
		if !validSource(*s) || ids[s.SensorID] || names[s.Name] || len(s.ArchivePaths) > 64 {
			return nil, ErrSources
		}
		ids[s.SensorID] = true
		names[s.Name] = true
		entries := append([]string{s.Path}, s.ArchivePaths...)
		for j, p := range entries {
			if p == "" || p == "." || filepath.IsAbs(p) || filepath.Clean(p) != p || p == ".." || strings.HasPrefix(p, ".."+string(filepath.Separator)) {
				return nil, ErrSources
			}
			resolved := filepath.Join(realRoot, p)
			// Parent directories are trusted configuration. Existing symlinks must not
			// redirect sources outside the log root; final-file symlinks are never read.
			parent, e := filepath.EvalSymlinks(filepath.Dir(resolved))
			if e != nil || !within(realRoot, parent) {
				return nil, ErrSources
			}
			resolved = filepath.Join(parent, filepath.Base(resolved))
			if paths[resolved] {
				return nil, ErrSources
			}
			paths[resolved] = true
			if j == 0 {
				s.Path = resolved
			} else {
				s.ArchivePaths[j-1] = resolved
			}
		}
	}
	return sources, nil
}
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func validSource(s Source) bool {
	if !validUUID(s.SensorID) || s.SensorID != strings.ToLower(s.SensorID) || len(s.Name) == 0 || len(s.Name) > 64 || !safeIdentifier(s.Name) || (s.Engine != "cowrie" && s.Engine != "web") || len(s.Endpoints) == 0 || len(s.Endpoints) > 2 {
		return false
	}
	if s.Engine == "cowrie" && len(s.Endpoints) != 1 {
		return false
	}
	endpoints, services := map[string]bool{}, map[string]bool{}
	for _, e := range s.Endpoints {
		observed, err := address(e.ObservedIP)
		_, ep := address(e.PublicIP)
		if err != nil || ep != nil || !port(e.ObservedPort) || !port(e.PublicPort) {
			return false
		}
		if (s.Engine == "cowrie" && e.Service != "ssh") || (s.Engine == "web" && e.Service != "http" && e.Service != "https") {
			return false
		}
		key := observed.String() + ":" + strconv.Itoa(e.ObservedPort)
		if endpoints[key] || services[e.Service] {
			return false
		}
		endpoints[key] = true
		services[e.Service] = true
	}
	return true
}
