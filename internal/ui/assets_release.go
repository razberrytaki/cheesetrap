//go:build release

package ui

import (
	"embed"
	"io/fs"
)

// A release must be built after npm --prefix web run build. Both patterns must
// match real generated assets; no development resource enters a release binary.
//
//go:embed dist/index.html dist/assets/*
var releaseAssets embed.FS

func assets() fs.FS { root, _ := fs.Sub(releaseAssets, "dist"); return root }
