//go:build !release

package ui

import (
	"embed"
	"io/fs"
)

// Development-only resource keeps clean-checkout Go tests independent of Node.
//
//go:embed dev/index.html
var developmentAssets embed.FS

func assets() fs.FS { root, _ := fs.Sub(developmentAssets, "dev"); return root }
