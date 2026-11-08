// Package migrations embeds application migrations for execution from any cwd.
package migrations

import "embed"

// Files contains only versioned Goose migrations, never bootstrap credentials.
//
//go:embed *.sql
var Files embed.FS
