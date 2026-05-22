// Package static embeds the demo HTML client so the binary is
// self-contained — no separate web/ directory needs to be copied next
// to the executable in production. The whole client is one file.
package static

import "embed"

//go:embed index.html
var FS embed.FS
