// Package smoke exposes the IRIX recipe modules to embedded frontends.
package smoke

import (
	"embed"
	"io/fs"
)

//go:embed irix_ip24.star irix_ip24_system.star irix_ip24_desktop.star
var irix embed.FS

// IRIX returns the original-media Indy recipe and its supporting modules.
func IRIX() fs.FS { return irix }
