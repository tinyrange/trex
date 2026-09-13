package archivegui

import "os/exec"

// Only the user's explicit desktop Open action invokes the desktop handler.
// name is absolute, so filenames cannot become command-line switches.
func shellOpen(name string) error { return exec.Command("xdg-open", name).Run() }
