package archivegui

import "os/exec"

// The user's explicit desktop Open action delegates to Launch Services.
// This is not a parser, extractor, or part of the archive processing pipeline.
func shellOpen(name string) error { return exec.Command("/usr/bin/open", "--", name).Run() }
