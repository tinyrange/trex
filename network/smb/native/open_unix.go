//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package native

import "syscall"

// Avoid blocking on a raced-in FIFO and reject a final symlink. os.Root
// independently confines all intermediate resolution, including concurrent
// parent-directory/symlink replacement.
const supportedHost = true
const safeOpenFlags = syscall.O_NONBLOCK | syscall.O_NOFOLLOW
