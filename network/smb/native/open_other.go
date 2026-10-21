//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly && !windows

package native

const supportedHost = false
const safeOpenFlags = 0
