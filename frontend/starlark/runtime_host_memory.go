package starlarkfrontend

import (
	"fmt"
	"io"
	"os"
	"path"
	"runtime"
	"strings"

	"go.starlark.net/starlark"
)

// These are observations, not a resource reservation or proof of which process
// an OOM event killed. Keep collection bounded even for procfs files with size 0.
const hostMemoryReadLimit = 64 << 10

func readHostMemoryFile(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, hostMemoryReadLimit+1))
	if err != nil {
		return "", err
	}
	if len(b) > hostMemoryReadLimit {
		return "", fmt.Errorf("host memory observation exceeds %d bytes", hostMemoryReadLimit)
	}
	return string(b), nil
}

func runtimeHostMemoryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	pid := os.Getpid()
	if err := starlark.UnpackArgs("runtime.host_memory", args, kwargs, "pid?", &pid); err != nil {
		return nil, err
	}
	if pid <= 0 || int64(pid) > 2147483647 {
		return nil, fmt.Errorf("runtime.host_memory: pid must be a positive 32-bit process ID")
	}
	proc := fmt.Sprintf("/proc/%d", pid)
	files, failures := starlark.NewDict(12), starlark.NewDict(12)
	if runtime.GOOS == "linux" {
		paths := []string{
			proc + "/status", proc + "/stat", "/proc/meminfo", "/proc/vmstat", proc + "/cgroup",
			"/sys/fs/cgroup/memory.current", "/sys/fs/cgroup/memory.max",
			"/sys/fs/cgroup/memory.peak", "/sys/fs/cgroup/memory.events",
			"/sys/fs/cgroup/memory.swap.current", "/sys/fs/cgroup/memory.swap.max",
		}
		if f, err := os.Open(proc + "/cgroup"); err == nil {
			text, err := readHostMemoryFile(f)
			f.Close()
			if err == nil {
				paths = append(paths, hostMemoryCgroupPaths(text)...)
			}
		}
		for _, path := range paths {
			f, err := os.Open(path)
			var text string
			if err == nil {
				text, err = readHostMemoryFile(f)
				f.Close()
			}
			if err != nil {
				failures.SetKey(starlark.String(path), starlark.String(err.Error()))
			} else {
				files.SetKey(starlark.String(path), starlark.String(text))
			}
		}
	}
	return newStarlarkRecord(starlark.StringDict{
		"platform": starlark.String(runtime.GOOS), "pid": starlark.MakeInt(pid),
		"files": files, "errors": failures,
	}), nil
}

// Bound both traversal and names; never accept a membership path escaping the
// fixed cgroup mount. Ancestors can impose limits absent at the process leaf.
func hostMemoryCgroupPaths(text string) []string {
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		member := strings.TrimPrefix(line, "0::")
		if path.Clean(member) != member || strings.ContainsRune(member, 0) || len(member) > 4096 {
			return nil
		}
		var result []string
		for depth := 0; member != "/" && depth < 16; depth++ {
			for _, leaf := range []string{"memory.current", "memory.max", "memory.peak", "memory.events", "memory.swap.current", "memory.swap.max"} {
				result = append(result, "/sys/fs/cgroup"+member+"/"+leaf)
			}
			member = path.Dir(member)
		}
		return result
	}
	return nil
}
