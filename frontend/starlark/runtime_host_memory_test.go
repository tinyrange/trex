package starlarkfrontend

import (
	"errors"
	"go.starlark.net/starlark"
	"io"
	"strings"
	"testing"
)

type failedMemoryReader struct{}

func (failedMemoryReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestHostMemoryReadBound(t *testing.T) {
	for _, n := range []int{0, hostMemoryReadLimit, hostMemoryReadLimit + 1} {
		text, err := readHostMemoryFile(strings.NewReader(strings.Repeat("x", n)))
		if n <= hostMemoryReadLimit {
			if err != nil || len(text) != n {
				t.Fatalf("size %d: len=%d err=%v", n, len(text), err)
			}
		} else if err == nil || text != "" {
			t.Fatal("oversize observation must fail without partial text")
		}
	}
	if text, err := readHostMemoryFile(failedMemoryReader{}); text != "" || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("read error lost: %q %v", text, err)
	}
}

func TestHostMemoryCgroupPaths(t *testing.T) {
	for _, text := range []string{"0::/../etc", "0::/a/../../etc", "0::relative", "1:memory:/other", "0::/a//b", "0::/a\x00b"} {
		if got := hostMemoryCgroupPaths(text); len(got) != 0 {
			t.Fatalf("unsafe membership %q: %v", text, got)
		}
	}
	paths := hostMemoryCgroupPaths("0::/user.slice/service\n")
	if len(paths) != 12 || paths[0] != "/sys/fs/cgroup/user.slice/service/memory.current" || paths[6] != "/sys/fs/cgroup/user.slice/memory.current" {
		t.Fatalf("paths=%v", paths)
	}
	if got := hostMemoryCgroupPaths("0::/" + strings.Repeat("a/", 100) + "b"); len(got) != 96 {
		t.Fatalf("unbounded ancestry: %d", len(got))
	}
}

func TestHostMemoryRejectsInvalidPID(t *testing.T) {
	for _, pid := range []int64{-1, 0, 2147483648} {
		if _, err := runtimeHostMemoryBuiltin(nil, nil, starlark.Tuple{starlark.MakeInt64(pid)}, nil); err == nil {
			t.Fatalf("accepted pid %d", pid)
		}
	}
}
