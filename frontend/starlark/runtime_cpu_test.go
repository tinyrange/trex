package starlarkfrontend

import (
	"bytes"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

//go:noinline
func runtimeCPUBusyLeaf(n int) int {
	x := 1
	for i := 0; i < n; i++ {
		x = x*1103515245 + 12345
	}
	return x
}

func TestSummarizeCPUProfile(t *testing.T) {
	var buffer bytes.Buffer
	if err := pprof.StartCPUProfile(&buffer); err != nil {
		t.Skip("CPU profiler unavailable:", err)
	}
	sink := 0
	for end := time.Now().Add(400 * time.Millisecond); time.Now().Before(end); {
		sink += runtimeCPUBusyLeaf(1 << 16)
	}
	pprof.StopCPUProfile()
	_ = sink
	s, err := summarizeCPUProfile(buffer.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if s.samples == 0 || s.total <= 0 {
		t.Fatalf("no samples: %+v", s)
	}
	var leaf *cpuProfileFunction
	for i := range s.functions {
		if strings.HasSuffix(s.functions[i].name, "runtimeCPUBusyLeaf") {
			leaf = &s.functions[i]
		}
		if s.functions[i].flat > s.functions[i].cum || s.functions[i].cum > s.total {
			t.Fatalf("inconsistent times %+v total %d", s.functions[i], s.total)
		}
	}
	if leaf == nil || leaf.flat*2 < s.total {
		t.Fatalf("busy leaf should dominate flat time: %+v of %d", leaf, s.total)
	}
	if empty, err := summarizeCPUProfile(nil); err != nil || empty.samples != 0 {
		t.Fatalf("empty profile: %+v %v", empty, err)
	}
	if _, err := summarizeCPUProfile([]byte("not gzip")); err == nil {
		t.Fatal("malformed profile accepted")
	}
}
