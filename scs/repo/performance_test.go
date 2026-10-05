package repo

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func benchmarkWorkspace(b *testing.B, files int, operation string) {
	r, err := createTest(filepath.Join(b.TempDir(), "bench.scs"))
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	w := r.Empty()
	// Bounded directory fanout, with increasing total tree size.
	for i := 0; i < files; i++ {
		dir := fmt.Sprintf("d%06d", i/100)
		if i%100 == 0 {
			if err := w.Mkdir(dir); err != nil {
				b.Fatal(err)
			}
		}
		if err := w.WriteFile(fmt.Sprintf("%s/f%03d", dir, i%100), []byte("initial")); err != nil {
			b.Fatal(err)
		}
	}
	if _, err := w.Snapshot(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		switch operation {
		case "snapshot":
			_, err = w.Snapshot()
		case "fork":
			_, err = w.Fork()
		case "edit-snapshot":
			err = w.WriteFile("d000000/f000", []byte(fmt.Sprint(i)))
			if err == nil {
				_, err = w.Snapshot()
			}
		case "fork-edit-snapshot":
			var f *Workspace
			f, err = w.Fork()
			if err == nil {
				err = f.WriteFile("d000000/f000", []byte(fmt.Sprint(i)))
			}
			if err == nil {
				_, err = f.Snapshot()
			}
		}
		if err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
}

func BenchmarkWorkspace(b *testing.B) {
	for _, n := range []int{100, 10000} {
		for _, op := range []string{"snapshot", "fork", "edit-snapshot", "fork-edit-snapshot"} {
			b.Run(fmt.Sprintf("%d/%s", n, op), func(b *testing.B) { benchmarkWorkspace(b, n, op) })
		}
	}
}

// Opt-in runner for hosts exposing go test but not its -bench flags.
func TestWorkspacePerformance(t *testing.T) {
	if os.Getenv("SCS_BENCH") != "1" {
		t.Skip("set SCS_BENCH=1 to measure workspace operations")
	}
	for _, n := range []int{100, 10000} {
		for _, op := range []string{"snapshot", "fork", "edit-snapshot", "fork-edit-snapshot"} {
			result := testing.Benchmark(func(b *testing.B) { benchmarkWorkspace(b, n, op) })
			t.Logf("%d/%s: %s %s", n, op, result.String(), result.MemString())
		}
	}
}
