package repo

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestPageEditsReuseBlocksAndKeepSnapshots(t *testing.T) {
	for _, optimized := range []bool{false, true} {
		t.Run(map[bool]string{false: "v2", true: "v3"}[optimized], func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "r.scs")
			createTestMode := createTest
			if optimized {
				createTestMode = createTestOptimized
			}
			r, err := createTestMode(p)
			must(t, err)
			defer r.Close()
			w := r.Empty()
			original := bytes.Repeat([]byte("abcdef"), 2000)
			must(t, w.WriteFile("f", original))
			old, err := w.Snapshot()
			must(t, err)
			base, err := w.OpenReader("f")
			must(t, err)
			page := bytes.Repeat([]byte("x"), BlockSize)
			must(t, w.WritePages("f", base, int64(len(original)), int64(len(original)), map[int64][]byte{1: page}))
			expected := bytes.Clone(original)
			copy(expected[BlockSize:2*BlockSize], page)
			readEquals(t, w, "f", expected)
			untouched, err := r.Fork(old)
			must(t, err)
			readEquals(t, untouched, "f", original)
			before, err := w.Stat("f")
			must(t, err)
			base.Close()
			base, err = w.OpenReader("f")
			must(t, err)
			page[0] = 'y'
			must(t, w.WritePages("f", base, int64(len(original)), int64(len(original)), map[int64][]byte{1: page}))
			after, err := w.Stat("f")
			must(t, err)
			if before.Blocks[0] != after.Blocks[0] || before.Blocks[2] != after.Blocks[2] || before.Blocks[1] == after.Blocks[1] {
				t.Fatal("unchanged blocks not shared")
			}
			// Invalid input must not replace the previous entry.
			if err = w.WritePages("f", base, 10, 0, map[int64][]byte{0: []byte("short")}); err == nil {
				t.Fatal("accepted short page")
			}
			expected[BlockSize] = 'y'
			readEquals(t, w, "f", expected)
			base.Close()
		})
	}
}
