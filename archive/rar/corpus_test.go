package rar

import (
	"os"
	"path/filepath"
	"testing"
)

type corpusSource struct {
	*os.File
	size int64
}

func (s corpusSource) Size() int64 { return s.size }

// Optional regression media stays on the caller's archive; tests never copy
// copyrighted payloads into testdata or extract files to the host.
func TestCorpus(t *testing.T) {
	root := os.Getenv("TREX_ARCHIVE_CORPUS")
	if root == "" {
		t.Skip("set TREX_ARCHIVE_CORPUS to the NAS archive root")
	}
	for _, name := range []string{
		"microsoft/windows_95/chicago_build_collection/4.00.490/Microsoft Windows 95 (''Chicago'' 4.00.490) (beta).rar",
		"microsoft/windows_95/chicago_build_collection/4.00.302/Windows 95.ver.4.00.302.English.rar",
		"microsoft/windows_95/chicago_build_collection/4.00.310/floppy/Windows 95.ver.4.00.310 (Floppy).English.rar",
	} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			src, e := os.Open(filepath.Join(root, name))
			if e != nil {
				t.Fatal(e)
			}
			defer src.Close()
			st, e := src.Stat()
			if e != nil {
				t.Fatal(e)
			}
			a, e := Open(corpusSource{src, st.Size()}, 100000)
			if e != nil {
				t.Fatal(e)
			}
			for _, f := range a.Files {
				if f.Directory {
					continue
				}
				if e = f.Verify(); e != nil {
					t.Fatal(e)
				}
			}
			// Reverse member order forces solid-chain reconstruction and cache eviction.
			for i := len(a.Files) - 1; i >= 0; i-- {
				f := a.Files[i]
				if f.Directory || f.Size() == 0 {
					continue
				}
				b := make([]byte, min(f.Size(), 31))
				if _, e = f.ReadAt(b, 0); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}
