package auto_test

import (
	"bytes"
	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
	"io"
	"os"
	"path/filepath"
	"testing"
)

type archiveMediaFile struct {
	*os.File
	size int64
}

func (f archiveMediaFile) Size() int64 { return f.size }
func gapMedia(t *testing.T, path string) storage.Reader {
	t.Helper()
	root := os.Getenv("TREX_PARSING_ARCHIVE")
	if root == "" {
		t.Skip("set TREX_PARSING_ARCHIVE to the caller-supplied software archive")
	}
	f, err := os.Open(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	s, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return archiveMediaFile{f, s.Size()}
}
func readGapTree(t *testing.T, n *auto.Node) (int, int64) {
	t.Helper()
	children, err := n.Children()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	var size int64
	for _, c := range children {
		if c.Summary().Kind == "directory" {
			a, b := readGapTree(t, c)
			count += a
			size += b
		} else if r := c.Reader(); r != nil {
			n, err := io.Copy(io.Discard, io.NewSectionReader(r, 0, r.Size()))
			if err != nil || n != r.Size() {
				t.Fatalf("%s: %d/%d %v", c.Name(), n, r.Size(), err)
			}
			count++
			size += n
		}
	}
	return count, size
}
func TestArchiveGapMedia(t *testing.T) {
	t.Run("installers", func(t *testing.T) {
		source := gapMedia(t, "pcworld/PC World New Zealand 2005-09.iso")
		root := auto.Open(source, "disc", auto.Options{})
		for _, c := range []struct {
			path, format string
			count        int
			size         int64
		}{
			{"browsers/Mozilla Firefox 1.0.6/Firefox Setup 1.0.6.exe", "7z", 12, 17633003},
			{"browsers/Mozilla Thunderbird 1.0.6 Win/Thunderbird Setup 1.0.6.exe", "7z", 13, 23566777},
			{"essentials/AVGFree/avg70free_323a539.exe", "rar", 7, 13488266},
			{"essentials/ATI/5-7_xp-2k_dd_cp_wdm_24085.exe", "nsis", 139, 35229227},
			{"Games/motogp_urt_3_demo.exe", "zip", 97, 169802924},
			{"browsers/Opera 8.0.2/ow32enen802.exe", "zip", 79, 5187837},
			{"browsers/Mozilla Win 1.7.11/mozilla-win32-1.7.11-installer.exe", "mozilla_sfx", 18, 12330832},
		} {
			t.Run(c.path, func(t *testing.T) {
				n, err := root.Resolve(c.path)
				if err != nil {
					t.Fatal(err)
				}
				m, err := n.Metadata()
				if err != nil || m.Format != c.format {
					t.Fatalf("%+v %v", m, err)
				}
				count, size := readGapTree(t, n)
				if count != c.count || size != c.size {
					t.Fatalf("%d files, %d bytes; want %d/%d", count, size, c.count, c.size)
				}
			})
		}
	})
	t.Run("mac", func(t *testing.T) {
		source := gapMedia(t, "apple/mac_os_x_10.3.0/Apple Mac OS X 10.3.0 - Disk 1.7z")
		root := auto.Open(source, "media", auto.Options{})
		volume, err := root.Resolve("Apple Mac OS X 10.3.0 - Disk 1.iso/blocks-512/partition-9")
		if err != nil {
			t.Fatal(err)
		}
		cs, err := volume.Children()
		if err != nil || len(cs) != 21 {
			t.Fatalf("%d entries %v", len(cs), err)
		}
		kernel, err := volume.Resolve("mach_kernel/data")
		if err != nil {
			t.Fatal(err)
		}
		r := kernel.Reader()
		data, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
		if err != nil || len(data) != 3819896 || !bytes.HasPrefix(data, []byte{0xfe, 0xed, 0xfa, 0xce}) {
			t.Fatalf("kernel %d %v", len(data), err)
		}
	})
	t.Run("helios", func(t *testing.T) {
		source := gapMedia(t, "oxide/helios/Oxide Helios Generic TTYA Base Image.raw.zst")
		result, err := auto.Identify(source, auto.Options{})
		if err != nil {
			t.Fatal(err)
		}
		decoded, ok := result.View.(*auto.DecodedView)
		if !ok {
			t.Fatalf("unexpected view %T", result.View)
		}
		// The opt-in real-image test retains at most 2 GiB in memory to avoid
		// repeatedly replaying a sequential zstd stream for random ZFS reads.
		data, err := io.ReadAll(io.NewSectionReader(decoded.Reader, 0, 2<<30))
		if err != nil || len(data) != 1572864000 {
			t.Fatalf("disk %d %v", len(data), err)
		}
		root := auto.Open(bytes.NewReader(data), "disk", auto.Options{})
		for _, c := range []struct {
			path   string
			size   int
			prefix []byte
		}{{"etc/release", 17, []byte("  Oxide Helios 3\n")}, {"usr/bin/ls", 47372, []byte{0x7f, 'E', 'L', 'F'}}} {
			n, err := root.Resolve("partition2/ROOT/1b4206e9/files/" + c.path)
			if err != nil {
				t.Fatal(err)
			}
			r := n.Reader()
			b, err := io.ReadAll(io.NewSectionReader(r, 0, r.Size()))
			if err != nil || len(b) != c.size || !bytes.HasPrefix(b, c.prefix) {
				t.Fatalf("%s: %d %v", c.path, len(b), err)
			}
		}
	})
}
