package iso9660

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/auto/adapter"
)

type corpusReader struct {
	*os.File
	size int64
	read int64
}

func (r *corpusReader) Size() int64 { return r.size }
func (r *corpusReader) ReadAt(p []byte, off int64) (int, error) {
	if int64(len(p)) > 16<<20-r.read {
		return 0, fmt.Errorf("metadata read budget exceeded")
	}
	r.read += int64(len(p))
	return r.File.ReadAt(p, off)
}

// Set TREX_NAS_ROOT to validate the audited media without checking copyrighted
// images into the repository. Only metadata and one small file sample are read.
func TestRockRidgeNASCorpus(t *testing.T) {
	root := os.Getenv("TREX_NAS_ROOT")
	if root == "" {
		t.Skip("set TREX_NAS_ROOT for optical-media corpus")
	}
	for _, name := range []string{
		"fedora/fedora_server_43/Fedora Server 43 1.6 Netinstall (x86_64).iso",
		"ibm/ibm_i_7.5_download_set/Virtual_IO_Server_Base_Install_2.2.6.65_Flash_072020_LCD8236306.iso",
		"ibm/zos/RDzUnitTest_v803_Desktop_Install.iso",
		"ibm/zos/RDzUnitTest_v803_QSG.ISO",
		"ibm/zos/RDzUnitTest_v803_SYSzSWdist_disc3.iso",
		"ibm/zos/RDzUnitTest_v803_SYSzSWdist_disc4.iso",
		"ibm/zos/RDzUnitTest_v803_SYSzSWdist_disc5.iso",
		"ibm/zos/RDzUnitTest_v803_SYSzSWdist_disc7.iso",
		"microsoft/windows_xp/Microsoft Windows XP SP2 Platform SDK.iso",
	} {
		t.Run(filepath.Base(name), func(t *testing.T) {
			f, err := os.Open(filepath.Join(root, filepath.FromSlash(name)))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			stat, err := f.Stat()
			if err != nil {
				t.Fatal(err)
			}
			r := &corpusReader{File: f, size: stat.Size()}
			img, err := newISOImage(adapter.File(r))
			if err != nil {
				t.Fatal(err)
			}
			if !img.rockRidge {
				t.Fatal("missing Rock Ridge tree")
			}
			view, err := adapter.Parsed(img, auto.Options{MaxEntries: 100000})
			if err != nil {
				t.Fatal(err)
			}
			count, links, modes := 0, 0, 0
			sampled := false
			var walk func(auto.View, int) error
			walk = func(view auto.View, depth int) error {
				if depth > 256 {
					return fmt.Errorf("excessively deep tree")
				}
				entries, err := view.Entries()
				if err != nil {
					return err
				}
				for _, entry := range entries {
					count++
					if _, ok := entry.Attributes["mode"]; ok {
						modes++
					}
					if entry.Kind == "symlink" {
						links++
						want := "../../usr/sys/inst.images/mksysb_image"
						if entry.Name == "mksysb2" {
							want += "2"
						}
						if entry.Reader != nil || entry.Attributes["link"] != want {
							return fmt.Errorf("unexpected link: %+v", entry)
						}
					}
					if entry.View != nil && entry.Name != "$metadata" {
						if err := walk(entry.View, depth+1); err != nil {
							return err
						}
					}
					if !sampled && entry.Reader != nil && entry.Reader.Size() > 0 && entry.Name != "boot_catalog.bin" {
						p := make([]byte, min(4096, entry.Reader.Size()))
						if _, err := entry.Reader.ReadAt(p, 0); err != nil && err != io.EOF {
							return err
						}
						sampled = true
					}
				}
				return nil
			}
			if err := walk(view, 0); err != nil {
				t.Fatal(err)
			}
			if modes == 0 || !sampled {
				t.Fatal("metadata or sample missing")
			}
			if filepath.Base(name) == "Virtual_IO_Server_Base_Install_2.2.6.65_Flash_072020_LCD8236306.iso" && links != 2 {
				t.Fatal("expected both VIOS links", links)
			}
			if filepath.Base(name) == "RDzUnitTest_v803_SYSzSWdist_disc3.iso" {
				for _, p := range []string{"dvd3", "sbcic1.gz", "sbdb91.gz"} {
					if _, err := img.lookup(p); err != nil {
						t.Fatal(err)
					}
				}
			}
			t.Logf("entries=%d POSIX=%d symlinks=%d source_bytes=%d", count, modes, links, r.read)
		})
	}
}
