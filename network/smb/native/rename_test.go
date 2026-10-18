package native

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/tinyrange/trex/network/smb"
)

func TestCaseOnlyRenameAndChildSharing(t *testing.T) {
	r, dir := rootFixture(t, false)
	f := mustOpen(t, r, "Hello.txt", options(smb.AccessRead|smb.AccessDelete))
	if e := f.Rename("HELLO.TXT", false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "HELLO.TXT")); e != nil {
		t.Fatal(e)
	}
	if e := f.SetDeletePending(true); e != nil {
		t.Fatal(e)
	}
	if e := f.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "HELLO.TXT")); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
	os.Mkdir(filepath.Join(dir, "parent"), 0700)
	os.WriteFile(filepath.Join(dir, "parent", "child"), []byte("x"), 0600)
	o := options(smb.AccessRead | smb.AccessDelete)
	o.Directory = true
	d := mustOpen(t, r, "parent", o)
	childOptions := options(smb.AccessRead)
	childOptions.Share = smb.AccessRead
	child := mustOpen(t, r, "parent/child", childOptions)
	if e := d.Rename("moved", false); !errors.Is(e, smb.ErrSharingViolation) {
		t.Fatal(e)
	}
	child.Close()
	if e := d.Rename("moved", false); e != nil {
		t.Fatal(e)
	}
}
