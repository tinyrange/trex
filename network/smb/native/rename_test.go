package native

import (
	"errors"
	"fmt"
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

func TestDirectoryRenamePreservesChildEnumeration(t *testing.T) {
	r, dir := rootFixture(t, false)
	if err := os.MkdirAll(filepath.Join(dir, "parent", "child"), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if err := os.WriteFile(filepath.Join(dir, "parent", "child", fmt.Sprintf("file-%02d", i)), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	o := options(smb.AccessRead | smb.AccessDelete)
	o.Directory = true
	parent := mustOpen(t, r, "parent", o)
	child := mustOpen(t, r, "parent/child", o)
	first, err := child.ReadDir(3)
	if err != nil || len(first) != 3 {
		t.Fatal(first, err)
	}
	if err = parent.Rename("moved", false); err != nil {
		t.Fatal(err)
	}
	remaining, err := child.ReadDir(128)
	if err != nil || len(remaining) != 7 {
		t.Fatal(remaining, err)
	}
	seen := map[string]bool{}
	for _, info := range append(first, remaining...) {
		if seen[info.Name()] {
			t.Fatal("repeated entry", info.Name())
		}
		if info.Size() != 1 || !info.Mode().IsRegular() {
			t.Fatalf("wrong child metadata: %s %d %v", info.Name(), info.Size(), info.Mode())
		}
		seen[info.Name()] = true
	}
	if err = child.Rewind(); err != nil {
		t.Fatal(err)
	}
	all, err := child.ReadDir(128)
	if err != nil || len(all) != 10 {
		t.Fatalf("rewind after rename: %d entries, %v", len(all), err)
	}
}
