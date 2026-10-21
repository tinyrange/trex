package native

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tinyrange/trex/network/smb"
)

func rootFixture(t *testing.T, readonly bool) (*Root, string) {
	t.Helper()
	if !supportedHost {
		t.Skip("unsupported native backend")
	}
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "Hello.txt"), []byte("original"), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := OpenRoot(dir, readonly)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return r, dir
}
func options(access smb.Access) smb.OpenOptions {
	return smb.OpenOptions{Access: access, Share: 7, Disposition: smb.OpenExisting}
}
func mustOpen(t *testing.T, r *Root, name string, o smb.OpenOptions) smb.File {
	t.Helper()
	f, _, e := r.Open(name, o)
	if e != nil {
		t.Fatal(name, e)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
func TestRootReadWriteRenameDelete(t *testing.T) {
	r, dir := rootFixture(t, false)
	o := options(smb.AccessRead | smb.AccessWrite | smb.AccessDelete | smb.AccessMetadataWrite)
	o.Disposition = smb.CreateNew
	f, action, e := r.Open("created.txt", o)
	if e != nil || action != 2 {
		t.Fatal(action, e)
	}
	if _, e = f.WriteAt([]byte("abcdef"), 0); e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(3); e != nil {
		t.Fatal(e)
	}
	if e = f.Sync(); e != nil {
		t.Fatal(e)
	}
	if e = f.Rename("renamed.txt", false); e != nil {
		t.Fatal(e)
	}
	if e = f.SetTimes(time.Unix(100000, 0), time.Unix(200000, 0)); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4)
	if count, e := f.ReadAt(b, 0); count != 3 || e != io.EOF || string(b[:3]) != "abc" {
		t.Fatal(count, string(b), e)
	}
	if e = f.SetDeletePending(true); e != nil {
		t.Fatal(e)
	}
	if _, _, e = r.Open("renamed.txt", options(smb.AccessRead)); !errors.Is(e, smb.ErrDeletePending) {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(dir, "renamed.txt")); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal("not deleted", e)
	}
	if _, e = f.WriteAt([]byte("x"), 0); !errors.Is(e, fs.ErrClosed) {
		t.Fatal(e)
	}
}
func TestSharingBeforeTruncationAndHardlinkIdentity(t *testing.T) {
	r, dir := rootFixture(t, false)
	o := options(smb.AccessRead)
	o.Share = smb.AccessRead
	f := mustOpen(t, r, "hello.TXT", o)
	write := options(smb.AccessWrite)
	write.Disposition = smb.Overwrite
	if _, _, e := r.Open("Hello.txt", write); !errors.Is(e, smb.ErrSharingViolation) {
		t.Fatal("sharing", e)
	}
	b, e := os.ReadFile(filepath.Join(dir, "Hello.txt"))
	if e != nil || string(b) != "original" {
		t.Fatal("truncated before access check", e, string(b))
	}
	if e := os.Link(filepath.Join(dir, "Hello.txt"), filepath.Join(dir, "alias.txt")); e == nil {
		if _, _, e := r.Open("alias.txt", write); !errors.Is(e, smb.ErrSharingViolation) {
			t.Fatal("alias bypassed sharing", e)
		}
	}
	f.Close()
	g := mustOpen(t, r, "Hello.txt", options(smb.AccessRead))
	if _, e := g.WriteAt([]byte("x"), 0); !errors.Is(e, fs.ErrPermission) {
		t.Fatal("read handle allowed write", e)
	}
}
func TestHardlinkRenameUsesRequestedLink(t *testing.T) {
	r, dir := rootFixture(t, false)
	if e := os.Link(filepath.Join(dir, "Hello.txt"), filepath.Join(dir, "alias.txt")); e != nil {
		t.Skip(e)
	}
	a := mustOpen(t, r, "Hello.txt", options(smb.AccessRead|smb.AccessDelete))
	b := mustOpen(t, r, "alias.txt", options(smb.AccessRead|smb.AccessDelete))
	if e := b.Rename("moved.txt", false); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "Hello.txt")); e != nil {
		t.Fatal("renamed wrong link", e)
	}
	if e := b.SetDeletePending(true); e != nil {
		t.Fatal(e)
	}
	b.Close()
	a.Close()
	if _, e := os.Stat(filepath.Join(dir, "moved.txt")); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal("pending link not deleted", e)
	}
	if _, e := os.Stat(filepath.Join(dir, "Hello.txt")); e != nil {
		t.Fatal("deleted wrong link", e)
	}
}
func TestReadOnlyCannotMutate(t *testing.T) {
	r, dir := rootFixture(t, true)
	for _, access := range []smb.Access{smb.AccessWrite, smb.AccessDelete, smb.AccessMetadataWrite} {
		if _, _, e := r.Open("Hello.txt", options(access)); !errors.Is(e, fs.ErrPermission) {
			t.Fatal(access, e)
		}
	}
	for _, disposition := range []uint32{smb.CreateNew, smb.OpenIf, smb.OverwriteIf, smb.Supersede} {
		o := options(smb.AccessRead)
		o.Disposition = disposition
		if _, _, e := r.Open("new.txt", o); !errors.Is(e, fs.ErrPermission) {
			t.Fatal(disposition, e)
		}
	}
	f := mustOpen(t, r, "Hello.txt", options(smb.AccessRead))
	for _, e := range []error{f.Truncate(0), f.Rename("x", false), f.SetDeletePending(true), f.SetTimes(time.Now(), time.Now())} {
		if !errors.Is(e, fs.ErrPermission) {
			t.Fatal(e)
		}
	}
	b, e := os.ReadFile(filepath.Join(dir, "Hello.txt"))
	if e != nil || string(b) != "original" {
		t.Fatal(e, string(b))
	}
}
func TestRootRejectsEscapesAndSymlinks(t *testing.T) {
	r, dir := rootFixture(t, false)
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")
	os.WriteFile(secret, []byte("untouched"), 0600)
	names := []string{"../secret", "a/../../secret", "/secret", "C:/secret", "Hello.txt:stream", "NUL", "a/../Hello.txt", "Hello.txt.", "a//b"}
	if e := os.Symlink(outside, filepath.Join(dir, "escape")); e == nil {
		names = append(names, "escape/secret", "escape/new")
	}
	if e := os.Symlink(secret, filepath.Join(dir, "link")); e == nil {
		names = append(names, "link")
	}
	o := options(smb.AccessWrite)
	o.Disposition = smb.OverwriteIf
	for _, name := range names {
		if f, _, e := r.Open(name, o); e == nil {
			f.Close()
			t.Fatalf("unsafe open %q", name)
		}
	}
	f := mustOpen(t, r, "Hello.txt", options(smb.AccessDelete))
	for _, name := range names {
		if e := f.Rename(name, true); e == nil {
			t.Fatalf("unsafe rename %q", name)
		}
	}
	b, e := os.ReadFile(secret)
	if e != nil || string(b) != "untouched" {
		t.Fatal("outside file changed", e, string(b))
	}
}
func TestDirectoryRenameUpdatesOpenChildren(t *testing.T) {
	r, dir := rootFixture(t, false)
	os.Mkdir(filepath.Join(dir, "old"), 0700)
	os.WriteFile(filepath.Join(dir, "old", "file"), []byte("x"), 0600)
	o := options(smb.AccessRead | smb.AccessDelete)
	o.Directory = true
	d := mustOpen(t, r, "old", o)
	f := mustOpen(t, r, "old/file", options(smb.AccessRead|smb.AccessDelete))
	if e := d.Rename("new", false); e != nil {
		t.Fatal(e)
	}
	if e := f.SetDeletePending(true); e != nil {
		t.Fatal(e)
	}
	if e := f.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "new", "file")); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal(e)
	}
}
func TestRootSymlinkReplacementRace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation privileges differ")
	}
	r, dir := rootFixture(t, false)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "sentinel"), []byte("protected"), 0600)
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			os.Symlink(outside, filepath.Join(dir, "swap"))
			os.Remove(filepath.Join(dir, "swap"))
		}
	}()
	for i := 0; i < 100; i++ {
		o := options(smb.AccessWrite)
		o.Disposition = smb.OverwriteIf
		f, _, e := r.Open("swap/sentinel", o)
		if e == nil {
			f.WriteAt([]byte("bad"), 0)
			f.Close()
		}
	}
	close(stop)
	<-done
	b, e := os.ReadFile(filepath.Join(outside, "sentinel"))
	if e != nil || string(b) != "protected" {
		t.Fatal(e, string(b))
	}
}
