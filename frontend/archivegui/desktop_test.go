package archivegui

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/tinyrange/gowin/window"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

type fakeDesktop struct {
	native   bool
	opened   int
	saved    string
	saveOpen bool
}

func (d *fakeDesktop) CanOpen(storage.Reader) bool             { return d.native }
func (d *fakeDesktop) Open(storage.Reader) error               { d.opened++; return nil }
func (d *fakeDesktop) SuggestedDestination(name string) string { return "/chosen/" + name }
func (d *fakeDesktop) Save(_ storage.Reader, name string, open bool) error {
	d.saved = name
	d.saveOpen = open
	return nil
}

func menuBrowser(t *testing.T) *browser {
	t.Helper()
	b := newBrowser(fixture(t), "fixture")
	loc, err := readLocation(b.root, "/outer.zip/inner.zip")
	if err != nil {
		t.Fatal(err)
	}
	b.results <- result{loc: loc, history: -1}
	b.receive()
	b.width = 1100
	b.height = 720
	return b
}
func TestContextMenuAndExplicitDesktopActions(t *testing.T) {
	b := menuBrowser(t)
	d := &fakeDesktop{}
	b.desktop = d
	// First row is a directory. Right-click selects but does not navigate.
	b.contextMenu(300, 130)
	if b.selected != 0 || b.busy || b.menu == nil || b.menu.items[1].enabled {
		t.Fatal("directory context state")
	}
	b.key(window.InputEvent{Key: window.KeyEscape}, 20)
	if b.menu != nil || b.selected != 0 {
		t.Fatal("Escape changed selection")
	}
	// Second row is binary.bin. Menu Open must request a retained destination.
	b.contextMenu(300, 156)
	if b.selected != 1 || !b.menu.items[1].enabled {
		t.Fatal("file context state")
	}
	b.menu.selected = 1
	b.key(window.InputEvent{Key: window.KeyEnter}, 20)
	if b.save == nil || !b.save.open || d.opened != 0 || b.busy {
		t.Fatal("archive member launched without a destination")
	}
	b.insert("/chosen/member.bin")
	b.confirmSave()
	req := <-b.requests
	message, err := req.action()
	if err != nil {
		t.Fatal(err)
	}
	b.results <- result{action: true, message: message}
	b.receive()
	if d.saved != "/chosen/member.bin" || !d.saveOpen || b.loc.path != "/outer.zip/inner.zip" {
		t.Fatal("save action lost location")
	}
	// A native file can be handed off directly, only on the explicit action.
	d.native = true
	n, p := b.target()
	b.openSystem(n, p)
	req = <-b.requests
	if d.opened != 0 {
		t.Fatal("shell open ran on UI thread")
	}
	if _, err := req.action(); err != nil || d.opened != 1 {
		t.Fatal("native shell action not routed", err)
	}
}
func TestContextMenuDismissalAndClamping(t *testing.T) {
	b := menuBrowser(t)
	b.contextMenu(1098, 685)
	if b.menu == nil || b.menu.x+300 > 1100 || b.menu.y+148 > 720 {
		t.Fatal("menu escaped viewport")
	}
	b.menuClick(0, 0)
	if b.menu != nil || b.busy {
		t.Fatal("outside click did not dismiss")
	}
	b.contextMenu(300, 130)
	b.key(window.InputEvent{Key: window.KeyDown}, 20)
	if b.menu.selected != 0 {
		t.Fatal("keyboard menu navigation")
	}
	b.key(window.InputEvent{Key: window.KeyDown}, 20)
	if b.menu.selected != 3 {
		t.Fatal("keyboard selected disabled action")
	}
}
func TestSaveFinalOutputNeverOverwritesAndRejectsShortRead(t *testing.T) {
	d := nativeDesktop{}
	dest := filepath.Join(t.TempDir(), "document.txt")
	r := &starfile.Bytes{Data: []byte("retained document")}
	if err := d.Save(r, dest, false); err != nil {
		t.Fatal(err)
	}
	if err := d.Save(&starfile.Bytes{Data: []byte("replacement")}, dest, false); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "retained document" {
		t.Fatal("output overwritten", err)
	}
	broken := filepath.Join(t.TempDir(), "broken.txt")
	if err := d.Save(shortReader{}, broken, false); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if _, err := os.Stat(broken); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial output retained", err)
	}
}

type shortReader struct{}

func (shortReader) Size() int64                       { return 100 }
func (shortReader) ReadAt([]byte, int64) (int, error) { return 0, io.EOF }

// Opt-in shell smoke opens an existing, explicitly selected document using its
// registered handler. It does not run as part of the ordinary test suite.
func TestSystemViewer(t *testing.T) {
	name := os.Getenv("TREX_BROWSER_VIEWER_FILE")
	if name == "" {
		t.Skip("set TREX_BROWSER_VIEWER_FILE to an existing document")
	}
	s, root, err := OpenDirectory(filepath.Dir(name))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n, err := root.Resolve(filepath.Base(name))
	if err != nil {
		t.Fatal(err)
	}
	if err := (nativeDesktop{}).Open(n.Reader()); err != nil {
		t.Fatal(err)
	}
	t.Log("Opened in system viewer:", name)
}
