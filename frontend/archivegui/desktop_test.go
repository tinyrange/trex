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

type fakeDesktop struct{ saved string }

func (d *fakeDesktop) SuggestedDestination(name string) string  { return "/chosen/" + name }
func (d *fakeDesktop) Save(_ storage.Reader, name string) error { d.saved = name; return nil }

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
	// Second row is binary.bin. Saving requires an explicit retained destination.
	b.contextMenu(300, 156)
	if b.selected != 1 || !b.menu.items[1].enabled {
		t.Fatal("file context state")
	}
	b.menu.selected = 1
	b.key(window.InputEvent{Key: window.KeyEnter}, 20)
	if b.save == nil || b.busy || d.saved != "" {
		t.Fatal("save did not request a destination")
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
	if d.saved != "/chosen/member.bin" || b.loc.path != "/outer.zip/inner.zip" {
		t.Fatal("save action lost location")
	}
}
func TestContextMenuDismissalAndClamping(t *testing.T) {
	b := menuBrowser(t)
	b.contextMenu(1098, 685)
	if b.menu == nil || b.menu.x+300 > 1100 || b.menu.y+120 > 720 {
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
	if b.menu.selected != 2 {
		t.Fatal("keyboard selected disabled action")
	}
}
func TestSaveFinalOutputNeverOverwritesAndRejectsShortRead(t *testing.T) {
	d := nativeDesktop{}
	dest := filepath.Join(t.TempDir(), "document.txt")
	r := &starfile.Bytes{Data: []byte("retained document")}
	if err := d.Save(r, dest); err != nil {
		t.Fatal(err)
	}
	if err := d.Save(&starfile.Bytes{Data: []byte("replacement")}, dest); !errors.Is(err, os.ErrExist) {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "retained document" {
		t.Fatal("output overwritten", err)
	}
	broken := filepath.Join(t.TempDir(), "broken.txt")
	if err := d.Save(shortReader{}, broken); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if _, err := os.Stat(broken); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("partial output retained", err)
	}
}

type shortReader struct{}

func (shortReader) Size() int64                       { return 100 }
func (shortReader) ReadAt([]byte, int64) (int, error) { return 0, io.EOF }
