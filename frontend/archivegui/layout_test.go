package archivegui

import (
	"testing"

	"github.com/tinyrange/gowin/window"
)

func TestCompactLayoutHitTargetsAndFolderToggle(t *testing.T) {
	b := menuBrowser(t)
	if b.listLeft() != 0 {
		t.Fatal("folder tree should be hidden by default")
	}
	// Full-width list rows, including the former tree region, select files.
	b.click(35, listTop+rowHeight+8, 1100, 720)
	if b.selected != 1 {
		t.Fatal("compact row selection", b.selected)
	}
	b.contextMenu(35, listTop+rowHeight+8)
	if b.menu == nil || !b.menu.items[1].enabled {
		t.Fatal("context menu used stale row geometry")
	}
	b.key(window.InputEvent{Key: window.KeyEscape}, 20)
	b.click(4+6*52+20, 40, 1100, 720)
	if b.listLeft() != 210 {
		t.Fatal("Folders button did not reveal tree")
	}
	b.click(float32(b.listLeft()+35), listTop+8, 1100, 720)
	if b.selected != 0 {
		t.Fatal("tree shifted file hit targets incorrectly")
	}
	b.mainMenu(2)
	b.menu.selected = 0
	b.menuKey(window.InputEvent{Key: window.KeyEnter})
	if b.showTree {
		t.Fatal("View menu did not hide tree")
	}
	cols := b.columns(1100)
	b.click(cols[2].x+20, 112, 1100, 720)
	if b.column != 3 {
		t.Fatal("packed size heading did not sort")
	}
}

func TestDetailPresentationUsesAvailableMetadata(t *testing.T) {
	b := menuBrowser(t)
	var fileName string
	for _, n := range b.visible {
		if n.Reader() != nil {
			fileName = n.Name()
			if packedSize(n) < 0 || detailValue(n, 3) == "" {
				t.Fatal("ZIP packed size missing")
			}
			if detailValue(n, 1) != "256" {
				t.Fatal("file size", detailValue(n, 1))
			}
		}
	}
	if fileName == "" || groupNumber(12345678) != "12 345 678" || groupNumber(-1) != "" {
		t.Fatal("size formatting")
	}
	b.label = "L:\\"
	b.loc.path = "/pcworld/disc.iso"
	if b.displayPath() != "L:\\pcworld\\disc.iso" {
		t.Fatal(b.displayPath())
	}
}
