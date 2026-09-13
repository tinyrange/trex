package archivegui

import (
	"fmt"
	"image/png"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tinyrange/gowin/graphics"
	"github.com/tinyrange/gowin/window"
)

// Opt-in because this opens an actual desktop window. The fixture remains in
// memory; an optional screenshot is a final, independently viewable artifact.
func TestDesktop(t *testing.T) {
	if os.Getenv("TREX_BROWSER_GUI_TEST") != "1" {
		t.Skip("set TREX_BROWSER_GUI_TEST=1 with a desktop display")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	root := fixture(t)
	label := "In-memory nested archive test"
	target := "/outer.zip/inner.zip"
	if dir := os.Getenv("TREX_BROWSER_ROOT"); dir != "" {
		s, r, err := OpenDirectory(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		root = r
		label = dir
		target = os.Getenv("TREX_BROWSER_OPEN")
		if target == "" {
			t.Fatal("TREX_BROWSER_OPEN required with TREX_BROWSER_ROOT")
		}
	}
	start := time.Now()
	step := 0
	err := run(root, label, "/", func(b *browser, f graphics.Frame) error {
		if time.Since(start) > 60*time.Second {
			return fmt.Errorf("desktop test timeout: %s", b.status)
		}
		if b.busy {
			return nil
		}
		if strings.HasPrefix(b.status, "Cannot") {
			return fmt.Errorf("desktop navigation: %s", b.status)
		}
		switch step {
		case 0:
			if b.text.font == b.text.monoFont || math.Abs(float64(b.text.MonoAdvance(15, "iiii0000")-b.text.MonoAdvance(15, "WWWWffff"))) > 0.01 {
				return fmt.Errorf("preview font is not independently monospaced")
			}
			b.key(window.InputEvent{Key: window.KeyL, Mods: window.ModCtrl}, 20)
			b.insert(target)
			b.key(window.InputEvent{Key: window.KeyEnter}, 20)
		case 1:
			if len(b.visible) == 0 {
				return fmt.Errorf("archive contains no rows")
			}
			b.key(window.InputEvent{Key: window.KeyF, Mods: window.ModCtrl}, 20)
			b.insert(b.visible[0].Name())
			if len(b.visible) == 0 {
				return fmt.Errorf("filter lost matching row")
			}
			b.key(window.InputEvent{Key: window.KeyEscape}, 20)
			b.key(window.InputEvent{Key: window.KeyLeft, Mods: window.ModAlt}, 20)
		case 2:
			if b.loc.path != "/" {
				return fmt.Errorf("Back did not restore root")
			}
			b.key(window.InputEvent{Key: window.KeyRight, Mods: window.ModAlt}, 20)
		case 3:
			if b.loc.path != target {
				return fmt.Errorf("Forward did not restore archive")
			}
			row := 0
			for i, n := range b.visible {
				if n.Reader() != nil {
					row = i
					break
				}
			}
			b.contextMenu(float32(b.listLeft()+60), float32(listTop+rowHeight/2+row*rowHeight))
			if b.menu == nil {
				return fmt.Errorf("right-click menu did not open")
			}
		case 4:
			b.key(window.InputEvent{Key: window.KeyEscape}, 20)
			if b.menu != nil {
				return fmt.Errorf("Escape did not dismiss context menu")
			}
		case 5:
			if output := os.Getenv("TREX_BROWSER_SCREENSHOT"); output != "" {
				img, err := f.ScreenshotLogical()
				if err != nil {
					return err
				}
				out, err := os.Create(output)
				if err != nil {
					return err
				}
				err = png.Encode(out, img)
				closeErr := out.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
			}
			t.Logf("Desktop browsed %s: %d entries; filter, Back/Forward and context menu passed", target, len(b.visible))
			// Reuse the native window: the Windows gowin backend registers one
			// process-wide window class. Only the portable source is changed.
			b.root = fixture(t)
			b.label = "In-memory hex fixture"
			b.history = nil
			b.historyIndex = -1
			b.navigate("/outer.zip/inner.zip/binary.bin", -1)
		case 6:
			if err := checkHexDesktop(b, f); err != nil {
				return err
			}
			return errExit
		}
		step++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if step != 6 {
		t.Fatal("window closed before smoke completed")
	}
}

func checkHexDesktop(b *browser, f graphics.Frame) error {
	if b.loc.format != "Hex preview" || len(b.loc.preview) < 16 {
		return fmt.Errorf("expected multiline hex preview: %s", b.status)
	}
	if math.Abs(float64(b.text.MonoAdvance(15, "iiii0000")-b.text.MonoAdvance(15, "WWWWffff"))) > 0.01 {
		return fmt.Errorf("hex glyph widths differ")
	}
	b.key(window.InputEvent{Key: window.KeyRight}, 20)
	if b.previewX != 4 {
		return fmt.Errorf("horizontal preview scroll failed")
	}
	b.key(window.InputEvent{Key: window.KeyLeft}, 20)
	if output := os.Getenv("TREX_BROWSER_HEX_SCREENSHOT"); output != "" {
		img, err := f.ScreenshotLogical()
		if err != nil {
			return err
		}
		out, err := os.Create(output)
		if err != nil {
			return err
		}
		err = png.Encode(out, img)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}
