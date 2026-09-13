package archivegui

import (
	"errors"
	"fmt"
	"image/color"
	"path"
	"strings"
	"time"
	"unicode"

	"github.com/tinyrange/gowin/graphics"
	"github.com/tinyrange/gowin/window"
	"github.com/tinyrange/trex/auto"
)

var errExit = errors.New("browser closed")

type result struct {
	loc     location
	err     error
	history int
	action  bool
	message string
}
type request struct {
	name    string
	history int
	action  func() (string, error)
}
type treeRow struct {
	name, path string
	depth      int
}

type browser struct {
	root                         *auto.Node
	label                        string
	loc                          location
	visible                      []*auto.Node
	visited                      map[string][]*auto.Node
	history                      []string
	historyIndex                 int
	requests                     chan request
	results                      chan result
	done                         chan struct{}
	busy                         bool
	status                       string
	address, filter              string
	focus                        int // 0: list, 1: address, 2: filter
	caret                        int
	selectAll                    bool
	selected, scroll, treeScroll int
	column                       int
	descending                   bool
	lastClick                    time.Time
	lastRow                      int
	desktop                      desktopActions
	menu                         *popupMenu
	save                         *saveDialog
	width, height                int
	showTree                     bool
	previewX                     int
	text                         *uiText
}

func newBrowser(root *auto.Node, label string) *browser {
	return &browser{root: root, label: label, address: "/", historyIndex: -1, selected: -1, lastRow: -1,
		desktop: nativeDesktop{}, visited: make(map[string][]*auto.Node), requests: make(chan request, 1), results: make(chan result, 1), done: make(chan struct{})}
}

func (b *browser) worker() {
	for {
		select {
		case <-b.done:
			return
		case req := <-b.requests:
			var res result
			if req.action != nil {
				res.action = true
				res.message, res.err = req.action()
			} else {
				res.loc, res.err = readLocation(b.root, req.name)
				res.history = req.history
			}
			select {
			case b.results <- res:
			case <-b.done:
				return
			}
		}
	}
}

func (b *browser) navigate(name string, history int) {
	if b.busy {
		return
	}
	b.busy = true
	b.status = "Opening " + name + " ..."
	b.requests <- request{name: name, history: history}
}

func (b *browser) receive() {
	select {
	case r := <-b.results:
		b.busy = false
		if r.action {
			if r.err != nil {
				b.status = "Cannot complete action: " + r.err.Error()
			} else {
				b.status = r.message
			}
			return
		}
		if r.err != nil {
			b.status = "Cannot open: " + r.err.Error()
			return
		}
		b.loc = r.loc
		b.address = r.loc.path
		b.filter = ""
		b.focus = 0
		b.scroll = 0
		b.previewX = 0
		b.lastRow = -1
		b.visited = r.loc.ancestors
		if r.loc.preview == nil {
			b.visited[r.loc.path] = r.loc.children
		}
		if r.history >= 0 {
			b.historyIndex = r.history
		} else if b.historyIndex < 0 || b.history[b.historyIndex] != r.loc.path {
			b.history = append(b.history[:b.historyIndex+1], r.loc.path)
			if len(b.history) > 64 {
				b.history = b.history[1:]
			}
			b.historyIndex = len(b.history) - 1
		}
		b.relist()
		b.status = fmt.Sprintf("%d items", len(b.visible))
		if r.loc.preview != nil {
			b.status = r.loc.format
		}
	default:
	}
}

func (b *browser) relist() {
	b.visible = rows(b.loc.children, b.filter, b.column, b.descending)
	b.selected = -1
	b.scroll = 0
}
func (b *browser) openSelected() {
	if b.selected >= 0 && b.selected < len(b.visible) {
		b.navigate(path.Join(b.loc.path, b.visible[b.selected].Name()), -1)
	}
}
func (b *browser) back(delta int) {
	i := b.historyIndex + delta
	if i >= 0 && i < len(b.history) {
		b.navigate(b.history[i], i)
	}
}
func (b *browser) tree() []treeRow {
	out := []treeRow{{b.label, "/", 0}}
	var walk func(string, int)
	walk = func(p string, depth int) {
		for _, n := range b.visited[p] {
			child := path.Join(p, n.Name())
			_, opened := b.visited[child]
			if n.Summary().Kind != "directory" && !opened {
				continue
			}
			out = append(out, treeRow{n.Name(), child, depth})
			if opened {
				walk(child, depth+1)
			}
		}
	}
	walk("/", 1)
	return out
}

func (b *browser) field() *string {
	if b.focus == 3 && b.save != nil {
		return &b.save.destination
	}
	if b.focus == 1 {
		return &b.address
	}
	return &b.filter
}
func (b *browser) focusField(focus int) {
	b.focus = focus
	b.caret = len([]rune(*b.field()))
	b.selectAll = true
}
func (b *browser) insert(s string) {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	r := []rune(*b.field())
	if b.selectAll {
		r = nil
		b.caret = 0
		b.selectAll = false
	}
	b.caret = min(b.caret, len(r))
	r = append(append(append([]rune{}, r[:b.caret]...), []rune(s)...), r[b.caret:]...)
	b.caret += len([]rune(s))
	*b.field() = string(r)
	if b.focus == 2 {
		b.relist()
	}
}

func (b *browser) key(e window.InputEvent, pageSize int) {
	if b.menu != nil {
		b.menuKey(e)
		return
	}
	if b.save != nil {
		if e.Key == window.KeyEscape {
			b.save = nil
			b.focus = 0
			return
		}
		if e.Key == window.KeyEnter || e.Key == window.KeyNumpadEnter {
			b.confirmSave()
			return
		}
		if e.Key == window.KeyTab || (e.Mods&(window.ModCtrl|window.ModSuper) != 0 && (e.Key == window.KeyL || e.Key == window.KeyF)) {
			return
		}
	}
	if b.save == nil && e.Key == window.KeyF10 && e.Mods&window.ModShift != 0 {
		b.contextMenu(float32(b.listLeft()+28), float32(listTop+rowHeight/2+max(0, b.selected-b.scroll)*rowHeight))
		return
	}
	ctrl := e.Mods&(window.ModCtrl|window.ModSuper) != 0
	if b.save == nil && ctrl && e.Key == window.KeyEnter {
		n, p := b.target()
		b.openSystem(n, p)
		return
	}
	if ctrl && e.Key == window.KeyL {
		b.focusField(1)
		return
	}
	if ctrl && e.Key == window.KeyF {
		b.focusField(2)
		return
	}
	if e.Key == window.KeyTab {
		next := (b.focus + 1) % 3
		if e.Mods&window.ModShift != 0 {
			next = (b.focus + 2) % 3
		}
		if next == 0 {
			b.focus = 0
		} else {
			b.focusField(next)
		}
		return
	}
	if e.Key == window.KeyEscape {
		b.focus = 0
		b.filter = ""
		b.relist()
		return
	}
	if e.Mods&window.ModAlt != 0 {
		switch e.Key {
		case window.KeyF:
			if b.save == nil {
				b.mainMenu(0)
			}
		case window.KeyE:
			if b.save == nil {
				b.mainMenu(1)
			}
		case window.KeyV:
			if b.save == nil {
				b.mainMenu(2)
			}
		case window.KeyT:
			if b.save == nil {
				b.mainMenu(3)
			}
		case window.KeyH:
			if b.save == nil {
				b.mainMenu(4)
			}
		case window.KeyLeft:
			b.back(-1)
		case window.KeyRight:
			b.back(1)
		case window.KeyUp:
			b.navigate(path.Dir(b.loc.path), -1)
		}
		return
	}
	if b.focus != 0 {
		if ctrl {
			switch e.Key {
			case window.KeyA:
				b.selectAll = true
			case window.KeyC:
				if b.selectAll {
					_ = window.GetClipboard().SetText(*b.field())
				}
			case window.KeyV:
				b.insert(window.GetClipboard().GetText())
			}
			return
		}
		r := []rune(*b.field())
		b.caret = min(b.caret, len(r))
		switch e.Key {
		case window.KeyEnter, window.KeyNumpadEnter:
			if b.focus == 1 {
				b.navigate(b.address, -1)
			}
			b.focus = 0
		case window.KeyLeft:
			b.caret = max(0, b.caret-1)
			b.selectAll = false
		case window.KeyRight:
			b.caret = min(len(r), b.caret+1)
			b.selectAll = false
		case window.KeyHome:
			b.caret = 0
			b.selectAll = false
		case window.KeyEnd:
			b.caret = len(r)
			b.selectAll = false
		case window.KeyBackspace, window.KeyDelete:
			if b.selectAll {
				b.insert("")
			} else {
				if e.Key == window.KeyBackspace && b.caret > 0 {
					r = append(r[:b.caret-1], r[b.caret:]...)
					b.caret--
				} else if e.Key == window.KeyDelete && b.caret < len(r) {
					r = append(r[:b.caret], r[b.caret+1:]...)
				}
				*b.field() = string(r)
				if b.focus == 2 {
					b.relist()
				}
			}
		}
		return
	}
	if b.loc.preview != nil {
		switch e.Key {
		case window.KeyUp:
			b.scroll--
		case window.KeyLeft:
			b.previewX = max(0, b.previewX-4)
		case window.KeyRight:
			b.previewX += 4
		case window.KeyDown:
			b.scroll++
		case window.KeyPageUp:
			b.scroll -= pageSize
		case window.KeyPageDown:
			b.scroll += pageSize
		case window.KeyHome:
			b.scroll = 0
		case window.KeyEnd:
			b.scroll = len(b.loc.preview)
		case window.KeyBackspace:
			b.navigate(path.Dir(b.loc.path), -1)
		}
		return
	}
	switch e.Key {
	case window.KeyEnter, window.KeyNumpadEnter:
		b.openSelected()
	case window.KeyBackspace:
		b.navigate(path.Dir(b.loc.path), -1)
	case window.KeyUp:
		b.selected--
	case window.KeyDown:
		b.selected++
	case window.KeyHome:
		b.selected = 0
	case window.KeyEnd:
		b.selected = len(b.visible) - 1
	case window.KeyPageUp:
		b.selected -= pageSize
	case window.KeyPageDown:
		b.selected += pageSize
	}
	b.selected = min(max(0, b.selected), len(b.visible)-1)
	if b.selected < b.scroll {
		b.scroll = b.selected
	}
	if b.selected >= b.scroll+pageSize {
		b.scroll = b.selected - pageSize + 1
	}
}

var (
	background = color.RGBA{240, 240, 240, 255}
	paper      = color.RGBA{255, 255, 255, 255}
	ink        = color.RGBA{0, 0, 0, 255}
	muted      = color.RGBA{128, 128, 128, 255}
	border     = color.RGBA{128, 128, 128, 255}
	selection  = color.RGBA{0, 120, 215, 255}
)

// Run opens a gowin native window. Call it on the initial OS thread (required
// by Cocoa). The root may be any portable directory or archive node.
func Run(root *auto.Node, label, initial string) error { return run(root, label, initial, nil) }

// afterDraw is used by the opt-in desktop integration test to inspect the real
// framebuffer and drive exactly the same navigation code as the controls.
func run(root *auto.Node, label, initial string, afterDraw func(*browser, graphics.Frame) error) error {
	win, err := graphics.New(label+" - trex Archive Browser", 1100, 760)
	if err != nil {
		return err
	}
	renderer, err := loadUIText(win)
	if err != nil {
		win.PlatformWindow().Close()
		return err
	}
	win.SetClearColor(background)
	b := newBrowser(root, label)
	b.text = renderer
	go b.worker()
	defer close(b.done)
	b.navigate(initial, -1)
	err = win.Loop(func(f graphics.Frame) error {
		b.receive()
		w, h := f.WindowSize()
		b.width, b.height = w, h
		pageSize := max(1, (h-listTop-statusHeight)/rowHeight)
		for _, e := range f.DrainInputEvents() {
			switch e.Type {
			case window.InputEventKeyDown:
				b.key(e, pageSize)
			case window.InputEventText:
				if b.menu == nil && b.focus != 0 && e.Mods&(window.ModCtrl|window.ModSuper|window.ModAlt) == 0 {
					b.insert(e.Text)
				}
			case window.InputEventScroll:
				if b.menu != nil || b.save != nil {
					continue
				}
				x, _ := f.CursorPos()
				if b.loc.preview != nil && (e.Mods&window.ModShift != 0 || e.ScrollX != 0) {
					b.previewX = max(0, b.previewX+int(-e.ScrollY*4+e.ScrollX*4))
					continue
				}
				if x < float32(b.listLeft()) {
					b.treeScroll -= int(e.ScrollY * 3)
				} else {
					b.scroll -= int(e.ScrollY * 3)
				}
			case window.InputEventMouseDown:
				if e.Button == window.ButtonLeft {
					b.click(e.MouseX/f.Scale(), e.MouseY/f.Scale(), w, h)
				}
				if e.Button == window.ButtonRight && b.save == nil {
					b.contextMenu(e.MouseX/f.Scale(), e.MouseY/f.Scale())
				}
			case window.InputEventMouseMove:
				if b.menu != nil {
					b.menuHover(e.MouseX/f.Scale(), e.MouseY/f.Scale())
				}
			}
		}
		n := len(b.visible)
		if b.loc.preview != nil {
			n = len(b.loc.preview)
		}
		b.scroll = max(0, min(b.scroll, n-pageSize))
		b.treeScroll = max(0, min(b.treeScroll, len(b.tree())-pageSize))
		renderer.SetViewportScale(int32(w), int32(h), f.Scale())
		b.draw(f, renderer, w, h, pageSize)
		b.drawOverlay(f, renderer)
		if afterDraw != nil {
			return afterDraw(b, f)
		}
		return nil
	})
	if errors.Is(err, errExit) {
		return nil
	}
	return err
}
