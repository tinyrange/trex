package archivegui

import (
	"fmt"
	"image/color"
	"path"
	"strings"
	"time"

	"github.com/tinyrange/gowin/graphics"
	"github.com/tinyrange/gowin/window"
	"github.com/tinyrange/trex/auto"
)

const (
	menuHeight    = 22
	toolbarBottom = 74
	addressBottom = 100
	listTop       = 124
	rowHeight     = 20
	statusHeight  = 22
	uiFontSize    = 14
)

func (b *browser) listLeft() int {
	if b.showTree {
		return 210
	}
	return 0
}
func (b *browser) filterVisible() bool { return b.focus == 2 || b.filter != "" }
func (b *browser) displayPath() string {
	sep := "/"
	if strings.Contains(b.label, "\\") {
		sep = "\\"
	}
	return strings.TrimRight(b.label, "/\\") + sep + strings.ReplaceAll(strings.TrimLeft(b.loc.path, "/"), "/", sep)
}

type detailColumn struct {
	name     string
	id       int
	x, width float32
	right    bool
}

func (b *browser) columns(w int) []detailColumn {
	left := float32(b.listLeft())
	available := float32(w) - left - 16
	nameWidth := max(float32(160), min(float32(300), available-510))
	return []detailColumn{
		{"Name", 0, left, nameWidth, false},
		{"Size", 1, left + nameWidth, 100, true},
		{"Packed Size", 3, left + nameWidth + 100, 100, true},
		{"Modified", 4, left + nameWidth + 200, 175, false},
		{"Type", 2, left + nameWidth + 375, max(float32(120), available-nameWidth-375), false},
	}
}

func (b *browser) click(x, y float32, w, h int) {
	if b.save != nil {
		b.saveClick(x, y)
		return
	}
	if b.menu != nil {
		if y < menuHeight && x >= 4 && x < 244 {
			b.mainMenu(int((x - 4) / 48))
			return
		}
		b.menuClick(x, y)
		return
	}
	if y < menuHeight {
		if x >= 4 && x < 244 {
			b.mainMenu(int((x - 4) / 48))
		}
		return
	}
	if y < toolbarBottom {
		i := int((x - 4) / 52)
		if x >= 4 && i >= 0 && i < len(b.toolbar()) {
			item := b.toolbar()[i]
			if item.enabled {
				item.action()
			}
		}
		return
	}
	if y < addressBottom {
		if x < 28 {
			b.navigate(path.Dir(b.loc.path), -1)
		} else if b.filterVisible() && x > float32(w-194) {
			b.focusField(2)
		} else {
			b.focusField(1)
		}
		return
	}
	b.focus = 0
	if y >= float32(h-statusHeight) {
		return
	}
	if x < float32(b.listLeft()) {
		i := int((y-listTop)/rowHeight) + b.treeScroll
		t := b.tree()
		if y >= listTop && i >= 0 && i < len(t) {
			b.navigate(t[i].path, -1)
		}
		return
	}
	if y < listTop {
		if b.loc.preview != nil {
			return
		}
		for _, c := range b.columns(w) {
			if x >= c.x && x < c.x+c.width {
				if b.column == c.id {
					b.descending = !b.descending
				} else {
					b.column = c.id
					b.descending = false
				}
				b.relist()
				break
			}
		}
		return
	}
	if x > float32(w-16) {
		n := len(b.visible)
		if b.loc.preview != nil {
			n = len(b.loc.preview)
		}
		b.scroll = int((y - listTop) / float32(max(1, h-listTop-statusHeight)) * float32(n))
		return
	}
	i := int((y-listTop)/rowHeight) + b.scroll
	if b.loc.preview == nil && i >= 0 && i < len(b.visible) {
		b.selected = i
		now := time.Now()
		if b.lastRow == i && now.Sub(b.lastClick) < 450*time.Millisecond {
			b.openSelected()
			b.lastRow = -1
		} else {
			b.lastRow = i
		}
		b.lastClick = now
	} else if b.loc.preview == nil {
		b.selected = -1
	}
}

type toolButton struct {
	name, icon string
	enabled    bool
	action     func()
}

func (b *browser) toolbar() []toolButton {
	n, p := b.target()
	readable := n != nil && n.Reader() != nil && !b.busy
	return []toolButton{
		{"Back", "back", b.historyIndex > 0 && !b.busy, func() { b.back(-1) }},
		{"Forward", "forward", b.historyIndex+1 < len(b.history) && !b.busy, func() { b.back(1) }},
		{"Up", "up", b.loc.path != "/" && !b.busy, func() { b.navigate(path.Dir(b.loc.path), -1) }},
		{"Open", "folder", n != nil && !b.busy, b.openSelected},
		{"View", "view", readable, func() { b.openSystem(n, p) }},
		{"Save", "save", readable, func() { b.promptSave(n, false) }},
		{"Folders", "tree", true, func() { b.showTree = !b.showTree }},
		{"Info", "info", n != nil, func() {
			b.status = "Info: " + n.Name() + " | " + fileType(n)
			if n.Reader() != nil {
				b.status += " | " + groupNumber(n.Summary().Size) + " bytes"
			}
		}},
	}
}

func (b *browser) mainMenu(index int) {
	n, p := b.target()
	readable := n != nil && n.Reader() != nil && !b.busy
	var items []menuItem
	switch index {
	case 0:
		items = []menuItem{{"Open in trex                 Enter", n != nil && !b.busy, func() { b.navigate(p, -1) }}, {"Open in system viewer   Ctrl+Enter", readable, func() { b.openSystem(n, p) }}, {"Save as...", readable, func() { b.promptSave(n, false) }}}
	case 1:
		items = []menuItem{{"Copy path", true, func() {
			if err := window.GetClipboard().SetText(b.displayPath()); err != nil {
				b.status = "Cannot copy: " + err.Error()
			} else {
				b.status = "Copied " + b.displayPath()
			}
		}}, {"Filter files                     Ctrl+F", true, func() { b.focusField(2) }}}
	case 2:
		name := "Show folders"
		if b.showTree {
			name = "Hide folders"
		}
		items = []menuItem{{name, true, func() { b.showTree = !b.showTree }}}
		for _, c := range b.columns(b.width) {
			items = append(items, menuItem{"Sort by " + c.name, b.loc.preview == nil, func() { b.column = c.id; b.descending = false; b.relist() }})
		}
	case 3:
		items = []menuItem{{"Go to path...                  Ctrl+L", true, func() { b.focusField(1) }}, {"Up one level                Backspace", b.loc.path != "/" && !b.busy, func() { b.navigate(path.Dir(b.loc.path), -1) }}}
	case 4:
		items = []menuItem{{"Keyboard shortcuts", true, func() {
			b.status = "Enter: Open | Ctrl+Enter: System viewer | Alt+Left/Right: History | Ctrl+L: Path | Ctrl+F: Filter"
		}}}
	default:
		return
	}
	b.menu = &popupMenu{x: float32(4 + index*48), y: menuHeight, selected: -1, items: items}
}

// Small pixel-style icons are rendered directly with gowin, without image
// assets or external icon tools. They stay crisp at integral desktop scaling.
func drawIcon(f graphics.Frame, kind string, x, y float32, enabled bool) {
	q := func(dx, dy, w, h float32, c color.Color) {
		if !enabled {
			c = muted
		}
		f.RenderQuad(x+dx, y+dy, w, h, nil, c)
	}
	blue := color.RGBA{0, 70, 180, 255}
	green := color.RGBA{0, 140, 70, 255}
	yellow := color.RGBA{255, 199, 42, 255}
	switch kind {
	case "back", "forward", "up":
		c := color.Color(green)
		if kind == "forward" {
			c = blue
		}
		for i := 0; i < 10; i++ {
			v := float32(i)
			if kind == "up" {
				q(11-v, 2+v, 1+2*v, 1, c)
			} else if kind == "back" {
				q(2+v, 11-v, 1, 1+2*v, c)
			} else {
				q(20-v, 11-v, 1, 1+2*v, c)
			}
		}
		if kind == "up" {
			q(8, 11, 7, 10, c)
		} else {
			q(10, 8, 11, 7, c)
		}
	case "folder":
		q(1, 6, 21, 15, color.RGBA{186, 132, 14, 255})
		q(2, 3, 9, 5, yellow)
		q(2, 7, 19, 13, yellow)
		q(3, 9, 18, 1, paper)
	case "save":
		q(2, 2, 20, 20, blue)
		q(5, 3, 13, 7, paper)
		q(14, 4, 3, 5, border)
		q(5, 13, 14, 8, paper)
		q(7, 15, 10, 1, border)
		q(7, 18, 10, 1, border)
	case "view":
		q(1, 2, 22, 16, border)
		q(2, 3, 20, 14, paper)
		q(4, 5, 16, 9, blue)
		q(10, 18, 4, 3, border)
		q(6, 21, 12, 2, ink)
	case "tree":
		q(3, 4, 1, 16, border)
		q(4, 9, 6, 1, border)
		q(4, 18, 6, 1, border)
		q(1, 1, 7, 5, yellow)
		q(10, 6, 12, 7, yellow)
		q(10, 15, 12, 7, yellow)
	case "info":
		q(9, 2, 6, 5, color.RGBA{230, 182, 0, 255})
		q(9, 9, 6, 12, color.RGBA{230, 182, 0, 255})
		q(7, 20, 10, 2, ink)
	}
}

func drawFileIcon(f graphics.Frame, x, y float32, folder bool) {
	q := func(dx, dy, w, h float32, c color.Color) { f.RenderQuad(x+dx, y+dy, w, h, nil, c) }
	if folder {
		q(0, 3, 15, 11, color.RGBA{230, 164, 24, 255})
		q(1, 1, 6, 4, color.RGBA{255, 213, 82, 255})
		q(1, 4, 14, 9, color.RGBA{255, 200, 51, 255})
		q(2, 5, 12, 1, color.RGBA{255, 232, 155, 255})
	} else {
		q(2, 0, 11, 15, border)
		q(3, 1, 9, 13, paper)
		q(5, 4, 5, 1, background)
		q(5, 7, 5, 1, background)
		q(5, 10, 5, 1, background)
	}
}

func (b *browser) draw(f graphics.Frame, t *uiText, w, h, count int) {
	q := func(x, y, width, height float32, c color.Color) { f.RenderQuad(x, y, width, height, nil, c) }
	label := func(s string, x, y, width float32, c color.Color) {
		if width <= 0 {
			return
		}
		f.PushClip(graphics.Rect{X: x, Y: y - 16, Width: width, Height: 20})
		t.RenderText(s, x, y, uiFontSize, c)
		f.PopClip()
	}
	q(0, 0, float32(w), menuHeight, paper)
	for i, name := range []string{"File", "Edit", "View", "Tools", "Help"} {
		label(name, float32(8+i*48), 16, 42, ink)
	}
	q(0, menuHeight, float32(w), 1, border)
	mx, my := f.CursorPos()
	for i, item := range b.toolbar() {
		x := float32(4 + i*52)
		if item.enabled && mx >= x && mx < x+50 && my >= 24 && my < 72 {
			bevel(f, x, 24, 50, 48, f.GetButtonState(window.ButtonLeft).IsDown())
		}
		if item.icon == "tree" && b.showTree {
			bevel(f, x, 24, 50, 48, true)
		}
		drawIcon(f, item.icon, x+13, 27, item.enabled)
		c := color.Color(ink)
		if !item.enabled {
			c = muted
		}
		advance := t.Advance(uiFontSize, item.name)
		label(item.name, x+(50-advance)/2, 66, 52, c)
	}
	q(0, toolbarBottom, float32(w), 1, border)
	drawIcon(f, "up", 3, 76, b.loc.path != "/" && !b.busy)
	addressWidth := float32(w - 34)
	if b.filterVisible() {
		addressWidth -= 196
	}
	field := func(s string, x, y, width float32, focus int) {
		q(x, y, width, 22, border)
		q(x+1, y+1, width-2, 20, paper)
		r := []rune(s)
		start := 0
		if b.focus == focus {
			for start < min(b.caret, len(r)) && t.Advance(uiFontSize, string(r[start:min(b.caret, len(r))])) > width-12 {
				start++
			}
		}
		c := color.Color(ink)
		if b.focus == focus && b.selectAll {
			q(x+3, y+3, width-6, 16, selection)
			c = paper
		}
		label(string(r[start:]), x+5, y+16, width-10, c)
		if b.focus == focus && !b.selectAll {
			q(x+5+t.Advance(uiFontSize, string(r[start:min(b.caret, len(r))])), y+3, 1, 16, ink)
		}
	}
	address := b.displayPath()
	if b.focus == 1 {
		address = b.address
	}
	field(address, 30, 77, addressWidth, 1)
	if b.filterVisible() {
		field(b.filter, float32(w-194), 77, 190, 2)
	}
	left := float32(b.listLeft())
	q(0, addressBottom, float32(w), float32(h-addressBottom-statusHeight), paper)
	if b.showTree {
		q(209, addressBottom, 1, float32(h-addressBottom-statusHeight), border)
		label("Folders", 8, 117, 192, ink)
	}
	cols := b.columns(w)
	if b.loc.preview != nil {
		if strings.HasPrefix(b.loc.format, "Hex") {
			f.PushClip(graphics.Rect{X: left + 8, Y: addressBottom, Width: max(1, float32(w)-left-24), Height: 24})
			header := "Offset    00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII"
			t.RenderMono(header, left+8-float32(b.previewX)*t.MonoAdvance(15, "0"), 117, 15, muted)
			f.PopClip()
		} else {
			label(b.loc.format, left+8, 117, float32(w)-left-24, muted)
		}
	} else {
		for _, c := range cols {
			q(c.x+c.width-1, addressBottom+2, 1, 20, color.RGBA{225, 225, 225, 255})
			x := c.x + 8
			if c.right {
				x = c.x + c.width - 8 - t.Advance(uiFontSize, c.name)
			}
			label(c.name, x, 117, c.width-12, ink)
			if b.column == c.id {
				sx := c.x + c.width/2
				for j := 0; j < 4; j++ {
					dy := j
					if b.descending {
						dy = 3 - j
					}
					q(sx-float32(j), 101+float32(dy), float32(2*j+1), 1, muted)
				}
			}
		}
	}
	if b.showTree {
		tr := b.tree()
		for i := b.treeScroll; i < len(tr) && i < b.treeScroll+count; i++ {
			y := float32(listTop + (i-b.treeScroll)*rowHeight)
			x := float32(6 + tr[i].depth*14)
			if tr[i].path == b.loc.path {
				q(0, y, 209, rowHeight, background)
			}
			drawFileIcon(f, x, y+2, true)
			label(tr[i].name, x+19, y+15, 190-x, ink)
		}
	}
	if b.loc.preview != nil {
		f.PushClip(graphics.Rect{X: left + 8, Y: listTop, Width: max(1, float32(w)-left-24), Height: float32(max(1, h-listTop-statusHeight))})
		for i := b.scroll; i < len(b.loc.preview) && i < b.scroll+count; i++ {
			t.RenderMono(b.loc.preview[i], left+8-float32(b.previewX)*t.MonoAdvance(15, "0"), float32(listTop+15+(i-b.scroll)*rowHeight), 15, ink)
		}
		f.PopClip()
	} else {
		for i := b.scroll; i < len(b.visible) && i < b.scroll+count; i++ {
			n := b.visible[i]
			y := float32(listTop + (i-b.scroll)*rowHeight)
			c := color.Color(ink)
			if i == b.selected {
				q(left, y, float32(w)-left-16, rowHeight, selection)
				c = paper
			}
			drawFileIcon(f, left+7, y+2, n.Summary().Kind == "directory")
			for _, col := range cols {
				value := detailValue(n, col.id)
				x := col.x + 8
				width := col.width - 16
				if col.id == 0 {
					x += 19
					width -= 19
				}
				if col.right {
					x = max(col.x+8, col.x+col.width-8-t.Advance(uiFontSize, value))
					width = col.x + col.width - 8 - x
				}
				label(value, x, y+15, width, c)
			}
		}
		if len(b.visible) == 0 && !b.busy {
			label("No items", left+8, listTop+18, float32(w)-left-20, muted)
		}
	}
	n := len(b.visible)
	if b.loc.preview != nil {
		n = len(b.loc.preview)
	}
	if n > count {
		track := float32(max(1, h-listTop-statusHeight))
		thumb := max(float32(20), track*float32(count)/float32(n))
		y := listTop + (track-thumb)*float32(b.scroll)/float32(n-count)
		q(float32(w-15), listTop, 15, track, background)
		q(float32(w-13), y, 11, thumb, color.RGBA{180, 180, 180, 255})
	}
	q(0, float32(h-statusHeight), float32(w), statusHeight, background)
	q(0, float32(h-statusHeight), float32(w), 1, border)
	selected := 0
	if b.selected >= 0 {
		selected = 1
	}
	footer := fmt.Sprintf("%d / %d object(s) selected", selected, len(b.visible))
	if b.loc.preview != nil {
		footer = b.loc.format
	}
	label(footer, 5, float32(h-6), 270, ink)
	q(280, float32(h-statusHeight+2), 1, statusHeight-3, color.RGBA{210, 210, 210, 255})
	status := b.status
	if strings.HasSuffix(status, " items") {
		status = ""
	}
	if b.filter != "" {
		status = fmt.Sprintf("%d of %d objects", len(b.visible), len(b.loc.children))
	}
	if b.busy || !strings.HasSuffix(b.status, " items") {
		status = b.status
	}
	label(status, 290, float32(h-6), float32(w-300), ink)
}

func groupNumber(n int64) string {
	if n < 0 {
		return ""
	}
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + " " + s[i:]
	}
	return s
}
func packedSize(n *auto.Node) int64 {
	a := n.Summary().Attributes
	for _, key := range []string{"compressed_size", "stored_size"} {
		switch v := a[key].(type) {
		case int64:
			return v
		case uint64:
			if v <= uint64(1<<63-1) {
				return int64(v)
			}
		case int:
			return int64(v)
		}
	}
	return -1
}
func modifiedValue(n *auto.Node) string {
	var value time.Time
	if r, ok := n.Reader().(interface{ Modified() time.Time }); ok {
		value = r.Modified()
	}
	if value.IsZero() {
		for _, key := range []string{"modified", "mtime"} {
			switch v := n.Summary().Attributes[key].(type) {
			case time.Time:
				value = v
			case string:
				return v
			}
			if !value.IsZero() {
				break
			}
		}
	}
	if value.IsZero() {
		return ""
	}
	return value.Format("2006-01-02 15:04")
}
func detailValue(n *auto.Node, col int) string {
	switch col {
	case 0:
		return n.Name()
	case 1:
		if n.Reader() != nil {
			return groupNumber(n.Summary().Size)
		}
	case 2:
		return fileType(n)
	case 3:
		return groupNumber(packedSize(n))
	case 4:
		return modifiedValue(n)
	}
	return ""
}
