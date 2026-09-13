package archivegui

import (
	"fmt"
	"image/color"
	"path"

	"github.com/tinyrange/gowin/graphics"
	"github.com/tinyrange/gowin/window"
	"github.com/tinyrange/trex/auto"
)

type menuItem struct {
	label   string
	enabled bool
	action  func()
}
type popupMenu struct {
	x, y     float32
	selected int
	items    []menuItem
}
type saveDialog struct {
	node        *auto.Node
	destination string
	open        bool
}

func bevel(f graphics.Frame, x, y, w, h float32, sunken bool) {
	if w <= 0 || h <= 0 {
		return
	}
	q := func(x, y, w, h float32, c color.Color) { f.RenderQuad(x, y, w, h, nil, c) }
	q(x, y, w, h, background)
	light, dark := color.Color(paper), color.Color(ink)
	if sunken {
		light, dark = border, paper
	}
	q(x, y, w-1, 1, light)
	q(x, y, 1, h-1, light)
	q(x+w-1, y, 1, h, dark)
	q(x, y+h-1, w, 1, dark)
	if sunken {
		light, dark = ink, background
	} else {
		light, dark = background, border
	}
	q(x+1, y+1, w-3, 1, light)
	q(x+1, y+1, 1, h-3, light)
	q(x+w-2, y+1, 1, h-2, dark)
	q(x+1, y+h-2, w-2, 1, dark)
}

func (b *browser) target() (*auto.Node, string) {
	if b.loc.preview != nil {
		return b.loc.node, b.loc.path
	}
	if b.selected >= 0 && b.selected < len(b.visible) {
		n := b.visible[b.selected]
		return n, path.Join(b.loc.path, n.Name())
	}
	return nil, b.loc.path
}

func (b *browser) perform(status string, action func() (string, error)) {
	if b.busy {
		return
	}
	b.busy = true
	b.status = status
	b.requests <- request{action: action}
}
func (b *browser) openSystem(n *auto.Node, p string) {
	if b.busy || n == nil || n.Reader() == nil {
		return
	}
	if !b.desktop.CanOpen(n.Reader()) {
		b.promptSave(n, true)
		return
	}
	b.perform("Opening system viewer ...", func() (string, error) { return "Opened " + p + " in system viewer", b.desktop.Open(n.Reader()) })
}
func (b *browser) promptSave(n *auto.Node, open bool) {
	if b.busy || n == nil || n.Reader() == nil {
		return
	}
	b.save = &saveDialog{node: n, destination: b.desktop.SuggestedDestination(n.Name()), open: open}
	b.focusField(3)
}
func (b *browser) confirmSave() {
	s := b.save
	if s == nil || s.destination == "" || b.busy {
		return
	}
	b.save = nil
	b.focus = 0
	b.perform("Saving "+s.node.Name()+" ...", func() (string, error) {
		message := "Saved " + s.destination
		if s.open {
			message += " and opened in system viewer"
		}
		return message, b.desktop.Save(s.node.Reader(), s.destination, s.open)
	})
}

func (b *browser) contextMenu(x, y float32) {
	if b.save != nil || y < addressBottom || y >= float32(b.height-statusHeight) {
		return
	}
	b.focus = 0
	b.lastRow = -1
	var n *auto.Node
	p := b.loc.path
	if x >= float32(b.listLeft()) && b.loc.preview == nil {
		i := int((y-listTop)/rowHeight) + b.scroll
		b.selected = -1
		if y >= listTop && i >= 0 && i < len(b.visible) {
			b.selected = i
			n = b.visible[i]
			p = path.Join(b.loc.path, n.Name())
		}
	} else if x < float32(b.listLeft()) {
		tree := b.tree()
		i := int((y-listTop)/rowHeight) + b.treeScroll
		if y >= listTop && i >= 0 && i < len(tree) {
			p = tree[i].path
			if p == "/" {
				n = b.root
			} else {
				for _, child := range b.visited[path.Dir(p)] {
					if child.Name() == path.Base(p) {
						n = child
						break
					}
				}
			}
		}
	} else {
		n = b.loc.node
	}
	readable := n != nil && n.Reader() != nil
	items := []menuItem{
		{"Open in trex", n != nil && !b.busy, func() { b.navigate(p, -1) }},
		{"Open in system viewer     Ctrl+Enter", readable && !b.busy, func() { b.openSystem(n, p) }},
		{"Save as...", readable && !b.busy, func() { b.promptSave(n, false) }},
		{"Copy path", true, func() {
			if err := window.GetClipboard().SetText(p); err != nil {
				b.status = "Cannot copy: " + err.Error()
			} else {
				b.status = "Copied " + p
			}
		}},
		{"Up one level", b.loc.path != "/" && !b.busy, func() { b.navigate(path.Dir(b.loc.path), -1) }},
	}
	x = max(0, min(x, float32(b.width-304)))
	y = max(0, min(y, float32(b.height-28*len(items)-8)))
	b.menu = &popupMenu{x: x, y: y, selected: -1, items: items}
}

func (b *browser) menuHover(x, y float32) {
	m := b.menu
	if m == nil {
		return
	}
	m.selected = -1
	if x >= m.x+3 && x < m.x+297 && y >= m.y+4 && y < m.y+4+float32(len(m.items)*28) {
		m.selected = int((y - m.y - 4) / 28)
	}
}
func (b *browser) menuClick(x, y float32) {
	b.menuHover(x, y)
	m := b.menu
	b.menu = nil
	if m.selected >= 0 && m.items[m.selected].enabled {
		m.items[m.selected].action()
	}
}
func (b *browser) menuKey(e window.InputEvent) {
	m := b.menu
	switch e.Key {
	case window.KeyEscape:
		b.menu = nil
	case window.KeyEnter, window.KeyNumpadEnter:
		if m.selected >= 0 && m.items[m.selected].enabled {
			b.menu = nil
			m.items[m.selected].action()
		}
	case window.KeyUp, window.KeyDown:
		delta := 1
		if e.Key == window.KeyUp {
			delta = -1
		}
		for range m.items {
			m.selected = (m.selected + delta + len(m.items)) % len(m.items)
			if m.items[m.selected].enabled {
				break
			}
		}
	}
}

func (b *browser) saveRect() (float32, float32) {
	return max(0, float32(b.width-560)/2), max(0, float32(b.height-210)/2)
}
func (b *browser) saveClick(x, y float32) {
	sx, sy := b.saveRect()
	if y >= sy+160 && y < sy+190 {
		if x >= sx+324 && x < sx+430 {
			b.confirmSave()
		} else if x >= sx+440 && x < sx+546 {
			b.save = nil
			b.focus = 0
		}
	} else if x >= sx+14 && x < sx+546 && y >= sy+88 && y < sy+120 {
		b.focusField(3)
	}
}

func (b *browser) drawOverlay(f graphics.Frame, t *uiText) {
	q := func(x, y, w, h float32, c color.Color) { f.RenderQuad(x, y, w, h, nil, c) }
	label := func(s string, x, y, w float32, c color.Color) {
		f.PushClip(graphics.Rect{X: x, Y: y - 18, Width: max(1, w), Height: 24})
		t.RenderText(s, x, y, 14, c)
		f.PopClip()
	}
	if m := b.menu; m != nil {
		bevel(f, m.x, m.y, 300, float32(len(m.items)*28+8), false)
		for i, item := range m.items {
			y := m.y + 4 + float32(i*28)
			c := color.Color(ink)
			if i == m.selected && item.enabled {
				q(m.x+3, y, 294, 28, selection)
				c = paper
			}
			if !item.enabled {
				label(item.label, m.x+13, y+20, 278, paper)
				c = muted
			}
			label(item.label, m.x+12, y+19, 278, c)
		}
	}
	if s := b.save; s != nil {
		x, y := b.saveRect()
		bevel(f, x, y, 560, 210, false)
		q(x+3, y+3, 554, 25, selection)
		title := "Save as"
		if s.open {
			title = "Save and open in system viewer"
		}
		label(title, x+10, y+21, 535, paper)
		label(fmt.Sprintf("Save %s", s.node.Name()), x+14, y+53, 530, ink)
		label("Destination filename:", x+14, y+79, 530, ink)
		bevel(f, x+14, y+88, 532, 32, true)
		q(x+16, y+90, 528, 28, paper)
		r := []rune(s.destination)
		b.caret = min(b.caret, len(r))
		start := 0
		for start < b.caret && t.Advance(14, string(r[start:b.caret])) > 506 {
			start++
		}
		c := color.Color(ink)
		if b.selectAll {
			q(x+18, y+93, 522, 23, selection)
			c = paper
		}
		label(string(r[start:]), x+20, y+110, 520, c)
		if !b.selectAll {
			q(x+20+t.Advance(14, string(r[start:b.caret])), y+94, 1, 20, ink)
		}
		label("The saved copy is kept. Existing files are not overwritten.", x+14, y+143, 530, ink)
		bevel(f, x+324, y+160, 106, 30, false)
		bevel(f, x+440, y+160, 106, 30, false)
		label("Save", x+355, y+181, 70, ink)
		label("Cancel", x+468, y+181, 72, ink)
	}
}
