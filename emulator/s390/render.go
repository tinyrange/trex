package s390

import (
	"image"
	"image/color"
	"sync"

	"renvo.dev/std/graphics"
	"renvo.dev/std/graphics/gofont"
)

// 3270 display rendering with the base-color scheme of a four-color display
// in base mode: unprotected normal green, unprotected intensified red,
// protected normal blue, protected intensified white.

const (
	cellW = 9
	cellH = 18
)

var (
	glyphOnce sync.Once
	glyphs    map[rune][]bool
	glyphMu   sync.Mutex
	glyphFont *graphics.Font
)

func glyph(r rune) []bool {
	glyphOnce.Do(func() {
		glyphs = map[rune][]bool{}
		glyphFont = gofont.NewMono(15)
	})
	glyphMu.Lock()
	defer glyphMu.Unlock()
	if g, ok := glyphs[r]; ok {
		return g
	}
	pixels := make([]byte, cellW*cellH*4)
	surface := graphics.NewSurfaceBuffer(cellW, cellH, pixels)
	surface.DrawText(glyphFont, graphics.Point{X: 0, Y: cellH - 4}, string(r), graphics.White)
	g := make([]bool, cellW*cellH)
	for i := range g {
		g[i] = pixels[i*4+3] >= 128
	}
	glyphs[r] = g
	return g
}

var (
	colorGreen = color.RGBA{0x40, 0xe0, 0x40, 0xff}
	colorRed   = color.RGBA{0xff, 0x50, 0x50, 0xff}
	colorBlue  = color.RGBA{0x60, 0xa0, 0xff, 0xff}
	colorWhite = color.RGBA{0xf0, 0xf0, 0xf0, 0xff}
	colorBack  = color.RGBA{0x00, 0x00, 0x00, 0xff}
)

// Capture renders the display buffer and cursor as an owned image.
func (t *Console3270) Capture() *image.RGBA {
	w, h := t.Cols*cellW, (t.Rows+1)*cellH
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = colorBack.R, colorBack.G, colorBack.B, 0xff
	}
	n := t.size()
	attr := byte(0)
	if f := t.fieldStart(0); f >= 0 {
		attr = t.buf[f]
	}
	for i := 0; i < n; i++ {
		if t.fa[i] {
			attr = t.buf[i]
			continue
		}
		disp := attr & faDisplay
		if disp == faDisplay || t.buf[i] == 0 {
			continue
		}
		col := colorGreen
		switch {
		case attr&faProtected != 0 && disp == 0x08:
			col = colorWhite
		case attr&faProtected != 0:
			col = colorBlue
		case disp == 0x08:
			col = colorRed
		}
		r := []rune(EBCDICString(t.buf[i : i+1]))[0]
		if r == ' ' {
			continue
		}
		t.drawGlyph(img, i%t.Cols, i/t.Cols, r, col)
	}
	// Cursor underline.
	cr, cc := t.cursor/t.Cols, t.cursor%t.Cols
	for x := 0; x < cellW; x++ {
		img.SetRGBA(cc*cellW+x, cr*cellH+cellH-2, colorWhite)
	}
	return img
}

func (t *Console3270) drawGlyph(img *image.RGBA, col, row int, r rune, c color.RGBA) {
	g := glyph(r)
	ox, oy := col*cellW, row*cellH
	for y := 0; y < cellH; y++ {
		for x := 0; x < cellW; x++ {
			if g[y*cellW+x] {
				img.SetRGBA(ox+x, oy+y, c)
			}
		}
	}
}

// CaptureLines renders the last rows lines of a line-mode console, wrapped
// at cols, in green on black.
func CaptureLines(lines []string, rows, cols int) *image.RGBA {
	var wrapped []string
	for _, l := range lines {
		r := []rune(l)
		for len(r) > cols {
			wrapped = append(wrapped, string(r[:cols]))
			r = r[cols:]
		}
		wrapped = append(wrapped, string(r))
	}
	if len(wrapped) > rows {
		wrapped = wrapped[len(wrapped)-rows:]
	}
	img := image.NewRGBA(image.Rect(0, 0, cols*cellW, rows*cellH))
	for i := 0; i < len(img.Pix); i += 4 {
		img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = colorBack.R, colorBack.G, colorBack.B, 0xff
	}
	t := &Console3270{Cols: cols}
	for y, l := range wrapped {
		for x, r := range []rune(l) {
			if r != ' ' {
				t.drawGlyph(img, x, y, r, colorGreen)
			}
		}
	}
	return img
}
