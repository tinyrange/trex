package archivegui

import (
	"image/color"
	"os"
	"path/filepath"
	"runtime"

	"github.com/tinyrange/gowin/graphics"
	"github.com/tinyrange/gowin/text"
)

// Use the installed classic Windows font when available; no system font is
// copied into the repository or distributed with the application.
type uiText struct {
	stash    *text.Stash
	font     int
	monoFont int
	shader   uint32
}

func loadUIText(win graphics.Window) (*uiText, error) {
	gl, err := win.PlatformWindow().GL()
	if err != nil {
		return nil, err
	}
	s := text.New(gl, 1024, 1024)
	s.SetYInverted(true)
	font := text.EMBEDDED_FONT
	var candidates []string
	switch runtime.GOOS {
	case "windows":
		candidates = []string{filepath.Join(os.Getenv("WINDIR"), "Fonts", "tahoma.ttf")}
	case "linux":
		candidates = []string{"/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/TTF/DejaVuSans.ttf"}
	case "darwin":
		candidates = []string{"/System/Library/Fonts/Supplemental/Tahoma.ttf"}
	}
	for _, name := range candidates {
		if data, err := os.ReadFile(name); err == nil {
			font = data
			break
		}
	}
	id, err := s.AddFontFromMemory(font)
	if err != nil {
		return nil, err
	}
	// Preview alignment must not depend on the proportional system UI font.
	mono, err := s.AddFontFromMemory(text.EMBEDDED_FONT)
	if err != nil {
		return nil, err
	}
	return &uiText{stash: s, font: id, monoFont: mono, shader: win.GetShaderProgram()}, nil
}
func (t *uiText) SetViewportScale(w, h int32, scale float32) {
	t.stash.SetViewport(w, h)
	t.stash.SetScale(scale)
	t.stash.SetGraphicsShader(t.shader)
}
func (t *uiText) RenderText(s string, x, y float32, size float64, c color.Color) {
	t.stash.BeginDraw()
	t.stash.DrawText(t.font, size, float64(x), float64(y), s, graphics.ColorToFloat32(c))
	t.stash.EndDraw()
}
func (t *uiText) Advance(size float64, s string) float32 {
	return float32(t.stash.GetAdvance(t.font, size, s))
}

func (t *uiText) RenderMono(s string, x, y float32, size float64, c color.Color) {
	t.stash.BeginDraw()
	t.stash.DrawText(t.monoFont, size, float64(x), float64(y), s, graphics.ColorToFloat32(c))
	t.stash.EndDraw()
}
func (t *uiText) MonoAdvance(size float64, s string) float32 {
	return float32(t.stash.GetAdvance(t.monoFont, size, s))
}
