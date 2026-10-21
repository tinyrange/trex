package desktop

import (
	"fmt"
	window "github.com/tinyrange/trex/frontend/desktop/internal/xwindow"
	"github.com/tinyrange/trex/vmm"
	"image"
	"math"
)

func viewport(w, h, gw, gh int) image.Rectangle {
	if w <= 0 || h <= 0 || gw <= 0 || gh <= 0 {
		return image.Rectangle{}
	}
	scale := math.Min(float64(w)/float64(gw), float64(h)/float64(gh))
	rw, rh := max(1, int(float64(gw)*scale)), max(1, int(float64(gh)*scale))
	x, y := (w-rw)/2, (h-rh)/2
	return image.Rect(x, y, x+rw, y+rh)
}
func absolutePoint(r image.Rectangle, x, y float32) (float64, float64) {
	return math.Max(0, math.Min(32767, float64(x-float32(r.Min.X))*32767/float64(max(1, r.Dx()-1)))), math.Max(0, math.Min(32767, float64(y-float32(r.Min.Y))*32767/float64(max(1, r.Dy()-1))))
}

type inputState struct {
	keys               map[window.Key]string
	buttons            map[window.Button]bool
	absolute, captured bool
	x, y               float64
	wheelFraction      float64
}

func (s *inputState) release() []vmm.Input {
	var out []vmm.Input
	for _, name := range s.keys {
		out = append(out, vmm.Input{Kind: "key", Key: name, Down: false})
	}
	if len(s.buttons) > 0 {
		out = append(out, vmm.Input{Kind: "pointer", Absolute: s.absolute, X: s.x, Y: s.y})
	}
	clear(s.keys)
	clear(s.buttons)
	s.captured = false
	s.wheelFraction = 0
	return out
}
func (s *inputState) event(e window.InputEvent, r image.Rectangle) []vmm.Input {
	if s.keys == nil {
		s.keys = map[window.Key]string{}
		s.buttons = map[window.Button]bool{}
	}
	switch e.Type {
	case window.InputEventKeyDown, window.InputEventKeyUp:
		name := keyName(e.Key)
		if name == "" {
			return nil
		}
		down := e.Type == window.InputEventKeyDown
		if !down {
			if _, ok := s.keys[e.Key]; !ok {
				return nil
			}
			delete(s.keys, e.Key)
		} else {
			s.keys[e.Key] = name
		}
		return []vmm.Input{{Kind: "key", Key: name, Down: down}}
	case window.InputEventMouseMove, window.InputEventMouseDown, window.InputEventMouseUp, window.InputEventScroll:
		if !s.absolute && !s.captured {
			return nil
		}
		if e.Type == window.InputEventMouseDown {
			if s.absolute && !image.Pt(int(e.MouseX), int(e.MouseY)).In(r) {
				return nil
			}
			if e.Button <= window.ButtonMiddle {
				s.buttons[e.Button] = true
			}
		}
		if e.Type == window.InputEventMouseUp {
			delete(s.buttons, e.Button)
		}
		in := vmm.Input{Kind: "pointer", Absolute: s.absolute}
		if s.absolute {
			s.x, s.y = absolutePoint(r, e.MouseX, e.MouseY)
			in.X, in.Y = s.x, s.y
			if e.Type == window.InputEventScroll {
				s.wheelFraction += float64(e.ScrollY)
				in.Wheel = max(-127, min(127, int(s.wheelFraction)))
				s.wheelFraction -= float64(in.Wheel)
			}
		} else if e.Type == window.InputEventMouseMove {
			in.X = math.Max(-4096, math.Min(4096, float64(e.MouseDeltaX)))
			in.Y = math.Max(-4096, math.Min(4096, float64(e.MouseDeltaY)))
		}
		for _, b := range []window.Button{window.ButtonLeft, window.ButtonRight, window.ButtonMiddle} {
			if s.buttons[b] {
				in.Buttons = append(in.Buttons, []string{"left", "right", "middle"}[int(b)])
			}
		}
		return []vmm.Input{in}
	}
	return nil
}
func keyName(k window.Key) string {
	if k >= window.KeyA && k <= window.KeyZ {
		return string(rune('a' + k - window.KeyA))
	}
	if k >= window.Key0 && k <= window.Key9 {
		return string(rune('0' + k - window.Key0))
	}
	if k >= window.KeyF1 && k <= window.KeyF12 {
		return fmt.Sprintf("f%d", k-window.KeyF1+1)
	}
	return keyNames[k]
}

var keyNames = map[window.Key]string{
	window.KeyLeftShift: "shift", window.KeyRightShift: "shift_r", window.KeyLeftControl: "ctrl", window.KeyRightControl: "ctrl_r", window.KeyLeftAlt: "alt", window.KeyRightAlt: "alt_r", window.KeyLeftSuper: "meta_l", window.KeyRightSuper: "meta_r",
	window.KeySpace: "spc", window.KeyEnter: "ret", window.KeyEscape: "esc", window.KeyBackspace: "backspace", window.KeyDelete: "delete", window.KeyTab: "tab", window.KeyCapsLock: "caps_lock",
	window.KeyUp: "up", window.KeyDown: "down", window.KeyLeft: "left", window.KeyRight: "right", window.KeyHome: "home", window.KeyEnd: "end", window.KeyPageUp: "pgup", window.KeyPageDown: "pgdn", window.KeyInsert: "insert",
	window.KeyGraveAccent: "grave_accent", window.KeyMinus: "minus", window.KeyEqual: "equal", window.KeyLeftBracket: "bracket_left", window.KeyRightBracket: "bracket_right", window.KeyBackslash: "backslash", window.KeySemicolon: "semicolon", window.KeyApostrophe: "apostrophe", window.KeyComma: "comma", window.KeyPeriod: "dot", window.KeySlash: "slash",
}
