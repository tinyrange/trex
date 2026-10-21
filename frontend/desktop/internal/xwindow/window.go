// Package xwindow adapts gowin's MIT-licensed X11 backend for VM focus and capture.
package xwindow

import "github.com/tinyrange/gowin/gl"

type Window interface {
	GL() (gl.OpenGL, error)
	Close()
	Poll() bool
	Swap()
	BackingSize() (int, int)
	Cursor() (float32, float32)
	Scale() float32
	GetKeyState(Key) KeyState
	GetButtonState(Button) ButtonState
	DrainInputEvents() []InputEvent
	TextInput() string
	SetCursorHidden(bool)
	SetCaptured(bool) bool
	SetFullscreen(bool)
	SetTitle(string)
}
