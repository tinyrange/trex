//go:build linux

// Package desktop presents a portable VM display in a native X11/GLX window.
package desktop

import (
	"context"
	"errors"
	"fmt"
	window "github.com/tinyrange/trex/frontend/desktop/internal/xwindow"
	"github.com/tinyrange/trex/vmm"
	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
	"image"
	"image/color"
	"image/draw"
	"time"
)

// Options.Start retains ownership of the VM and its image until ctx is canceled.
// publish must be called once, after startup. Run waits for Start to clean up.
type Options struct {
	Title string
	Start func(ctx context.Context, publish func(vmm.DisplaySource), progress func(string)) error
}
type capturedFrame struct {
	image    *image.RGBA
	absolute bool
}

// Run must execute on the initial, locked OS thread. Guest work runs off-thread.
func Run(parent context.Context, opts Options) (err error) {
	if opts.Start == nil {
		return fmt.Errorf("desktop start callback is required")
	}
	win, err := window.New(opts.Title, 1280, 720, true)
	if err != nil {
		return err
	}
	defer win.Close()
	api, err := win.GL()
	if err != nil {
		return err
	}
	render, err := newRenderer(api)
	if err != nil {
		return err
	}
	defer render.close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ready := make(chan vmm.DisplaySource, 1)
	progress := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- opts.Start(ctx, func(s vmm.DisplaySource) {
			select {
			case ready <- s:
			case <-ctx.Done():
			}
		}, func(s string) {
			select {
			case <-progress:
			default:
			}
			select {
			case progress <- s:
			default:
			}
		})
	}()
	// Even closing during construction waits for recipe cleanup: no detached VM.
	finished := false
	defer func() {
		cancel()
		if !finished {
			startErr := <-done
			if startErr != nil && !errors.Is(startErr, context.Canceled) {
				err = errors.Join(err, startErr)
			}
		}
	}()
	inputs := make(chan vmm.Input, 256)
	frames := make(chan capturedFrame, 1)
	workerDone := make(chan error, 1)
	workerRunning := false
	defer func() {
		cancel()
		if workerRunning {
			<-workerDone
		}
	}()
	state := inputState{}
	defer win.SetCaptured(false)
	send := func(events []vmm.Input) error {
		for _, in := range events {
			select {
			case inputs <- in:
			default:
				return fmt.Errorf("guest input queue full; stopping rather than losing key transitions")
			}
		}
		return nil
	}
	render.upload(progressImage("Constructing a fresh Windows image..."))
	fullscreen := false
	lastTitle := ""
	ticker := time.NewTicker(time.Second / 60)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if !win.Poll() {
			return nil
		}
		select {
		case e := <-done:
			finished = true
			return e
		default:
		}
		select {
		case source := <-ready:
			if source == nil {
				return fmt.Errorf("nil guest display")
			}
			workerRunning = true
			go func() { workerDone <- displayWorker(ctx, source, inputs, frames) }()
		default:
		}
		select {
		case e := <-workerDone:
			workerRunning = false
			return e
		default:
		}
		select {
		case s := <-progress:
			if !workerRunning {
				render.upload(progressImage(s))
				win.SetTitle(opts.Title + " — " + s)
			}
		default:
		}
		select {
		case frame := <-frames:
			if frame.absolute != state.absolute {
				if err := send(state.release()); err != nil {
					return err
				}
				win.SetCaptured(false)
			}
			state.absolute = frame.absolute
			render.upload(frame.image)
			title := opts.Title + " — click to capture · Ctrl+Alt releases · Ctrl+Alt+F fullscreen · close discards session"
			if frame.absolute {
				title = opts.Title + " — integrated pointer · Ctrl+Alt+F fullscreen · close discards session"
			}
			if title != lastTitle {
				win.SetTitle(title)
				lastTitle = title
			}
		default:
		}
		w, h := win.BackingSize()
		rect := viewport(w, h, render.width, render.height)
		for _, event := range win.DrainInputEvents() {
			if event.Type == window.InputEventFocusLost {
				win.SetCaptured(false)
				if err := send(state.release()); err != nil {
					return err
				}
				continue
			}
			ctrl := event.Mods&window.ModCtrl != 0
			alt := event.Mods&window.ModAlt != 0
			if event.Type == window.InputEventKeyDown && ((ctrl && alt) || (ctrl && (event.Key == window.KeyLeftAlt || event.Key == window.KeyRightAlt)) || (alt && (event.Key == window.KeyLeftControl || event.Key == window.KeyRightControl))) {
				if event.Key == window.KeyF && !event.Repeat {
					fullscreen = !fullscreen
					win.SetFullscreen(fullscreen)
				}
				win.SetCaptured(false)
				if err := send(state.release()); err != nil {
					return err
				}
				continue
			}
			if !workerRunning {
				continue
			}
			if event.Type == window.InputEventMouseDown && !state.absolute && !state.captured && image.Pt(int(event.MouseX), int(event.MouseY)).In(rect) {
				state.captured = win.SetCaptured(true)
				continue // capture click is not a guest click
			}
			if err := send(state.event(event, rect)); err != nil {
				return err
			}
		}
		mx, my := win.Cursor()
		win.SetCursorHidden(state.captured || (state.absolute && image.Pt(int(mx), int(my)).In(rect)))
		render.draw(w, h)
		win.Swap()
	}
}
func displayWorker(ctx context.Context, source vmm.DisplaySource, inputs <-chan vmm.Input, frames chan capturedFrame) error {
	tick := time.NewTicker(time.Second / 30)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case in := <-inputs:
			if err := source.Input(ctx, in); err != nil {
				return fmt.Errorf("guest input: %w", err)
			}
		case <-tick.C:
			if driver, ok := source.(vmm.Driver); ok {
				state, err := driver.Status(ctx)
				if err != nil {
					return err
				}
				if state.Name == "stopped" {
					result, err := driver.Wait(ctx)
					if err != nil {
						return err
					}
					if !result.Clean {
						return fmt.Errorf("guest stopped: %s: %s", result.Reason, result.Detail)
					}
					return nil
				}
			}
			frame, err := source.Capture(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("capture: %w", err)
			}
			absolute := false
			if pointer, ok := source.(vmm.AbsolutePointerSource); ok {
				absolute, err = pointer.AbsolutePointer(ctx)
				if err != nil {
					return err
				}
			}
			if frame == nil {
				continue
			}
			select {
			case <-frames:
			default:
			}
			select {
			case frames <- capturedFrame{frame, absolute}:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
func progressImage(status string) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 640, 360))
	draw.Draw(img, img.Bounds(), image.NewUniform(color.RGBA{12, 18, 28, 255}), image.Point{}, draw.Src)
	d := font.Drawer{Dst: img, Src: image.NewUniform(color.RGBA{210, 224, 242, 255}), Face: basicfont.Face7x13}
	for i, s := range []string{"Windows 11 / TinyRangeX", "", "Building directly from your original ISO.", "No installer VM. No saved system image.", "", status, "", "Closing this window cancels startup.", "Guest changes are discarded when the app exits."} {
		if len(s) > 82 {
			s = s[:82]
		}
		d.Dot = fixed.P(28, 70+i*24)
		d.DrawString(s)
	}
	return img
}
