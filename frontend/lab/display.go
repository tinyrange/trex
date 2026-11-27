package labfrontend

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"net/http"
	"time"

	"github.com/tinyrange/trex/lab"
	"github.com/tinyrange/trex/vmm"
	"golang.org/x/net/websocket"
)

func (a httpApp) display(w http.ResponseWriter, r *http.Request, s lab.Surface) {
	if s.Display == nil {
		http.NotFound(w, r)
		return
	}
	a.socket(w, r, func(ctx context.Context, conn *websocket.Conn) { serveDisplay(ctx, conn, s.Display) })
}

func (a httpApp) socket(w http.ResponseWriter, r *http.Request, serve func(context.Context, *websocket.Conn)) {
	// The application already checks the origin against its configured host.
	// An upgrade must also include it, since the socket accepts guest input.
	if r.Header.Get("Origin") == "" {
		http.Error(w, "Open the display from the lab editor.", http.StatusForbidden)
		return
	}
	server := websocket.Server{Handler: func(conn *websocket.Conn) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		if a.ctx != nil {
			stop := context.AfterFunc(a.ctx, cancel)
			defer stop()
		}
		conn.MaxPayloadBytes = 16 << 10
		serve(ctx, conn)
	}}
	server.ServeHTTP(w, r)
}

func serveDisplay(ctx context.Context, conn *websocket.Conn, display vmm.DisplaySource) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	frames := make(chan struct{})
	go func() {
		defer close(frames)
		streamFrames(ctx, conn, display)
		_ = conn.SetReadDeadline(time.Now())
	}()
	keys := make(map[string]bool)
	buttonsHeld := false
	defer func() {
		cancel()
		<-frames
		// Release held input even if the browser disconnected mid-drag.
		release, done := context.WithTimeout(context.Background(), time.Second)
		defer done()
		for key := range keys {
			_ = display.Input(release, vmm.Input{Kind: "key", Key: key})
		}
		if buttonsHeld {
			_ = display.Input(release, vmm.Input{Kind: "pointer"})
		}
	}()
	for {
		var input vmm.Input
		if err := websocket.JSON.Receive(conn, &input); err != nil || ctx.Err() != nil {
			return
		}
		if !validInputSize(input) {
			return
		}
		switch input.Kind {
		case "key", "pointer", "keys", "text":
		default:
			return
		}
		send, done := context.WithTimeout(ctx, 2*time.Second)
		err := display.Input(send, input)
		done()
		if err != nil {
			continue
		}
		switch input.Kind {
		case "key":
			if input.Down {
				keys[input.Key] = true
			} else {
				delete(keys, input.Key)
			}
		case "pointer":
			buttonsHeld = len(input.Buttons) != 0
		}
	}
}

// A packet is one pointer-mode byte followed by a PNG. Capture and input run
// independently. Only changed frames cross the connection.
func streamFrames(ctx context.Context, conn *websocket.Conn, display vmm.DisplaySource) {
	var last, reuse *image.RGBA
	var payload bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	reusable, _ := display.(vmm.ReusableDisplaySource)
	pointer, _ := display.(vmm.AbsolutePointerSource)
	var mode, lastMode byte
	var lastPointer time.Time
	lastCapture := time.Now()
	tick := time.NewTicker(time.Second / 30)
	defer tick.Stop()
	for {
		capture, finish := context.WithTimeout(ctx, 2*time.Second)
		var frame *image.RGBA
		var err error
		if reusable != nil {
			frame, err = reusable.CaptureInto(capture, reuse)
		} else {
			frame, err = display.Capture(capture)
		}
		if err == nil && frame != nil && pointer != nil && time.Since(lastPointer) >= 250*time.Millisecond {
			if absolute, err := pointer.AbsolutePointer(capture); err == nil {
				mode = 0
				if absolute {
					mode = 1
				}
			}
			lastPointer = time.Now()
		}
		finish()
		if err == nil && frame != nil {
			lastCapture = time.Now()
			if last == nil || mode != lastMode || frame.Rect != last.Rect || !bytes.Equal(frame.Pix, last.Pix) {
				payload.Reset()
				_ = payload.WriteByte(mode)
				if err := encoder.Encode(&payload, frame); err != nil {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if err := websocket.Message.Send(conn, payload.Bytes()); err != nil {
					return
				}
				last, reuse, lastMode = frame, last, mode
			} else {
				reuse = frame
			}
		} else if time.Since(lastCapture) > 5*time.Second {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
