package labfrontend

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinyrange/trex/lab"
	"github.com/tinyrange/trex/vmm"
	"golang.org/x/net/websocket"
)

type testDisplay struct {
	x      atomic.Uint32
	inputs chan vmm.Input
}

func (d *testDisplay) Capture(context.Context) (*image.RGBA, error) {
	frame := image.NewRGBA(image.Rect(0, 0, 8, 8))
	frame.SetRGBA(0, 0, color.RGBA{R: uint8(d.x.Load()), A: 255})
	return frame, nil
}

func (d *testDisplay) Input(_ context.Context, input vmm.Input) error {
	d.x.Store(uint32(input.X))
	d.inputs <- input
	return nil
}

func (d *testDisplay) AbsolutePointer(context.Context) (bool, error) { return true, nil }

func TestDisplayStreamsPointerAndReleasesButtons(t *testing.T) {
	display := &testDisplay{inputs: make(chan vmm.Input, 4)}
	app := httpApp{ctx: t.Context()}
	surface := lab.Surface{Display: display}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app.display(w, r, surface)
	}))
	defer server.Close()
	response, err := http.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("originless channel returned %d", response.StatusCode)
	}
	conn, err := websocket.Dial("ws"+strings.TrimPrefix(server.URL, "http"), "", server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	read := func(red uint8) {
		t.Helper()
		var message []byte
		if err := websocket.Message.Receive(conn, &message); err != nil {
			t.Fatal(err)
		}
		if len(message) < 2 || message[0] != 1 {
			t.Fatal("frame lacks absolute pointer mode")
		}
		img, err := png.Decode(bytes.NewReader(message[1:]))
		if err != nil || color.RGBAModel.Convert(img.At(0, 0)).(color.RGBA).R != red {
			t.Fatalf("frame missed the pointer update: %v", err)
		}
	}
	read(0)
	if err := websocket.JSON.Send(conn, vmm.Input{Kind: "pointer", X: 42, Buttons: []string{"left"}}); err != nil {
		t.Fatal(err)
	}
	read(42)
	_ = conn.Close()
	for _, held := range []bool{true, false} {
		select {
		case got := <-display.inputs:
			if got.Kind != "pointer" || (len(got.Buttons) != 0) != held {
				t.Fatalf("unexpected pointer transition: %+v", got)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("display did not release the held button")
		}
	}
}
