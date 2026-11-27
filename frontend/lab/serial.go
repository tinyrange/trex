package labfrontend

import (
	"context"
	"net/http"
	"time"

	"github.com/tinyrange/trex/lab"
	"golang.org/x/net/websocket"
)

func (a httpApp) serial(w http.ResponseWriter, r *http.Request, s lab.Surface) {
	if s.Terminal == nil {
		http.NotFound(w, r)
		return
	}
	a.socket(w, r, func(ctx context.Context, conn *websocket.Conn) {
		ctx, cancel := context.WithCancel(ctx)
		output := make(chan struct{})
		go func() {
			defer close(output)
			defer func() { _ = conn.SetReadDeadline(time.Now()) }()
			var offset uint64
			for {
				data, next, err := s.Terminal.Output(ctx, offset)
				if err != nil {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
				if err := websocket.Message.Send(conn, data); err != nil {
					return
				}
				offset = next
			}
		}()
		defer func() { cancel(); <-output }()
		for {
			var data []byte
			if err := websocket.Message.Receive(conn, &data); err != nil || len(data) > 4096 {
				return
			}
			if err := s.Terminal.Input(ctx, string(data)); err != nil {
				return
			}
		}
	})
}
