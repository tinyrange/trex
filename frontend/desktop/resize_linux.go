//go:build linux

package desktop

import (
	"context"
	"image"
	"time"

	"github.com/tinyrange/trex/vmm"
)

// The current Windows shared framebuffer reserves 8 MiB. Viewport requests
// preserve aspect ratio within its 1080p limit; the backend applies exact sizes.
const maxViewportWidth, maxViewportHeight = 1920, 1080
const resizeDebounce = 200 * time.Millisecond

func viewportSize(size image.Point) image.Point {
	w, h := int64(size.X), int64(size.Y)
	if w < 1 || h < 1 {
		return image.Point{}
	}
	if w > maxViewportWidth && w*maxViewportHeight >= h*maxViewportWidth {
		h = h * maxViewportWidth / w
		w = maxViewportWidth
	} else if h > maxViewportHeight {
		w = w * maxViewportHeight / h
		h = maxViewportHeight
	}
	return image.Pt(max(1, int(w)), max(1, int(h)))
}

// Resizing runs separately from capture/input so a guest's mode transition does
// not freeze presentation or lose input. A rejection is retried only for a new
// viewport, while a driver that is still booting is checked until it is ready.
func resizeWorker(ctx context.Context, source vmm.ResizeDisplaySource, sizes <-chan image.Point) {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	var desired, attempted image.Point
	var changed time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case size, ok := <-sizes:
			if !ok {
				return
			}
			size = viewportSize(size)
			if size != desired {
				desired, changed = size, time.Now()
			}
		case now := <-tick.C:
			if desired.X < 1 || desired.Y < 1 || desired == attempted || now.Sub(changed) < resizeDebounce {
				continue
			}
			if readiness, ok := source.(vmm.DisplayResizeReadiness); ok {
				ready, err := readiness.ResizeReady(ctx)
				if err != nil || !ready {
					continue
				}
			}
			attempted = desired
			request, cancel := context.WithTimeout(ctx, 10*time.Second)
			_ = source.Resize(request, desired.X, desired.Y)
			cancel()
		}
	}
}
