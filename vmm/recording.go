package vmm

import (
	"context"
	"fmt"
	"github.com/tinyrange/trex/storage"
	"time"
)

// RecordingOptions specifies a fixed-rate, video-only recording. Paths, codecs
// and subprocess control belong to the backend, not this portable contract.
type RecordingOptions struct {
	Width, Height, FPS int
	Maximum            int64
	Duration           time.Duration
	Lossless           bool
}

func (o RecordingOptions) Validate() error {
	if o.Width < 2 || o.Height < 2 || o.Width > 4096 || o.Height > 4096 || o.Width%2 != 0 || o.Height%2 != 0 || o.Width*o.Height > 4096*2160 {
		return fmt.Errorf("recording dimensions must be even, 2..4096, at most 4096x2160 pixels")
	}
	if o.FPS < 1 || o.FPS > 60 {
		return fmt.Errorf("recording fps must be 1..60")
	}
	if o.Maximum < 1024 || o.Maximum > 512<<20 {
		return fmt.Errorf("recording maximum must be 1 KiB..512 MiB")
	}
	if o.Duration <= 0 || o.Duration > time.Hour {
		return fmt.Errorf("recording duration must be in (0,3600] seconds")
	}
	return nil
}

type RecordingStats struct {
	Frames, Duplicated int64
	Elapsed            time.Duration
	Done               bool
}

// Recording.Stop finalizes and returns the bounded portable video file. Close
// cancels and discards the recording. Both join workers and reap the encoder.
type Recording interface {
	Stop(context.Context) (storage.File, error)
	Close() error
	Stats() RecordingStats
}
type RecordingDriver interface {
	Record(context.Context, RecordingOptions) (Recording, error)
}
