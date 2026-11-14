package cc

import (
	"fmt"
	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func (i inspection) audioCapture(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("cc.audio_capture", args, kwargs); err != nil {
		return nil, err
	}
	var result starlark.Value
	err := i.driver.call(i.ctx, func() error {
		s := i.driver.pc.sound
		if s == nil {
			return fmt.Errorf("audio_capture requires cc.backend(sb16=True)")
		}
		result = starvalue.NewRecord(starlark.StringDict{
			"file":        &starfile.Bytes{Data: s.wav()},
			"sample_rate": starlark.MakeInt(44100), "channels": starlark.MakeInt(2),
			"frames": starlark.MakeInt(len(s.capture) / 4), "total_frames": starlark.MakeUint64(s.totalFrames),
			"truncated": starlark.Bool(s.truncated), "fault": starlark.String(s.fault),
		})
		return nil
	})
	return result, err
}

func (s *sb16) state() any {
	if s == nil {
		return nil
	}
	channels := make([]any, 8)
	for i, c := range s.dma.channels {
		channels[i] = map[string]any{"channel": i, "address": int(c.address), "count": int(c.count), "page": int(c.page), "mode": int(c.mode), "masked": c.masked}
	}
	commands := make([]any, len(s.commands))
	for i, c := range s.commands {
		commands[i] = c
	}
	return map[string]any{"model": "sb16", "rate": s.rate, "bits": s.bits, "channels": s.channels, "active": s.active, "paused": s.paused, "auto": s.auto, "block_bytes": s.block, "pending": int(s.pending), "captured_frames": len(s.capture) / 4, "total_frames": s.totalFrames, "truncated": s.truncated, "commands": commands, "fault": s.fault, "dma": channels}
}
