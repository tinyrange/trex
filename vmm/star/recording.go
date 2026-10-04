package star

import (
	"context"
	"fmt"
	starvalue "github.com/tinyrange/trex/script/value"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
	"go.starlark.net/starlark"
	"time"
)

func (v *vmmSessionValue) recordBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	o := vmmapi.RecordingOptions{Width: 1440, Height: 900, FPS: 30, Maximum: 64 << 20}
	duration := starvalue.Number(600)
	if err := starlark.UnpackArgs("record", args, kwargs, "width?", &o.Width, "height?", &o.Height, "fps?", &o.FPS, "maximum?", &o.Maximum, "duration?", &duration, "lossless?", &o.Lossless); err != nil {
		return nil, err
	}
	if duration <= 0 || duration > 3600 {
		return nil, fmt.Errorf("duration must be in (0,3600] seconds")
	}
	o.Duration = time.Duration(float64(duration) * float64(time.Second))
	if err := o.Validate(); err != nil {
		return nil, err
	}
	driver, ok := v.driver.(vmmapi.RecordingDriver)
	if !ok {
		return nil, unsupportedVMM("video recording")
	}
	ctx, cancel := context.WithTimeout(v.ctx, 30*time.Second)
	defer cancel()
	recording, err := driver.Record(ctx, o)
	if err != nil {
		return nil, err
	}
	return &recordingValue{recording: recording}, nil
}

type recordingValue struct{ recording vmmapi.Recording }

func (v *recordingValue) String() string        { return "<video_recording>" }
func (v *recordingValue) Type() string          { return "video_recording" }
func (v *recordingValue) Freeze()               {}
func (v *recordingValue) Truth() starlark.Bool  { return starlark.True }
func (v *recordingValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable video_recording") }
func (v *recordingValue) AttrNames() []string   { return []string{"stop", "close", "stats"} }
func (v *recordingValue) Attr(name string) (starlark.Value, error) {
	switch name {
	case "stats":
		s := v.recording.Stats()
		return starvalue.NewRecord(starlark.StringDict{"frames": starlark.MakeInt64(s.Frames), "duplicated": starlark.MakeInt64(s.Duplicated), "elapsed": starlark.Float(s.Elapsed.Seconds()), "done": starlark.Bool(s.Done)}), nil
	case "close":
		return starlark.NewBuiltin("recording.close", func(_ *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("close", a, k); err != nil {
				return nil, err
			}
			return starlark.None, v.recording.Close()
		}), nil
	case "stop":
		return starlark.NewBuiltin("recording.stop", func(_ *starlark.Thread, _ *starlark.Builtin, a starlark.Tuple, k []starlark.Tuple) (starlark.Value, error) {
			if err := starlark.UnpackArgs("stop", a, k); err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			f, err := v.recording.Stop(ctx)
			if err != nil {
				return nil, err
			}
			return &recordingFile{File: f}, nil
		}), nil
	}
	return nil, nil
}

type recordingFile struct{ storage.File }

func (f *recordingFile) String() string                           { return "<file recording.mp4>" }
func (f *recordingFile) Type() string                             { return "file" }
func (f *recordingFile) Freeze()                                  {}
func (f *recordingFile) Truth() starlark.Bool                     { return starlark.True }
func (f *recordingFile) Hash() (uint32, error)                    { return 0, fmt.Errorf("unhashable file") }
func (f *recordingFile) AttrNames() []string                      { return starfile.AttrNames() }
func (f *recordingFile) Attr(name string) (starlark.Value, error) { return starfile.Attr(f, name), nil }
