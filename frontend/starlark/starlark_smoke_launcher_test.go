package starlarkfrontend

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestSmokeLauncherConfirmation(t *testing.T) {
	frames := make([]starlark.Value, 4)
	for state := range frames {
		frame := image.NewRGBA(image.Rect(0, 0, 128, 96))
		for y := 0; y < 96; y++ {
			for x := 0; x < 128; x++ {
				pixel := color.RGBA{A: 255}
				if state != 0 {
					pixel = color.RGBA{R: 30, G: 60, B: 90, A: 255}
				}
				if state == 2 && x >= 20 && x < 100 && y >= 20 && y < 80 {
					pixel = color.RGBA{R: 255, G: 255, B: 255, A: 255}
				}
				if state == 3 && x < 60 && y < 50 {
					pixel = color.RGBA{R: 200, G: 200, B: 200, A: 255}
				}
				frame.SetRGBA(x, y, pixel)
			}
		}
		var data bytes.Buffer
		if err := png.Encode(&data, frame); err != nil {
			t.Fatal(err)
		}
		frames[state] = &starfile.Bytes{Name: "launcher-frame.png", Data: data.Bytes()}
	}
	for _, test := range []struct {
		name              string
		transition        bool
		differentReopened bool
		attempts          int
		passed            bool
		chords            int
	}{
		{"desktop-transition-is-not-a-launcher", true, false, 1, false, 1},
		{"retry-empty-launcher-after-transition", true, false, 2, true, 3},
		{"reopened-surface-must-match", false, true, 1, false, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			thread, _, err := newStarlarkRuntime("-")
			if err != nil {
				t.Fatal(err)
			}
			module := workflowModule(t, thread, "@stdlib//vmm:smoke.star")
			vm := newWorkflowVM()
			vm.value.attrs["backend_id"] = starlark.String("test")
			vm.value.attrs["running"] = starlark.True
			vm.value.attrs["status"] = starlark.String("running")
			vm.value.attrs["result"] = starlark.None
			state, chords := 1, 0
			if test.transition {
				state = 0
			}
			vm.value.attrs["screenshot"] = workflowBuiltin("screenshot", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				return frames[state], nil
			})
			vm.value.attrs["chord"] = workflowBuiltin("chord", func(_ *starlark.Thread, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				chords++
				state = 2
				if test.transition && chords == 1 {
					state = 1
				} else if test.differentReopened && chords == 2 {
					state = 3
				}
				return starlark.None, nil
			})
			vm.value.attrs["key"] = workflowBuiltin("key", func(_ *starlark.Thread, args starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
				if args[0] == starlark.String("escape") && state > 1 {
					state = 1
				}
				return starlark.None, nil
			})
			// No send_text method is supplied: confirmation must never submit
			// a command, even when it retries a false-positive desktop change.
			result := workflowCallKw(t, thread, module, "_open_command_surface", starlark.Tuple{vm.value, starlark.String("run_dialog")}, []starlark.Tuple{
				{starlark.String("timeout"), starlark.Float(0.4)},
				{starlark.String("attempts"), starlark.MakeInt(test.attempts)},
				{starlark.String("confirm"), starlark.True},
			}).(*starlark.Dict)
			passed, _, _ := result.Get(starlark.String("passed"))
			if passed != starlark.Bool(test.passed) || chords != test.chords {
				t.Fatalf("passed=%s, chords=%d; result=%s", passed, chords, result)
			}
		})
	}
}
