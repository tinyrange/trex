package qemu

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Sharp one-pixel features reveal scaling/codec damage that solid-color frames
// cannot detect. Compare decoded video, not just FFmpeg exit status or a PNG.
func TestRecordingDecodedPixelFidelity(t *testing.T) {
	requireFFmpeg(t)
	for _, lossless := range []bool{false, true} {
		name := "compatible"
		if lossless {
			name = "lossless_rgb"
		}
		t.Run(name, func(t *testing.T) {
			src := image.NewRGBA(image.Rect(0, 0, 32, 24))
			for y := 0; y < 24; y++ {
				for x := 0; x < 32; x++ {
					v := uint8(0)
					if (x+y*3)%7 < 3 {
						v = 255
					}
					c := color.RGBA{v, v, v, 255}
					if lossless {
						c = color.RGBA{uint8(x * 7), uint8(y * 11), uint8((x*3 + y*5) % 256), 255}
					}
					src.SetRGBA(x, y, c)
				}
			}
			o := recordingTestOptions()
			o.Width = 80
			o.Height = 64
			o.Duration = 300 * time.Millisecond
			o.Lossless = lossless
			expected, err := recordingRGB(src, o.Width, o.Height)
			if err != nil {
				t.Fatal(err)
			}
			// The integer 2x image occupies 64x48 centered at (8,8), not an uneven 2.5x fit.
			for y := 0; y < 24; y++ {
				for x := 0; x < 32; x++ {
					c := src.RGBAAt(x, y)
					for dy := 0; dy < 2; dy++ {
						for dx := 0; dx < 2; dx++ {
							i := ((8+y*2+dy)*80 + 8 + x*2 + dx) * 3
							if !bytes.Equal(expected[i:i+3], []byte{c.R, c.G, c.B}) {
								t.Fatal("fractional scaling changed pixel geometry")
							}
						}
					}
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			r, err := startRecording(ctx, ctx, o, func(context.Context) (image.Image, error) { return src, nil })
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			<-r.done
			f, err := r.Stop(ctx)
			if err != nil {
				t.Fatal(err)
			}
			encoded := make([]byte, f.Size())
			if _, err = f.ReadAt(encoded, 0); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, "ffmpeg", "-v", "error", "-i", "pipe:0", "-frames:v", "1", "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1")
			cmd.Stdin = bytes.NewReader(encoded)
			decoded, err := cmd.Output()
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) != len(expected) {
				t.Fatalf("decoded length %d", len(decoded))
			}
			maximum, total := 0, 0
			for i, want := range expected {
				d := int(decoded[i]) - int(want)
				if d < 0 {
					d = -d
				}
				total += d
				if d > maximum {
					maximum = d
				}
			}
			if lossless && maximum != 0 {
				t.Fatalf("lossless RGB changed source canvas: max=%d", maximum)
			}
			if !lossless && (maximum > 12 || total > len(expected)*2) {
				t.Fatalf("pixel text degraded: max=%d mean=%f", maximum, float64(total)/float64(len(expected)))
			}
			t.Logf("decoded RGB error max=%d mean=%.4f", maximum, float64(total)/float64(len(expected)))
		})
	}
}

// Opt-in check for the actual exported demo, not just synthetic frames. Decode
// at one frame per second with bounded memory, and compare the final frame to
// the independently captured guest PNG. The five-second final hold ensures the
// last sampled frame represents the final desktop, not a transition.
func TestRecordedArtifactFidelity(t *testing.T) {
	videoPath := os.Getenv("TREX_RECORDING_VIDEO")
	if videoPath == "" {
		t.Skip("set TREX_RECORDING_VIDEO and TREX_RECORDING_SCREENSHOT to verify a demo artifact")
	}
	requireFFmpeg(t)
	source, err := os.Open(os.Getenv("TREX_RECORDING_SCREENSHOT"))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(source)
	source.Close()
	if err != nil {
		t.Fatal(err)
	}
	expected, err := recordingRGB(img, 1440, 900)
	if err != nil {
		t.Fatal(err)
	}
	video, err := os.Open(videoPath)
	if err != nil {
		t.Fatal(err)
	}
	defer video.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ffmpeg", "-v", "error", "-i", "pipe:0", "-vf", "fps=1", "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1")
	cmd.Stdin = video
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	frame, last := make([]byte, len(expected)), make([]byte, len(expected))
	frames, changes := 0, 0
	for {
		_, err = io.ReadFull(out, frame)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if frames > 0 && !bytes.Equal(frame, last) {
			changes++
		}
		copy(last, frame)
		frames++
	}
	if err = cmd.Wait(); err != nil {
		t.Fatal(err, diagnostics.String())
	}
	if frames < 10 || changes < 3 {
		t.Fatalf("recording does not show a paced changing session: samples=%d changes=%d", frames, changes)
	}
	maximum, total := 0, int64(0)
	for i, want := range expected {
		d := int(last[i]) - int(want)
		if d < 0 {
			d = -d
		}
		total += int64(d)
		if d > maximum {
			maximum = d
		}
	}
	mean := float64(total) / float64(len(expected))
	if os.Getenv("TREX_RECORDING_LOSSLESS") == "true" && maximum != 0 {
		t.Fatalf("lossless final frame differs: max=%d mean=%.4f", maximum, mean)
	}
	if mean > 3 {
		t.Fatalf("final frame degraded or mismatched: max=%d mean=%.4f", maximum, mean)
	}
	t.Logf("decoded %d one-second samples with %d changes; final source-PNG RGB error max=%d mean=%.4f", frames, changes, maximum, mean)
}
