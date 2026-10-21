package qemu

import (
	"bytes"
	"context"
	"errors"
	vmmapi "github.com/tinyrange/trex/vmm"
	"image"
	"image/color"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func recordingTestOptions() vmmapi.RecordingOptions {
	return vmmapi.RecordingOptions{Width: 64, Height: 48, FPS: 10, Maximum: 1 << 20, Duration: 1200 * time.Millisecond}
}
func requireFFmpeg(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("FFmpeg not installed")
	}
}
func TestRecordingFFmpegModeSwitch(t *testing.T) {
	requireFFmpeg(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	calls := 0
	started := time.Now()
	r, err := startRecording(ctx, ctx, recordingTestOptions(), func(context.Context) (image.Image, error) {
		calls++
		w, h := 64, 48
		c := color.RGBA{R: 255, A: 255}
		if calls > 4 {
			w, h = 32, 24
			c = color.RGBA{B: 255, A: 255}
		}
		img := image.NewRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				img.SetRGBA(x, y, c)
			}
		}
		return img, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if time.Since(started) > time.Second {
		t.Fatal("startup waited for duration instead of encoder readiness")
	}
	select {
	case <-r.done:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	f, err := r.Stop(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, f.Size())
	if _, err = f.ReadAt(b, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("ftyp")) || !bytes.Contains(b, []byte("moof")) {
		t.Fatal("not fragmented MP4")
	}
	cmd := exec.CommandContext(ctx, "ffmpeg", "-v", "error", "-i", "pipe:0", "-f", "rawvideo", "-pix_fmt", "rgb24", "pipe:1")
	cmd.Stdin = bytes.NewReader(b)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	frameSize := 64 * 48 * 3
	if len(raw)%frameSize != 0 || int64(len(raw)/frameSize) != r.Stats().Frames {
		t.Fatalf("decoded frames=%d stats=%+v", len(raw)/frameSize, r.Stats())
	}
	if r.Stats().Frames != 12 {
		t.Fatalf("not fixed-rate duration: %+v", r.Stats())
	}
	if raw[0] < 200 || raw[2] > 30 {
		t.Fatalf("first frame not red: %v", raw[:3])
	}
	last := raw[len(raw)-frameSize:]
	if last[2] < 200 || last[0] > 30 {
		t.Fatalf("last frame not blue: %v", last[:3])
	}
	if f2, err := r.Stop(ctx); err != nil || f2 != f {
		t.Fatal("Stop is not idempotent", err)
	}
}
func TestRecordingLimitsFailureAndCancellation(t *testing.T) {
	requireFFmpeg(t)
	for _, kind := range []string{"limit", "capture", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			o := recordingTestOptions()
			if kind == "limit" {
				o.Maximum = 1024
			}
			calls := 0
			r, err := startRecording(ctx, ctx, o, func(ctx context.Context) (image.Image, error) {
				calls++
				if kind == "capture" {
					return nil, errors.New("capture fault")
				}
				return image.NewRGBA(image.Rect(0, 0, 64, 48)), nil
			})
			if kind == "capture" {
				if err == nil || !strings.Contains(err.Error(), "capture fault") {
					t.Fatalf("%v", err)
				}
				return
			}
			if err != nil {
				if kind == "limit" && strings.Contains(err.Error(), "maximum") {
					return
				}
				t.Fatal(err)
			}
			defer r.Close()
			if kind == "cancel" {
				_ = r.Close()
				if !r.Stats().Done {
					t.Fatal("Close failed to join")
				}
				return
			}
			<-r.done
			if _, err = r.Stop(ctx); err == nil || !strings.Contains(err.Error(), "maximum") {
				t.Fatalf("%v", err)
			}
		})
	}
}
func TestRecordingRGBLetterbox(t *testing.T) {
	img := image.NewRGBA(image.Rect(5, 7, 9, 9))
	for y := 7; y < 9; y++ {
		for x := 5; x < 9; x++ {
			img.SetRGBA(x, y, color.RGBA{R: 255, A: 255})
		}
	}
	b, err := recordingRGB(img, 4, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 48 || !bytes.Equal(b[:12], make([]byte, 12)) || b[12] != 255 || !bytes.Equal(b[36:], make([]byte, 12)) {
		t.Fatal("incorrect letterbox or source origin", b)
	}
}
func TestRecordingSlowCapturePreservesTime(t *testing.T) {
	r := &qemuRecording{options: recordingTestOptions(), started: time.Now()}
	r.options.Duration = 600 * time.Millisecond
	var b bytes.Buffer
	err := r.frames(context.Background(), context.Background(), &b, func(context.Context) (image.Image, error) {
		time.Sleep(150 * time.Millisecond)
		return image.NewRGBA(image.Rect(0, 0, 64, 48)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	s := r.Stats()
	if s.Frames != 6 || s.Duplicated == 0 {
		t.Fatalf("lost timeline: %+v", s)
	}
}
