package qemu

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"time"

	channelpkg "github.com/tinyrange/trex/channel"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
)

// All process details stay in the native QEMU backend. FFmpeg only receives
// RGB frames on stdin and writes a fragmented MP4 to stdout; no host files,
// network inputs, shell, user-supplied arguments or converter fallback.
type qemuRecording struct {
	options   vmmapi.RecordingOptions
	stop      context.CancelFunc
	abort     context.CancelFunc
	done      chan struct{}
	ready     chan struct{}
	first     chan struct{}
	mu        sync.Mutex
	stats     vmmapi.RecordingStats
	file      storage.File
	err       error
	started   time.Time
	discarded bool
}
type recordingOutput struct {
	buffer  bytes.Buffer
	maximum int64
	ready   chan struct{}
	once    sync.Once
	err     error
}

func (b *recordingOutput) Write(p []byte) (int, error) {
	if int64(b.buffer.Len())+int64(len(p)) > b.maximum {
		b.err = fmt.Errorf("recording exceeds maximum %d bytes", b.maximum)
		return 0, b.err
	}
	n, err := b.buffer.Write(p)
	if n > 0 {
		b.once.Do(func() { close(b.ready) })
	}
	return n, err
}
func (d *qemuDriver) Record(ctx context.Context, o vmmapi.RecordingOptions) (vmmapi.Recording, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	if d.capture == nil {
		return nil, unsupportedVMM("recording requires a capturable display")
	}
	d.recordMu.Lock()
	defer d.recordMu.Unlock()
	if d.recording != nil && !d.recording.Stats().Done {
		return nil, fmt.Errorf("a recording is already active")
	}
	r, err := startRecording(ctx, d.ctx, o, func(ctx context.Context) (image.Image, error) {
		f, err := d.Screenshot(ctx, "ppm")
		if err != nil {
			return nil, err
		}
		b, err := starfile.ReadAll(f)
		if err != nil {
			return nil, err
		}
		return decodeQEMUPPM(b)
	})
	if err != nil {
		return nil, err
	}
	d.recording = r
	return r, nil
}
func startRecording(startup, life context.Context, o vmmapi.RecordingOptions, capture func(context.Context) (image.Image, error)) (*qemuRecording, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	binary, err := exec.LookPath("ffmpeg")
	if err != nil {
		return nil, fmt.Errorf("QEMU recording requires FFmpeg with the libx264 encoder: %w", err)
	}
	processCtx, abort := context.WithCancel(life)
	captureCtx, stop := context.WithCancel(processCtx)
	r := &qemuRecording{options: o, stop: stop, abort: abort, done: make(chan struct{}), ready: make(chan struct{}), first: make(chan struct{})}
	go r.run(processCtx, captureCtx, binary, capture)
	encoded, first := r.ready, r.first
	for encoded != nil || first != nil {
		select {
		case <-encoded:
			encoded = nil
		case <-first:
			first = nil
		case <-r.done:
			if r.err != nil {
				return nil, r.err
			}
			return r, nil
		case <-startup.Done():
			_ = r.Close()
			return nil, fmt.Errorf("start recording: %w", startup.Err())
		}
	}
	select {
	case <-r.done:
		if r.err != nil {
			return nil, r.err
		}
	default:
	}
	return r, nil
}
func recordingArgs(o vmmapi.RecordingOptions) []string {
	codec, pixelFormat, crf := "libx264", "yuv420p", "10"
	if o.Lossless {
		codec, pixelFormat, crf = "libx264rgb", "rgb24", "0"
	}
	return []string{"-hide_banner", "-loglevel", "error", "-nostdin", "-probesize", "32", "-analyzeduration", "0", "-f", "rawvideo", "-pixel_format", "rgb24", "-video_size", fmt.Sprintf("%dx%d", o.Width, o.Height), "-framerate", strconv.Itoa(o.FPS), "-i", "pipe:0", "-an", "-c:v", codec, "-preset", "veryfast", "-tune", "zerolatency", "-crf", crf, "-pix_fmt", pixelFormat, "-threads", "2", "-g", strconv.Itoa(o.FPS), "-movflags", "+frag_keyframe+empty_moov+default_base_moof", "-flush_packets", "1", "-f", "mp4", "pipe:1"}
}
func (r *qemuRecording) run(processCtx, captureCtx context.Context, binary string, capture func(context.Context) (image.Image, error)) {
	defer close(r.done)
	defer r.abort()
	defer r.stop()
	defer func() {
		r.mu.Lock()
		r.stats.Done = true
		if !r.started.IsZero() {
			r.stats.Elapsed = time.Since(r.started)
		}
		r.mu.Unlock()
	}()
	var output recordingOutput
	output.maximum = r.options.Maximum
	output.ready = r.ready
	stderr := &boundedBuffer{limit: 64 << 10}
	cmd := exec.CommandContext(processCtx, binary, recordingArgs(r.options)...)
	cmd.Stdout = &output
	cmd.Stderr = stderr
	cmd.WaitDelay = 3 * time.Second
	stdin, err := cmd.StdinPipe()
	if err != nil {
		r.err = err
		return
	}
	if err = cmd.Start(); err != nil {
		_ = stdin.Close()
		r.err = err
		return
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	// A blocked encoder write must not trap stop/teardown forever. This timer
	// only starts on stop; normal frames run independently of Starlark calls.
	writerDone := make(chan struct{})
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		duration := time.NewTimer(r.options.Duration)
		defer duration.Stop()
		select {
		case <-duration.C:
			r.stop()
		case <-captureCtx.Done():
		case <-writerDone:
			return
		}
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			r.abort()
			_ = stdin.Close()
		case <-writerDone:
		}
	}()
	r.mu.Lock()
	r.started = time.Now()
	r.mu.Unlock()
	err = r.frames(captureCtx, processCtx, stdin, capture)
	_ = stdin.Close()
	// EOF finalizes the container. Bound both encoder drain and process reaping.
	timer := time.NewTimer(10 * time.Second)
	var waitErr error
	select {
	case waitErr = <-waited:
	case <-timer.C:
		r.abort()
		waitErr = <-waited
		if waitErr == nil {
			waitErr = fmt.Errorf("FFmpeg finalization timed out")
		}
	}
	timer.Stop()
	close(writerDone)
	<-watchdogDone
	if output.err != nil {
		err = output.err
	}
	if waitErr != nil {
		if err == nil {
			err = fmt.Errorf("FFmpeg: %w: %s", waitErr, stderr.String())
		} else {
			err = fmt.Errorf("%w; FFmpeg: %v: %s", err, waitErr, stderr.String())
		}
	}
	if err == nil && processCtx.Err() != nil {
		err = processCtx.Err()
	}
	if err == nil && (output.buffer.Len() == 0 || r.stats.Frames == 0) {
		err = fmt.Errorf("FFmpeg produced no video frames")
	}
	r.err = err
	if err == nil {
		r.file = &starfile.Bytes{Name: "qemu-recording.mp4", Data: output.buffer.Bytes()}
	}
}
func (r *qemuRecording) frames(ctx, life context.Context, w io.Writer, capture func(context.Context) (image.Image, error)) error {
	period := time.Second / time.Duration(r.options.FPS)
	maxFrames := int64(r.options.Duration / period)
	if maxFrames < 1 {
		maxFrames = 1
	}
	start := r.started
	var previous []byte
	var count int64
	emit := func(frame []byte, duplicate bool) error {
		if err := channelpkg.WriteAll(w, frame); err != nil {
			return err
		}
		count++
		if count == 1 && r.first != nil {
			close(r.first)
		}
		r.mu.Lock()
		r.stats.Frames = count
		if duplicate {
			r.stats.Duplicated++
		}
		r.stats.Elapsed = time.Since(start)
		r.mu.Unlock()
		return nil
	}
	for count < maxFrames {
		delay := time.Until(start.Add(time.Duration(count) * period))
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return nil
		}
		shotCtx, cancel := context.WithTimeout(life, 3*time.Second)
		img, err := capture(shotCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("recording capture: %w", err)
		}
		frame, err := recordingRGB(img, r.options.Width, r.options.Height)
		if err != nil {
			return err
		}
		// Do not accelerate guest time when capture or encoding misses deadlines.
		// Fill missed slots with the last observed frame and report those duplicates.
		target := int64(time.Since(start) / period)
		if target-count > int64(r.options.FPS)*5 {
			return fmt.Errorf("recording fell more than five seconds behind real time")
		}
		if previous == nil {
			previous = frame
		}
		for count < target && count < maxFrames {
			if err := emit(previous, true); err != nil {
				return err
			}
		}
		if count < maxFrames {
			if err := emit(frame, false); err != nil {
				return err
			}
		}
		previous = frame
	}
	return nil
}

// Fit the guest raster into a fixed black canvas. Only integer upscales are
// allowed: fractional enlargement gives pixel text uneven stroke widths. A
// source larger than the canvas still uses nearest-neighbor downscaling.
// Lossless refers to encoding this canvas, not to reversing downscaling.
func recordingRGB(src image.Image, width, height int) ([]byte, error) {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	if sw < 1 || sh < 1 || sw > 16384 || sh > 16384 {
		return nil, fmt.Errorf("invalid source raster")
	}
	dw, dh := width, height
	if int64(sw)*int64(height) > int64(sh)*int64(width) {
		dh = sh * width / sw
	} else {
		dw = sw * height / sh
	}
	if sw <= width && sh <= height {
		scale := min(width/sw, height/sh)
		dw, dh = sw*scale, sh*scale
	}
	if dw < 1 {
		dw = 1
	}
	if dh < 1 {
		dh = 1
	}
	out := make([]byte, width*height*3)
	ox, oy := (width-dw)/2, (height-dh)/2
	if rgba, ok := src.(*image.RGBA); ok {
		for y := 0; y < dh; y++ {
			row := (y * sh / dh) * rgba.Stride
			for x := 0; x < dw; x++ {
				si := row + (x*sw/dw)*4
				di := ((oy+y)*width + ox + x) * 3
				copy(out[di:di+3], rgba.Pix[si:si+3])
			}
		}
		return out, nil
	}
	for y := 0; y < dh; y++ {
		for x := 0; x < dw; x++ {
			red, green, blue, _ := src.At(b.Min.X+x*sw/dw, b.Min.Y+y*sh/dh).RGBA()
			i := ((oy+y)*width + ox + x) * 3
			out[i] = byte(red >> 8)
			out[i+1] = byte(green >> 8)
			out[i+2] = byte(blue >> 8)
		}
	}
	return out, nil
}
func (r *qemuRecording) Stop(ctx context.Context) (storage.File, error) {
	r.stop()
	select {
	case <-r.done:
	case <-ctx.Done():
		r.abort()
		<-r.done
		return nil, ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.discarded {
		return nil, fmt.Errorf("recording was closed and discarded")
	}
	return r.file, r.err
}
func (r *qemuRecording) Close() error {
	r.stop()
	r.abort()
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	r.discarded = true
	r.file = nil
	return nil
}
func (r *qemuRecording) Stats() vmmapi.RecordingStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats
	if !s.Done && !r.started.IsZero() {
		s.Elapsed = time.Since(r.started)
	}
	return s
}
