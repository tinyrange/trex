package qemu

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"image/png"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	vmmapi "github.com/tinyrange/trex/vmm"
)

const qemuTextCharacterDelay = 5 * time.Millisecond

var qemuKeyAliases = map[string]string{
	"control":   "ctrl",
	"enter":     "ret",
	"escape":    "esc",
	"page_down": "pgdn",
	"page_up":   "pgup",
}

func (d *qemuDriver) Input(ctx context.Context, input vmmapi.Input) error {
	switch input.Kind {
	case "key":
		key := qemuKeyCode(input.Key)
		if !qemuAtomName.MatchString(key) {
			return &vmmapi.Error{Code: vmmapi.ErrorInvalid, Message: "invalid key name"}
		}
		_, err := d.qmp.Call(ctx, "input-send-event", map[string]any{"events": []any{map[string]any{
			"type": "key", "data": map[string]any{"down": input.Down, "key": map[string]any{"type": "qcode", "data": key}},
		}}})
		return err
	case "keys":
		keys := make([]any, len(input.Keys))
		for index, key := range input.Keys {
			key = qemuKeyCode(key)
			if !qemuAtomName.MatchString(key) {
				return &vmmapi.Error{Code: vmmapi.ErrorInvalid, Message: "invalid key name " + key}
			}
			keys[index] = map[string]any{"type": "qcode", "data": key}
		}
		_, err := d.qmp.Call(ctx, "send-key", map[string]any{"keys": keys})
		return err
	case "text":
		characters := []rune(input.Text)
		for index, character := range characters {
			events, err := qemuTextEvents(string(character))
			if err != nil {
				return err
			}
			if _, err := d.qmp.Call(ctx, "input-send-event", map[string]any{"events": events}); err != nil {
				return err
			}
			if index+1 < len(characters) {
				timer := time.NewTimer(qemuTextCharacterDelay)
				select {
				case <-ctx.Done():
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					return ctx.Err()
				case <-timer.C:
				}
			}
		}
		return nil
	case "pointer":
		d.inputMu.Lock()
		defer d.inputMu.Unlock()
		events, buttons := qemuPointerEvents(input, d.pointerButtons)
		_, err := d.qmp.Call(ctx, "input-send-event", map[string]any{"events": events})
		if err == nil {
			d.pointerButtons = buttons
		}
		return err
	default:
		return unsupportedVMM("input " + input.Kind)
	}
}

func qemuKeyCode(key string) string {
	if alias := qemuKeyAliases[key]; alias != "" {
		return alias
	}
	return key
}

func qemuPointerEvents(input vmmapi.Input, previous map[string]bool) ([]any, map[string]bool) {
	events := []any{
		qemuPointerEvent(input.Absolute, "x", int64(input.X)),
		qemuPointerEvent(input.Absolute, "y", int64(input.Y)),
	}
	current := make(map[string]bool, len(input.Buttons))
	for _, button := range input.Buttons {
		current[button] = true
	}
	released := make([]string, 0, len(previous))
	for button := range previous {
		if !current[button] {
			released = append(released, button)
		}
	}
	sort.Strings(released)
	for _, button := range released {
		events = append(events, qemuButtonEvent(button, false))
	}
	pressed := make(map[string]bool, len(input.Buttons))
	for _, button := range input.Buttons {
		if !previous[button] && !pressed[button] {
			events = append(events, qemuButtonEvent(button, true))
			pressed[button] = true
		}
	}
	if input.Wheel != 0 {
		button := map[bool]string{true: "wheel-up", false: "wheel-down"}[input.Wheel > 0]
		events = append(events, qemuButtonEvent(button, true), qemuButtonEvent(button, false))
	}
	return events, current
}

func qemuButtonEvent(button string, down bool) map[string]any {
	return map[string]any{"type": "btn", "data": map[string]any{"down": down, "button": button}}
}

func qemuTextEvents(text string) ([]any, error) {
	events := make([]any, 0, len(text)*2)
	for _, character := range text {
		keys, err := qemuTextKeys(character)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			events = append(events, qemuKeyEvent(key, true))
		}
		for index := len(keys) - 1; index >= 0; index-- {
			events = append(events, qemuKeyEvent(keys[index], false))
		}
	}
	return events, nil
}

func qemuKeyEvent(key string, down bool) map[string]any {
	return map[string]any{
		"type": "key",
		"data": map[string]any{
			"down": down,
			"key":  map[string]any{"type": "qcode", "data": key},
		},
	}
}

func qemuPointerEvent(absolute bool, axis string, value int64) map[string]any {
	kind := "rel"
	if absolute {
		kind = "abs"
	}
	return map[string]any{"type": kind, "data": map[string]any{"axis": axis, "value": value}}
}

func qemuTextKeys(character rune) ([]string, error) {
	if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
		return []string{string(character)}, nil
	}
	if character >= 'A' && character <= 'Z' {
		return []string{"shift", strings.ToLower(string(character))}, nil
	}
	plain := map[rune]string{' ': "spc", '\n': "ret", '\r': "ret", '\t': "tab", '-': "minus", '=': "equal", '[': "bracket_left", ']': "bracket_right", ';': "semicolon", '\'': "apostrophe", ',': "comma", '.': "dot", '/': "slash", '\\': "backslash", '`': "grave_accent"}
	if key := plain[character]; key != "" {
		return []string{key}, nil
	}
	shifted := map[rune]string{'!': "1", '@': "2", '#': "3", '$': "4", '%': "5", '^': "6", '&': "7", '*': "8", '(': "9", ')': "0", '_': "minus", '+': "equal", '{': "bracket_left", '}': "bracket_right", ':': "semicolon", '"': "apostrophe", '<': "comma", '>': "dot", '?': "slash", '|': "backslash", '~': "grave_accent"}
	if key := shifted[character]; key != "" {
		return []string{"shift", key}, nil
	}
	return nil, &vmmapi.Error{Code: vmmapi.ErrorUnsupported, Message: fmt.Sprintf("cannot encode character %q as a QEMU key", character)}
}

func (d *qemuDriver) Screenshot(ctx context.Context, format string) (starfile.File, error) {
	if d.capture == nil || d.captureFD == 0 {
		return nil, unsupportedVMM("screenshot")
	}
	if format != "png" && format != "ppm" {
		return nil, &vmmapi.Error{Code: vmmapi.ErrorUnsupported, Message: "screenshot format " + format + " is unsupported"}
	}
	var data []byte
	if qemuCaptureUsesStream() {
		result := make(chan qemuCaptureResult, 1)
		go func() {
			value, err := readQEMUPPMStream(d.capture, 128<<20)
			result <- qemuCaptureResult{data: value, err: err}
		}()
		if _, err := d.qmp.Call(ctx, "screendump", map[string]any{"filename": qemuInheritedFDPath(d.captureFD), "format": "ppm"}); err != nil {
			_ = d.capture.SetReadDeadline(time.Now())
			<-result
			_ = d.capture.SetReadDeadline(time.Time{})
			return nil, err
		}
		captured := <-result
		if captured.err != nil {
			return nil, captured.err
		}
		data = captured.data
	} else {
		if err := d.capture.Truncate(0); err != nil {
			return nil, err
		}
		if _, err := d.capture.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		if _, err := d.qmp.Call(ctx, "screendump", map[string]any{"filename": qemuInheritedFDPath(d.captureFD), "format": "ppm"}); err != nil {
			return nil, err
		}
		if _, err := d.capture.Seek(0, io.SeekStart); err != nil {
			return nil, err
		}
		var err error
		data, err = io.ReadAll(io.LimitReader(d.capture, 128<<20))
		if err != nil {
			return nil, err
		}
	}
	if format == "ppm" {
		return &starfile.Bytes{Name: "qemu-screenshot.ppm", Data: data}, nil
	}
	frame, err := decodeQEMUPPM(data)
	if err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, frame); err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "qemu-screenshot.png", Data: encoded.Bytes()}, nil
}

type qemuCaptureResult struct {
	data []byte
	err  error
}

func readQEMUPPMStream(reader io.Reader, maximum int) ([]byte, error) {
	header := make([]byte, 0, 64)
	tokens := 0
	inToken := false
	for len(header) < 4096 {
		var one [1]byte
		if _, err := io.ReadFull(reader, one[:]); err != nil {
			return nil, fmt.Errorf("screendump: read PPM header: %w", err)
		}
		header = append(header, one[0])
		space := strings.ContainsRune(" \t\r\n", rune(one[0]))
		if space && inToken {
			tokens++
			inToken = false
			if tokens == 4 {
				break
			}
		} else if !space {
			inToken = true
		}
	}
	fields := bytes.Fields(header)
	if len(fields) != 4 || string(fields[0]) != "P6" || string(fields[3]) != "255" {
		return nil, fmt.Errorf("screendump: invalid PPM header")
	}
	width, widthErr := strconv.Atoi(string(fields[1]))
	height, heightErr := strconv.Atoi(string(fields[2]))
	if widthErr != nil || heightErr != nil || width <= 0 || height <= 0 || width > maximum/3 || height > maximum/(width*3) {
		return nil, fmt.Errorf("screendump: invalid or oversized dimensions")
	}
	pixelSize := width * height * 3
	if len(header) > maximum-pixelSize {
		return nil, fmt.Errorf("screendump: image exceeds %d bytes", maximum)
	}
	data := make([]byte, len(header)+pixelSize)
	copy(data, header)
	if _, err := io.ReadFull(reader, data[len(header):]); err != nil {
		return nil, fmt.Errorf("screendump: read PPM pixels: %w", err)
	}
	return data, nil
}

func decodeQEMUPPM(data []byte) (image.Image, error) {
	offset := 0
	next := func() string {
		for offset < len(data) && (data[offset] == ' ' || data[offset] == '\t' || data[offset] == '\r' || data[offset] == '\n') {
			offset++
		}
		start := offset
		for offset < len(data) && data[offset] != ' ' && data[offset] != '\t' && data[offset] != '\r' && data[offset] != '\n' {
			offset++
		}
		return string(data[start:offset])
	}
	magic, widthText, heightText, maximum := next(), next(), next(), next()
	if magic != "P6" || maximum != "255" {
		return nil, fmt.Errorf("screendump: invalid PPM header")
	}
	width, err := strconv.Atoi(widthText)
	if err != nil || width <= 0 {
		return nil, fmt.Errorf("screendump: invalid width")
	}
	height, err := strconv.Atoi(heightText)
	if err != nil || height <= 0 {
		return nil, fmt.Errorf("screendump: invalid height")
	}
	if offset >= len(data) || !strings.ContainsRune(" \t\r\n", rune(data[offset])) {
		return nil, fmt.Errorf("screendump: missing pixel separator")
	}
	offset++
	pixels := data[offset:]
	if len(pixels) != width*height*3 {
		return nil, fmt.Errorf("screendump: pixel size mismatch")
	}
	frame := image.NewRGBA(image.Rect(0, 0, width, height))
	for source, target := 0, 0; source < len(pixels); source, target = source+3, target+4 {
		copy(frame.Pix[target:target+3], pixels[source:source+3])
		frame.Pix[target+3] = 0xff
	}
	return frame, nil
}
