package mszip

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

// Decoder reuses the deflate working set across independent MSZIP blocks.
// It is not concurrent. Decode returns borrowed bytes valid until the next call;
// history may refer to the preceding result, but compressed must not alias it.
// The zero value is ready for use.
type Decoder struct {
	input           bytes.Reader
	reader          io.ReadCloser
	output, history []byte
	scratch         [32768]byte
	sink            boundedOutput
}

func (d *Decoder) Decode(compressed, history []byte, expected int) ([]byte, error) {
	if expected < 0 {
		return nil, fmt.Errorf("negative decoded length")
	}
	// Preserve the original dictionary for the compatibility retry, even when
	// the caller passed our previous output as history.
	history = history[max(0, len(history)-32768):]
	d.history = append(d.history[:0], history...)
	d.input.Reset(compressed)
	if d.reader == nil {
		d.reader = flate.NewReaderDict(&d.input, d.history)
	} else if err := d.reader.(flate.Resetter).Reset(&d.input, d.history); err != nil {
		return nil, err
	}
	if cap(d.output) < expected {
		d.output = make([]byte, expected)
	} else {
		d.output = d.output[:expected]
	}
	d.sink = boundedOutput{data: d.output}
	n, err := io.CopyBuffer(&d.sink, d.reader, d.scratch[:])
	closeErr := d.reader.Close()
	if err == nil && closeErr == nil {
		if n != int64(expected) {
			return nil, fmt.Errorf("decoded %d bytes, want %d", n, expected)
		}
		return d.output, nil
	}
	strictErr := err
	if strictErr == nil {
		strictErr = closeErr
	}
	decoded, compatErr := Inflate(compressed, d.history, expected)
	if compatErr != nil {
		return nil, fmt.Errorf("strict inflate: %v; compatible inflate: %w", strictErr, compatErr)
	}
	copy(d.output, decoded)
	return d.output, nil
}

// Continue to the strict end marker even after the advertised size is exceeded:
// legacy compatibility depends on whether strict decoding itself failed, not
// just whether its partial prefix exceeded the size. Never retain excess output.
type boundedOutput struct {
	data []byte
	at   int
}

func (w *boundedOutput) Write(p []byte) (int, error) {
	w.at += copy(w.data[w.at:], p)
	return len(p), nil
}
