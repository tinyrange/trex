// Package mszip decodes the deflate variant used in Microsoft cabinet and
// KWAJ streams, including the bounded compatibility behavior required by
// early encoders.
package mszip

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

// Decode expands one MSZIP block using up to 32 KiB of preceding output as
// its dictionary and requires exactly expected output bytes.
func Decode(compressed, history []byte, expected int) ([]byte, error) {
	var reader io.ReadCloser
	if len(history) == 0 {
		reader = flate.NewReader(bytes.NewReader(compressed))
	} else {
		reader = flate.NewReaderDict(bytes.NewReader(compressed), history)
	}
	var decoded bytes.Buffer
	_, copyErr := io.Copy(&decoded, reader)
	closeErr := reader.Close()
	if copyErr == nil && closeErr == nil {
		if decoded.Len() != expected {
			return nil, fmt.Errorf("decoded %d bytes, want %d", decoded.Len(), expected)
		}
		return decoded.Bytes(), nil
	}
	strictErr := copyErr
	if strictErr == nil {
		strictErr = closeErr
	}
	decodedData, err := Inflate(compressed, history, expected)
	if err != nil {
		return nil, fmt.Errorf("strict inflate: %v; compatible inflate: %w", strictErr, err)
	}
	return decodedData, nil
}
