// Package channel defines portable duplex byte transports used by debugger,
// display, serial, and block protocols.
package channel

import (
	"errors"
	"io"
	"time"
)

var ErrDeadlinesUnsupported = errors.New("channel does not support deadlines")

// ByteChannel is a caller-owned duplex byte stream.
type ByteChannel interface {
	io.Reader
	io.Writer
	io.Closer
}

// DeadlineSetter is implemented by channels supporting bounded operations.
type DeadlineSetter interface {
	SetDeadline(time.Time) error
}

// ReadDeadlineSetter is implemented by channels that can bound reads without
// changing the deadline for concurrent writes on the same duplex stream.
type ReadDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

// ReadNotifier is implemented by channels that expose read readiness without
// consuming bytes.
type ReadNotifier interface {
	ReadReady() <-chan struct{}
}

func WriteAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		count, err := writer.Write(data)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrShortWrite
		}
		data = data[count:]
	}
	return nil
}
