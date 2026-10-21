// Package channel defines portable duplex byte transports used by debugger,
// display, serial, and block protocols.
package channel

import (
	"errors"
	"io"
	"time"
)

var ErrDeadlinesUnsupported = errors.New("channel does not support deadlines")

var ErrWriteCapacityUnsupported = errors.New("channel does not expose write capacity")

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
// consuming bytes. Capture the notification before reading to avoid missing a
// transition. Notifications can be spurious; retry the read after waking. A nil
// notification means readiness is unavailable.
type ReadNotifier interface {
	ReadReady() <-chan struct{}
}

// WriteCapacityNotifier exposes the number of bytes an atomic cooperative write
// can currently accept, and a notification that closes when that capacity or
// the stream's closed state changes. Capture both before attempting a write;
// concurrent writes can still consume the observed capacity. A closed stream
// returns its write error. Wrappers without this capability return
// ErrWriteCapacityUnsupported.
type WriteCapacityNotifier interface {
	WriteCapacity() (available int, changed <-chan struct{}, err error)
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
