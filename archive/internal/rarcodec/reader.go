package rarcodec

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

const (
	decode29Ver = 2
	decode50Ver = 3
	decode70Ver = 4
)

var (
	ErrUnknownDecoder   = errors.New("rar: unknown compression version")
	ErrDecoderOutOfData = errors.New("rar: truncated compressed data")
	ErrMemoryLimit      = errors.New("rar: dictionary or PPM memory exceeds 64 MiB")
)

type byteReader interface {
	io.Reader
	io.ByteReader
}

// Reader retains the dictionary and compression models between solid members.
// Reset must be called after completely consuming the preceding solid member.
type Reader struct{ d decodeReader }

func (r *Reader) Reset(src io.Reader, version int, dictionary, size int64, solid bool) error {
	if dictionary < 0 || dictionary > 64<<20 {
		return ErrMemoryLimit
	}
	v := 0
	switch version {
	case 29, 36:
		v = decode29Ver
	case 50:
		v = decode50Ver
	case 51:
		v = decode70Ver
	default:
		return ErrUnknownDecoder
	}
	if !solid {
		r.d = decodeReader{}
	}
	return r.d.init(bufio.NewReaderSize(src, 64<<10), v, int(dictionary), !solid, solid, size)
}
func (r *Reader) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	defer func() {
		if v := recover(); v != nil {
			n = 0
			err = fmt.Errorf("rar: malformed compression stream: %v", v)
		}
	}()
	return r.d.Read(p)
}
