package nsis

import (
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/archive/sevenzip"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
)

func listSolidLZMA(source storage.Reader, offset, block, end, total, headerSize int64, props []byte, o Options) (*Listing, error) {
	stream, err := sevenzip.NewLZMAStream(io.NewSectionReader(source, block+5, end-block-5), props, 64<<20)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(stream, o.MaxSolidBytes+1))
	if err != nil {
		return nil, fmt.Errorf("nsis: solid LZMA: %w", err)
	}
	if int64(len(data)) > o.MaxSolidBytes {
		return nil, ErrLimit
	}
	if int64(len(data)) < 4+headerSize || int64(binary.LittleEndian.Uint32(data)) != headerSize {
		return nil, fmt.Errorf("nsis: solid metadata size mismatch")
	}
	l := &Listing{HeaderOffset: offset, DataOffset: 4 + headerSize, HeaderSize: headerSize, HeaderCompression: "lzma-solid", ContainerSize: total, solidData: data}
	if err := l.parseMetadata(data[4:4+headerSize], &starfile.Bytes{Data: data}, int64(len(data)), o); err != nil {
		return nil, err
	}
	return l, nil
}
