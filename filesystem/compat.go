package filesystem

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/block"
	starfile "github.com/tinyrange/trex/storage/star"
)

type blockDeviceExtenter = block.Extenter

func validateBlockRange(size, offset, length int64) error {
	return block.ValidateRange(size, offset, length)
}

func writeFileRangeTo(writer io.Writer, file starfile.File, offset, size int64) error {
	if offset < 0 || size < 0 || offset > file.Size() {
		return fmt.Errorf("read: invalid file range")
	}
	if size > file.Size()-offset {
		size = file.Size() - offset
	}
	_, err := io.CopyN(writer, io.NewSectionReader(file, offset, size), size)
	return err
}

func writeZerosTo(writer io.Writer, size int64) (int64, error) {
	return io.CopyN(writer, zeroReader{}, size)
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
}
