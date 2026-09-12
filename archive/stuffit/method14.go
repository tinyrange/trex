package stuffit

import (
	"encoding/binary"
	"fmt"

	"github.com/tinyrange/trex/archive/internal/aladdin"
)

// Installer14 uses independently coded blocks with up to 256 KiB of prior
// decoded history. Block sizes include their eight-byte size header; the
// stream's two-byte block count is separate. Original fork CRCs validate the
// result in Open; missing initial history is never synthesized.
func decode14(input []byte, size int) ([]byte, error) {
	if len(input) < 2 || size < 0 {
		return nil, fmt.Errorf("invalid method14 header")
	}
	count := int(binary.LittleEndian.Uint16(input))
	position := 2
	output := make([]byte, 0, min(size, 1<<20))
	for i := 0; i < count; i++ {
		if len(input)-position < 8 {
			return nil, fmt.Errorf("truncated method14 block header")
		}
		stored := int64(binary.LittleEndian.Uint32(input[position:]))
		decoded := int64(binary.LittleEndian.Uint32(input[position+4:]))
		if stored < 8 || stored > int64(len(input)-position) || decoded > 65536 || decoded > int64(size-len(output)) {
			return nil, fmt.Errorf("method14 block sizes outside input or output")
		}
		end := position + int(stored)
		history := output[max(0, len(output)-(256<<10)):]
		block, err := aladdin.Decode(input[position+8:end], history, int(decoded), aladdin.Installer14)
		if err != nil {
			return nil, fmt.Errorf("method14 block %d: %w", i, err)
		}
		output = append(output, block...)
		position = end
	}
	if position != len(input) || len(output) != size {
		return nil, fmt.Errorf("method14 final size mismatch")
	}
	return output, nil
}
