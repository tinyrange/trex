package uup

import (
	"fmt"
	"io"

	"github.com/tinyrange/trex/compression/lzms"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
)

// Component-store compression is distinct from WIM resource compression. Delta
// hashes identify expanded bytes, not the DCS representation stored in the WIM.
func expandAssemblyBasis(file storage.Reader) (storage.Reader, error) {
	var magic [4]byte
	if file.Size() < 4 {
		return file, nil
	}
	if _, err := file.ReadAt(magic[:], 0); err != nil {
		return nil, err
	}
	if !lzms.IsDCS(magic[:]) {
		return file, nil
	}
	if file.Size() > maximumCanonicalTarget {
		return nil, fmt.Errorf("compressed basis exceeds bound")
	}
	data := make([]byte, int(file.Size()))
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, file.Size()), data); err != nil {
		return nil, err
	}
	expanded, err := lzms.DecompressDCS(data, uint64(maximumCanonicalTarget))
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Name: "expanded component basis", Data: expanded}, nil
}
