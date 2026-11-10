package windows

import (
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/registry"
)

// Transfer completed writer bytes, never a borrowed file's mutable backing
// slice. The file adapter exposes no mutation path; a later patch copies bytes
// before editing and receives a new version with independent indexes/digest.
func newHiveImage(name string, data []byte) (*starfile.ReaderValue, error) {
	reader, err := registry.OpenOwnedSnapshot(data)
	if err != nil {
		return nil, err
	}
	return starfile.NewReader(name, reader), nil
}

// Deliberately recognize only the native adapter and owned registry reader,
// not arbitrary files claiming immutability or callback-defined providers.
func sharedHiveSnapshot(file starfile.File) *registry.Hive {
	if value, ok := file.(*starfile.ReaderValue); ok {
		if reader, ok := value.StorageReader().(*registry.Hive); ok && reader.IsSnapshot() {
			return reader
		}
	}
	return nil
}
