package native

import starvalue "github.com/tinyrange/trex/storage/star"

const retainedChunkBytes = starvalue.PackedChunkBytes
const maximumRetainedReadCache = 64 << 20

type retainedFileStore = starvalue.PackedFileStore
type retainedFile = starvalue.PackedFile

func newRetainedFileStore() (*retainedFileStore, error) {
	return starvalue.NewPackedFileStore(maximumRetainedReadCache, true)
}
