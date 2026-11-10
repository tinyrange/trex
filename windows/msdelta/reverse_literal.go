package msdelta

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
)

// literalReversePrefix builds the exact PA31 framing without allocating target
// bytes. Uncompressed playback literals have a data-independent encoded size.
// The returned CRC field is filled only after the actual target is appended.
func literalReversePrefix(sourceHash, targetHash [32]byte, targetSize, fileTime, maximum uint64) ([]byte, error) {
	if maximum == 0 || maximum > 128<<20 || targetSize > maximum {
		return nil, fmt.Errorf("msdelta: literal reverse input exceeds bound")
	}
	playback := newDeltaWriter()
	playback.raw(0x4d535250, 32)
	playback.raw(1, 32)
	if targetSize != 0 {
		literal := newDeltaWriter()
		literal.raw(1, 32)
		literal.raw(1, 32)
		literal.raw(0, 32)
		literal.rift([]riftEntry{{0, int64(targetSize)}})
		literal.number(targetSize)
		literal.align()
		prefix := literal.finish()
		playback.number(uint64(len(prefix)) + targetSize)
		playback.align()
		playback.data = append(playback.data, prefix...)
	}
	metadata := newDeltaWriter()
	metadata.number(0x101)
	metadata.number(1)
	metadata.number(0)
	metadata.number(targetSize)
	metadata.number(0x800c)
	metadata.buffer(targetHash[:])
	for _, field := range []uint64{136, 1, 0} {
		metadata.number(field)
	}
	metadata.buffer(sourceHash[:])
	outer := newDeltaWriter()
	outer.buffer(metadata.finish())
	prefix := playback.finish()
	outer.number(uint64(len(prefix)) + targetSize)
	outer.align()
	outer.data = append(outer.data, prefix...)
	record := make([]byte, 4+coreHeaderSize)
	copy(record[4:], "PA31")
	binary.LittleEndian.PutUint64(record[8:], fileTime)
	record = append(record, outer.finish()...)
	if uint64(len(record))+targetSize > maximum {
		return nil, fmt.Errorf("msdelta: literal reverse record exceeds bound")
	}
	return record, nil
}

// LiteralReversePSFRecordSize returns the exact encoded length without reading
// any payload. Hashes and timestamps occupy fixed-width fields.
func LiteralReversePSFRecordSize(targetSize, maximum uint64) (int64, error) {
	prefix, err := literalReversePrefix([32]byte{}, [32]byte{}, targetSize, 0, maximum)
	if err != nil {
		return 0, err
	}
	return int64(len(prefix)) + int64(targetSize), nil
}

// CreateLiteralReversePSFRecord emits source-bound raw reverse playback. The
// caller must obtain sourceHash from the admitted forward content identity.
// Applying the record still requires that exact source hash, even though no
// source bytes are copied. The target is independently SHA-256 protected.
func CreateLiteralReversePSFRecord(sourceHash [32]byte, target []byte, fileTime, maximum uint64) ([]byte, error) {
	prefix, err := literalReversePrefix(sourceHash, sha256.Sum256(target), uint64(len(target)), fileTime, maximum)
	if err != nil {
		return nil, err
	}
	record := make([]byte, len(prefix)+len(target))
	copy(record, prefix)
	copy(record[len(prefix):], target)
	binary.LittleEndian.PutUint32(record, crc32.ChecksumIEEE(record[4:]))
	return record, nil
}
