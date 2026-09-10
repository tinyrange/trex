// Package msdelta parses and, where supported, applies Microsoft
// delta-compression streams.
package msdelta

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

const (
	coreHeaderSize = 12
	maxHashSize    = 32
)

// Header describes the portable metadata embedded in a PA30 or PA31 delta.
// Preprocess and Patch refer to immutable ranges in the input passed to Parse.
type Header struct {
	Version        string
	TargetFileTime uint64
	FileTypeSet    int64
	FileType       int64
	Flags          int64
	TargetSize     uint64
	HashAlgorithm  uint32
	TargetHash     []byte
	Extension      [3]uint32
	ExtensionHash  []byte
	Preprocess     []byte
	Patch          []byte
}

// ParsePSFRecord verifies and parses the framing used for delta records in a
// PSF payload. The first four bytes are the little-endian IEEE CRC-32 of the
// PA stream that follows.
func ParsePSFRecord(record []byte) (*Header, error) {
	if len(record) < 4 {
		return nil, errors.New("msdelta: truncated PSF record")
	}
	want := binary.LittleEndian.Uint32(record[:4])
	got := crc32.ChecksumIEEE(record[4:])
	if got != want {
		return nil, fmt.Errorf("msdelta: PSF record checksum mismatch: got %08x, want %08x", got, want)
	}
	return Parse(record[4:])
}

// Parse reads a PA30 or PA31 delta header. The input must start at the PA
// signature; PSF payload records commonly put a four-byte checksum before it.
func Parse(data []byte) (*Header, error) {
	if len(data) < coreHeaderSize {
		return nil, errors.New("msdelta: truncated header")
	}
	version := string(data[:4])
	if version != "PA30" && version != "PA31" {
		return nil, fmt.Errorf("msdelta: unsupported signature %q", data[:4])
	}

	bits, err := newBitReader(data[coreHeaderSize:])
	if err != nil {
		return nil, fmt.Errorf("msdelta: outer bitstream: %w", err)
	}
	metadata := bits
	if version == "PA31" {
		data, err := bits.buffer()
		if err != nil {
			return nil, fmt.Errorf("msdelta: PA31 metadata: %w", err)
		}
		metadata, err = newBitReader(data)
		if err != nil {
			return nil, fmt.Errorf("msdelta: PA31 metadata bitstream: %w", err)
		}
	}
	fileTypeSet, err := metadata.number64()
	if err != nil {
		return nil, fmt.Errorf("msdelta: file type set: %w", err)
	}
	fileType, err := metadata.number64()
	if err != nil {
		return nil, fmt.Errorf("msdelta: file type: %w", err)
	}
	flags, err := metadata.number64()
	if err != nil {
		return nil, fmt.Errorf("msdelta: flags: %w", err)
	}
	targetSize, err := metadata.number64()
	if err != nil {
		return nil, fmt.Errorf("msdelta: target size: %w", err)
	}
	if targetSize < 0 {
		return nil, errors.New("msdelta: negative target size")
	}
	hashAlgorithm, err := metadata.number32()
	if err != nil {
		return nil, fmt.Errorf("msdelta: hash algorithm: %w", err)
	}
	targetHash, err := metadata.buffer()
	if err != nil {
		return nil, fmt.Errorf("msdelta: target hash: %w", err)
	}
	if len(targetHash) > maxHashSize {
		return nil, fmt.Errorf("msdelta: target hash is too large: %d", len(targetHash))
	}
	var extension [3]uint32
	var extensionHash []byte
	if version == "PA31" {
		for index := range extension {
			extension[index], err = metadata.number32()
			if err != nil {
				return nil, fmt.Errorf("msdelta: PA31 extension field %d: %w", index, err)
			}
		}
		extensionHash, err = metadata.buffer()
		if err != nil {
			return nil, fmt.Errorf("msdelta: PA31 extension hash: %w", err)
		}
		if len(extensionHash) > maxHashSize {
			return nil, fmt.Errorf("msdelta: PA31 extension hash is too large: %d", len(extensionHash))
		}
		if !metadata.atEnd() {
			return nil, fmt.Errorf("msdelta: %d trailing bytes in PA31 metadata", metadata.remainingBytes())
		}
	}
	preprocess, err := bits.buffer()
	if err != nil {
		return nil, fmt.Errorf("msdelta: preprocessing stream: %w", err)
	}
	patch, err := bits.buffer()
	if err != nil {
		return nil, fmt.Errorf("msdelta: patch stream: %w", err)
	}
	if !bits.atEnd() {
		return nil, fmt.Errorf("msdelta: %d trailing bytes after outer bitstream", bits.remainingBytes())
	}

	return &Header{
		Version:        version,
		TargetFileTime: binary.LittleEndian.Uint64(data[4:12]),
		FileTypeSet:    fileTypeSet,
		FileType:       fileType,
		Flags:          flags,
		TargetSize:     uint64(targetSize),
		HashAlgorithm:  hashAlgorithm,
		TargetHash:     targetHash,
		Extension:      extension,
		ExtensionHash:  extensionHash,
		Preprocess:     preprocess,
		Patch:          patch,
	}, nil
}

type bitReader struct {
	data     []byte
	bytePos  int
	value    uint64
	bitCount uint
	lastPad  uint
}

func newBitReader(data []byte) (*bitReader, error) {
	if len(data) == 0 {
		return nil, errors.New("empty bitstream")
	}
	r := &bitReader{data: data, lastPad: uint(data[0] & 7)}
	pad, err := r.read(3)
	if err != nil {
		return nil, err
	}
	if pad > 7 {
		return nil, fmt.Errorf("invalid padding %d", pad)
	}
	return r, nil
}

func (r *bitReader) fill() {
	for r.bitCount <= 56 && r.bytePos < len(r.data) {
		bits := uint(8)
		if r.bytePos == len(r.data)-1 {
			bits -= r.lastPad
		}
		r.value |= uint64(r.data[r.bytePos]&byte((uint16(1)<<bits)-1)) << r.bitCount
		r.bitCount += bits
		r.bytePos++
	}
}

func (r *bitReader) read(count uint) (uint64, error) {
	if count > 64 {
		return 0, errors.New("bit count exceeds 64")
	}
	if count == 0 {
		return 0, nil
	}
	// fill cannot append a byte when more than 56 bits remain buffered.
	// Wide unaligned reads must consume part of the reservoir first.
	if count > 56 {
		low, err := r.read(32)
		if err != nil {
			return 0, err
		}
		high, err := r.read(count - 32)
		if err != nil {
			return 0, err
		}
		return low | high<<32, nil
	}
	r.fill()
	if r.bitCount < count {
		return 0, errors.New("unexpected end of bitstream")
	}
	var mask uint64 = ^uint64(0)
	if count < 64 {
		mask = (uint64(1) << count) - 1
	}
	value := r.value & mask
	r.value >>= count
	r.bitCount -= count
	return value, nil
}

func (r *bitReader) number32() (uint32, error) {
	value, err := r.number64()
	if err != nil {
		return 0, err
	}
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		return 0, errors.New("number does not fit in 32 bits")
	}
	return uint32(value), nil
}

func (r *bitReader) number64() (int64, error) {
	zeros := uint(0)
	for {
		bit, err := r.read(1)
		if err != nil {
			return 0, err
		}
		if bit != 0 {
			break
		}
		zeros++
		if zeros >= 16 {
			return 0, errors.New("number prefix is too long")
		}
	}
	value, err := r.read((zeros + 1) * 4)
	return int64(value), err
}

func (r *bitReader) buffer() ([]byte, error) {
	length, err := r.number64()
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, errors.New("negative buffer length")
	}
	// Buffers start at the next input-byte boundary. Because unread complete
	// bytes are already in value, bytePos-bitCount/8 identifies that byte.
	start := r.bytePos - int(r.bitCount/8)
	if start < 0 || uint64(length) > uint64(len(r.data)-start) {
		return nil, errors.New("buffer extends past end of bitstream")
	}
	end := start + int(length)
	r.bytePos = end
	r.value = 0
	r.bitCount = 0
	return r.data[start:end], nil
}

func (r *bitReader) atEnd() bool {
	return r.bytePos == len(r.data) && r.bitCount == 0
}

func (r *bitReader) remainingBytes() int {
	return len(r.data) - (r.bytePos - int(r.bitCount/8))
}
