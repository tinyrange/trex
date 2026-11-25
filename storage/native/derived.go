package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	bytecache "github.com/tinyrange/trex/storage/cache"
)

var errDerivedRecord = errors.New("damaged derived cache record")

const (
	maximumRecordBytes = 64 << 20
	recordHeaderBytes  = 4 + 2*sha256.Size
	syncRecordCount    = 128
)

type derivedRecord struct {
	digest [sha256.Size]byte
	offset int64
	length int
}

type derivedShard struct {
	mu      sync.RWMutex
	file    *os.File
	entries map[[sha256.Size]byte]derivedRecord
	end     int64
	dirty   int
}

// DerivedCache backs portable derived records with private native storage.
// Shards are append-only packs. A partial trailing record is repaired before
// the next append, and record checksums bind each entry to its lookup key.
type DerivedCache struct {
	root       string
	shards     [256]derivedShard
	chunks     *bytecache.Cache
	nextSource atomic.Uint64
}

func NewDerivedCache(root string) (*DerivedCache, error) {
	if root == "" {
		return nil, errors.New("derived cache directory is empty")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("derived cache requires a private, non-symlink directory")
	}
	if err := os.MkdirAll(filepath.Join(root, "records-v1"), 0700); err != nil {
		return nil, err
	}
	return &DerivedCache{root: root, chunks: bytecache.New(32 << 20)}, nil
}

// Close flushes opened packs after all cache users have finished.
func (c *DerivedCache) Close() error {
	var errs []error
	for i := range c.shards {
		shard := &c.shards[i]
		shard.mu.Lock()
		if shard.file != nil {
			if shard.dirty != 0 {
				errs = append(errs, shard.file.Sync())
			}
			errs = append(errs, shard.file.Close())
			shard.file = nil
		}
		shard.mu.Unlock()
	}
	return errors.Join(errs...)
}

func (c *DerivedCache) GetOrBuild(ctx context.Context, key [sha256.Size]byte, maximum int64, build func() ([]byte, error)) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if maximum < 0 || maximum > maximumRecordBytes {
		return nil, errors.New("invalid derived cache record limit")
	}
	shard := &c.shards[key[0]]
	shard.mu.RLock()
	data, err := shard.read(key, maximum)
	shard.mu.RUnlock()
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errDerivedRecord) {
		return nil, err
	}

	path := filepath.Join(c.root, "records-v1", fmt.Sprintf("%02x.pack", key[0]))
	data, err = updateDerivedShard(ctx, shard, path, key, maximum, nil)
	if err == nil {
		return data, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errDerivedRecord) {
		return nil, err
	}
	data, err = build()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("derived cache builder exceeded its record limit")
	}
	// Builders may resolve nested artifacts in the same shard. Publication
	// checks for concurrent additions after the lock-free build finishes.
	return updateDerivedShard(ctx, shard, path, key, maximum, &data)
}

func updateDerivedShard(ctx context.Context, shard *derivedShard, path string, key [sha256.Size]byte, maximum int64, built *[]byte) ([]byte, error) {
	shard.mu.Lock()
	defer shard.mu.Unlock()
	data, err := shard.read(key, maximum)
	if err == nil || !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errDerivedRecord) {
		return data, err
	}
	lock, err := lockHTTPRangeCache(ctx, path+".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := shard.refresh(path); err != nil {
		return nil, err
	}
	data, err = shard.read(key, maximum)
	if built == nil || err == nil || !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errDerivedRecord) {
		return data, err
	}
	return *built, shard.appendRecord(key, *built)
}

func derivedChecksum(key [sha256.Size]byte, data []byte) [sha256.Size]byte {
	hash := sha256.New()
	_, _ = hash.Write(key[:])
	_, _ = hash.Write(data)
	return [sha256.Size]byte(hash.Sum(nil))
}

// refresh indexes newly published records while the shard's OS lock is held.
// An interrupted append is truncated at its first incomplete record.
func (s *derivedShard) refresh(path string) error {
	if s.file == nil {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
		if err != nil {
			return err
		}
		s.file = f
		s.entries = make(map[[sha256.Size]byte]derivedRecord)
	}
	info, err := s.file.Stat()
	if err != nil {
		return err
	}
	if s.end > info.Size() {
		clear(s.entries)
		s.end = 0
	}
	var header [recordHeaderBytes]byte
	for s.end+recordHeaderBytes <= info.Size() {
		if _, err := s.file.ReadAt(header[:], s.end); err != nil {
			return err
		}
		length := int64(binary.LittleEndian.Uint32(header[:]))
		offset := s.end + recordHeaderBytes
		if length > maximumRecordBytes || length > info.Size()-offset {
			break
		}
		key := [sha256.Size]byte(header[4:])
		s.entries[key] = derivedRecord{digest: [sha256.Size]byte(header[4+sha256.Size:]), offset: offset, length: int(length)}
		s.end = offset + length
	}
	if s.end < info.Size() {
		return s.file.Truncate(s.end)
	}
	return nil
}

func (s *derivedShard) read(key [sha256.Size]byte, maximum int64) ([]byte, error) {
	entry, ok := s.entries[key]
	if !ok || s.file == nil {
		return nil, os.ErrNotExist
	}
	if int64(entry.length) > maximum {
		return nil, errDerivedRecord
	}
	data := make([]byte, entry.length)
	if _, err := s.file.ReadAt(data, entry.offset); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errDerivedRecord
		}
		return nil, err
	}
	if derivedChecksum(key, data) != entry.digest {
		return nil, errDerivedRecord
	}
	return data, nil
}

func (s *derivedShard) appendRecord(key [sha256.Size]byte, data []byte) error {
	digest := derivedChecksum(key, data)
	record := make([]byte, recordHeaderBytes+len(data))
	binary.LittleEndian.PutUint32(record, uint32(len(data)))
	copy(record[4:], key[:])
	copy(record[4+sha256.Size:], digest[:])
	copy(record[recordHeaderBytes:], data)
	if _, err := s.file.WriteAt(record, s.end); err != nil {
		return err
	}
	s.entries[key] = derivedRecord{digest: digest, offset: s.end + recordHeaderBytes, length: len(data)}
	s.end += int64(len(record))
	s.dirty++
	if s.dirty >= syncRecordCount {
		if err := s.file.Sync(); err != nil {
			return err
		}
		s.dirty = 0
	}
	return nil
}
