package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/pierrec/lz4/v4"
	"github.com/tinyrange/trex/storage"
	bytecache "github.com/tinyrange/trex/storage/cache"
	starfile "github.com/tinyrange/trex/storage/star"
)

const (
	contentChunkBytes = starfile.PackedChunkBytes
	contentMagic      = "TRXPK002"
	contentHeaderSize = len(contentMagic) + 8 + 2*sha256.Size
	contentIndexSize  = 4 + sha256.Size
	rawContentChunk   = 1 << 31
	maximumContent    = 512 << 20
)

func (c *DerivedCache) GetOrBuildContent(ctx context.Context, digest [sha256.Size]byte, size int64, build func() ([]byte, error)) (storage.Reader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if size < 0 || size > maximumContent {
		return nil, errors.New("invalid derived content size")
	}
	id := hex.EncodeToString(digest[:])
	dir := filepath.Join(c.root, "content-v2", id[:2])
	name := filepath.Join(dir, id[2:])
	file, err := c.openContent(name, digest, size)
	if err == nil {
		return file, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errDerivedRecord) {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := lockHTTPRangeCache(ctx, name+".lock")
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	file, err = c.openContent(name, digest, size)
	if err == nil {
		return file, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errDerivedRecord) {
		return nil, err
	}
	data, err := build()
	if err != nil {
		return nil, err
	}
	if int64(len(data)) != size || sha256.Sum256(data) != digest {
		return nil, errors.New("derived content does not match its admitted digest and size")
	}
	if err := publishContent(ctx, name, digest, data); err != nil {
		return nil, err
	}
	return c.openContent(name, digest, size)
}

type contentChunk struct {
	digest [sha256.Size]byte
	offset int64
	bytes  int
	raw    bool
}

type contentReader struct {
	name   string
	digest [sha256.Size]byte
	size   int64
	chunks []contentChunk
	cache  *bytecache.Cache
	id     uint64
}

func (c *DerivedCache) openContent(name string, digest [sha256.Size]byte, size int64) (*contentReader, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	count := int(storage.CeilDiv(size, contentChunkBytes))
	headerSize := contentHeaderSize + count*contentIndexSize
	if !info.Mode().IsRegular() || info.Size() < int64(headerSize) || info.Size() > int64(headerSize)+size {
		return nil, errDerivedRecord
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(f, header); err != nil {
		return nil, fmt.Errorf("%w: %v", errDerivedRecord, err)
	}
	if string(header[:len(contentMagic)]) != contentMagic ||
		binary.LittleEndian.Uint64(header[len(contentMagic):]) != uint64(size) ||
		[sha256.Size]byte(header[len(contentMagic)+8:]) != digest ||
		[sha256.Size]byte(header[contentHeaderSize-sha256.Size:]) != derivedChecksum(digest, header[contentHeaderSize:]) {
		return nil, errDerivedRecord
	}
	chunks := make([]contentChunk, count)
	offset := int64(headerSize)
	for i := range chunks {
		row := header[contentHeaderSize+i*contentIndexSize:]
		flag := binary.LittleEndian.Uint32(row)
		length, raw := int(flag&^rawContentChunk), flag&rawContentChunk != 0
		decoded := min(int64(contentChunkBytes), size-int64(i)*contentChunkBytes)
		if length == 0 || int64(length) > decoded || raw && int64(length) != decoded {
			return nil, errDerivedRecord
		}
		chunks[i] = contentChunk{digest: [sha256.Size]byte(row[4:]), offset: offset, bytes: length, raw: raw}
		offset += int64(length)
	}
	if offset != info.Size() {
		return nil, errDerivedRecord
	}
	return &contentReader{name: name, digest: digest, size: size, chunks: chunks, cache: c.chunks, id: c.nextSource.Add(1)}, nil
}

func publishContent(ctx context.Context, name string, digest [sha256.Size]byte, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(name), ".content-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	count := int(storage.CeilDiv(int64(len(data)), contentChunkBytes))
	header := make([]byte, contentHeaderSize+count*contentIndexSize)
	copy(header, contentMagic)
	binary.LittleEndian.PutUint64(header[len(contentMagic):], uint64(len(data)))
	copy(header[len(contentMagic)+8:], digest[:])
	if _, err := f.Seek(int64(len(header)), io.SeekStart); err != nil {
		return err
	}
	encoded := make([]byte, lz4.CompressBlockBound(contentChunkBytes))
	for i, offset := 0, 0; offset < len(data); i, offset = i+1, offset+contentChunkBytes {
		if err := ctx.Err(); err != nil {
			return err
		}
		part := data[offset:min(offset+contentChunkBytes, len(data))]
		count, err := lz4.CompressBlock(part, encoded, nil)
		if err != nil {
			return err
		}
		payload, flag := part, uint32(len(part))|rawContentChunk
		if count != 0 && count < len(part) {
			payload, flag = encoded[:count], uint32(count)
		}
		if _, err := f.Write(payload); err != nil {
			return err
		}
		row := header[contentHeaderSize+i*contentIndexSize:]
		binary.LittleEndian.PutUint32(row, flag)
		sum := sha256.Sum256(part)
		copy(row[4:], sum[:])
	}
	indexDigest := derivedChecksum(digest, header[contentHeaderSize:])
	copy(header[contentHeaderSize-sha256.Size:], indexDigest[:])
	if _, err := f.WriteAt(header, 0); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), name)
}

func (r *contentReader) Size() int64 { return r.size }

func (r *contentReader) VerifiedSHA256() ([sha256.Size]byte, bool) {
	return r.digest, true
}

func (r *contentReader) chunk(index int) ([]byte, error) {
	return r.cache.Get(bytecache.Key{Source: r.id, Index: index}, func() ([]byte, error) {
		entry := r.chunks[index]
		f, err := os.Open(r.name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		data := make([]byte, entry.bytes)
		if _, err = f.ReadAt(data, entry.offset); err != nil {
			return nil, fmt.Errorf("read derived content chunk: %w", err)
		}
		length := int(min(int64(contentChunkBytes), r.size-int64(index)*contentChunkBytes))
		if !entry.raw {
			decoded := make([]byte, length)
			count, err := lz4.UncompressBlock(data, decoded)
			if err != nil || count != length {
				return nil, errDerivedRecord
			}
			data = decoded
		}
		if len(data) != length || sha256.Sum256(data) != entry.digest {
			return nil, errors.New("derived content chunk failed verification")
		}
		return data, nil
	})
}

func (r *contentReader) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, errors.New("negative derived content offset")
	}
	read := 0
	for len(p) > 0 && offset < r.size {
		chunk, err := r.chunk(int(offset / contentChunkBytes))
		if err != nil {
			return read, err
		}
		n := copy(p, chunk[offset%contentChunkBytes:])
		offset += int64(n)
		read += n
		p = p[n:]
	}
	if len(p) != 0 {
		return read, io.EOF
	}
	return read, nil
}
