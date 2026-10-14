package aea

// Format/key-derivation reference and MIT notice: LICENSE.reference.

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/tinyrange/trex/archive/lzfse"
	"github.com/tinyrange/trex/compression/lzvn"
	"github.com/tinyrange/trex/storage"
	"golang.org/x/crypto/hkdf"
)

const maxSegment = 64 << 20

type segment struct {
	offset, start  int64
	packed, size   uint32
	cluster, index uint32
	mac            [32]byte
	checksum       []byte
}

// File is an authenticated, lazy profile-1 AEA1 plaintext view. Input bytes must
// remain unchanged. Header and cluster MACs authenticate layout; each segment's
// MAC and plaintext checksum are checked before returning its bytes.
type File struct {
	source                          storage.Reader
	size                            int64
	EncryptedSize                   int64
	SegmentSize, SegmentsPerCluster uint32
	Compression, Checksum           byte
	mainKey                         []byte
	firstMAC                        []byte
	dataOffset                      int64
	once                            sync.Once
	indexErr                        error
	segments                        []segment
	mu                              sync.Mutex
	cachedIndex                     int
	cached                          []byte
}

func read(source storage.Reader, offset, size int64) ([]byte, error) {
	if offset < 0 || size < 0 || size > maxSegment || offset > source.Size() || size > source.Size()-offset {
		return nil, fmt.Errorf("aea: invalid source extent")
	}
	b := make([]byte, int(size))
	_, err := io.ReadFull(io.NewSectionReader(source, offset, size), b)
	return b, err
}

func derive(key, salt, info []byte, size int) []byte {
	b := make([]byte, size)
	// All call sites use SHA-256 with a fixed bounded output length.
	if _, err := io.ReadFull(hkdf.New(sha256.New, key, salt, info), b); err != nil {
		panic(err)
	}
	return b
}

func mac(key, data, salt []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(salt)
	m.Write(data)
	var length [8]byte
	binary.LittleEndian.PutUint64(length[:], uint64(len(salt)))
	m.Write(length[:])
	return m.Sum(nil)
}

func crypt(data, material []byte) {
	block, err := aes.NewCipher(material[32:64])
	if err != nil {
		panic(err)
	}
	cipher.NewCTR(block, material[64:80]).XORKeyStream(data, data)
}

func indexedInfo(name string, index uint32) []byte {
	return binary.LittleEndian.AppendUint32([]byte(name), index)
}

// Open authenticates a symmetric-encryption AEA header. A nil key selects the
// explicit encryption_key metadata field; it never fetches remote keys. Other
// profiles require different key derivation and are rejected. Zero maximum
// selects a 4 GiB decoded limit. Decryption never creates host files.
func Open(source storage.Reader, key []byte, maximum int64) (*File, error) {
	metadata, err := ReadMetadata(source)
	if err != nil {
		return nil, err
	}
	if metadata.Profile != 1 || metadata.ScryptStrength != 0 {
		return nil, fmt.Errorf("aea: unsupported profile/strength %d/%d", metadata.Profile, metadata.ScryptStrength)
	}
	if key == nil {
		value, ok := metadata.Values["encryption_key"]
		if !ok {
			return nil, fmt.Errorf("aea: symmetric key required")
		}
		key, err = hex.DecodeString(string(value))
		if err != nil {
			return nil, fmt.Errorf("aea: invalid embedded key")
		}
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("aea: expected 32-byte symmetric key")
	}
	if maximum == 0 {
		maximum = 4 << 30
	}
	if maximum < 0 {
		return nil, fmt.Errorf("aea: negative decoded limit")
	}
	auth, err := read(metadata.AuthData, 0, metadata.AuthData.Size())
	if err != nil {
		return nil, err
	}
	offset := int64(12) + int64(len(auth))
	h, err := read(source, offset, 32+112)
	if err != nil {
		return nil, err
	}
	mainKey := derive(key, h[:32], indexedInfo("AEA_AMK", 1), 32)
	material := derive(mainKey, nil, []byte("AEA_RHEK"), 80)
	root := h[64:112]
	firstMAC := h[112:144]
	salt := append(append([]byte(nil), firstMAC...), auth...)
	if !hmac.Equal(h[32:64], mac(material[:32], root, salt)) {
		return nil, fmt.Errorf("aea: root header authentication failed")
	}
	crypt(root, material)
	u32, u64 := binary.LittleEndian.Uint32, binary.LittleEndian.Uint64
	size, encrypted := u64(root), u64(root[8:])
	segmentSize, perCluster := u32(root[16:]), u32(root[20:])
	if size > uint64(maximum) || encrypted > uint64(source.Size()) || encrypted < uint64(offset+144) ||
		segmentSize == 0 || segmentSize > maxSegment || perCluster == 0 || perCluster > 65536 ||
		(size+uint64(segmentSize)-1)/uint64(segmentSize) > 1<<20 {
		return nil, fmt.Errorf("aea: invalid root geometry (size=%d encrypted=%d segment=%d cluster=%d)", size, encrypted, segmentSize, perCluster)
	}
	if root[25] > 2 {
		return nil, fmt.Errorf("aea: unsupported checksum %d", root[25])
	}
	return &File{source: source, size: int64(size), EncryptedSize: int64(encrypted), SegmentSize: segmentSize,
		SegmentsPerCluster: perCluster, Compression: root[24], Checksum: root[25], mainKey: mainKey,
		firstMAC: firstMAC, dataOffset: offset + 144, cachedIndex: -1}, nil
}

func (f *File) Size() int64 { return f.size }

func (f *File) index() error {
	checksumSize := [...]int{0, 8, 32}[f.Checksum]
	width := int64(8 + checksumSize)
	offset, total := f.dataOffset, int64(0)
	expected := f.firstMAC
	for cluster := uint32(0); total < f.size; cluster++ {
		key := derive(f.mainKey, nil, indexedInfo("AEA_CK", cluster), 32)
		material := derive(key, nil, []byte("AEA_CHEK"), 80)
		headerSize := width * int64(f.SegmentsPerCluster)
		h, err := read(f.source, offset, headerSize+32+32*int64(f.SegmentsPerCluster))
		if err != nil {
			return err
		}
		if !hmac.Equal(expected, mac(material[:32], h[:headerSize], h[headerSize:])) {
			return fmt.Errorf("aea: cluster %d authentication failed", cluster)
		}
		expected = append([]byte(nil), h[headerSize:headerSize+32]...)
		crypt(h[:headerSize], material)
		offset += int64(len(h))
		for i := uint32(0); i < f.SegmentsPerCluster; i++ {
			entry := h[int64(i)*width : int64(i+1)*width]
			size, packed := binary.LittleEndian.Uint32(entry), binary.LittleEndian.Uint32(entry[4:])
			want := uint32(min(int64(f.SegmentSize), f.size-total))
			if size != want || (size == 0 && packed != 0) || (size != 0 && (packed == 0 || packed > maxSegment)) ||
				offset > f.EncryptedSize || int64(packed) > f.EncryptedSize-offset {
				return fmt.Errorf("aea: invalid cluster %d segment %d extent", cluster, i)
			}
			if size == 0 {
				continue
			}
			s := segment{offset: offset, start: total, packed: packed, size: size, cluster: cluster, index: i,
				checksum: append([]byte(nil), entry[8:]...)}
			copy(s.mac[:], h[headerSize+32+int64(i)*32:])
			f.segments = append(f.segments, s)
			offset += int64(packed)
			total += int64(size)
		}
	}
	// The final cluster MAC authenticates optional opaque padding with a plain
	// HMAC (unlike the salted/length-suffixed header and segment MACs).
	if offset < f.source.Size() {
		material := derive(f.mainKey, nil, []byte("AEA_PAK"), 80)
		m := hmac.New(sha256.New, material[:32])
		if _, err := io.Copy(m, io.NewSectionReader(f.source, offset, f.source.Size()-offset)); err != nil {
			return err
		}
		if !hmac.Equal(expected, m.Sum(nil)) {
			return fmt.Errorf("aea: padding authentication failed")
		}
	}
	return nil
}

func (f *File) decode(index int) ([]byte, error) {
	s := f.segments[index]
	b, err := read(f.source, s.offset, int64(s.packed))
	if err != nil {
		return nil, err
	}
	clusterKey := derive(f.mainKey, nil, indexedInfo("AEA_CK", s.cluster), 32)
	material := derive(clusterKey, nil, indexedInfo("AEA_SK", s.index), 80)
	if !hmac.Equal(s.mac[:], mac(material[:32], b, nil)) {
		return nil, fmt.Errorf("aea: segment %d authentication failed", index)
	}
	crypt(b, material)
	if s.packed != s.size {
		switch f.Compression {
		case 'e':
			decoded, err := lzfse.Open(bytes.NewReader(b), int64(s.size))
			if err != nil {
				return nil, err
			}
			if decoded.Size() != int64(s.size) {
				return nil, fmt.Errorf("aea: LZFSE length mismatch")
			}
			b, err = io.ReadAll(io.NewSectionReader(decoded, 0, decoded.Size()))
			if err != nil {
				return nil, err
			}
		case 'f':
			b, err = lzvn.Decode(b, int(s.size), nil)
			if err != nil {
				return nil, err
			}
		case 'z':
			input := bytes.NewReader(b)
			decoded, err := zlib.NewReader(input)
			if err != nil {
				return nil, err
			}
			b, err = io.ReadAll(io.LimitReader(decoded, int64(s.size)+1))
			closeErr := decoded.Close()
			if err != nil {
				return nil, err
			}
			if closeErr != nil {
				return nil, closeErr
			}
			if input.Len() != 0 {
				return nil, fmt.Errorf("aea: trailing zlib bytes")
			}
		default:
			return nil, fmt.Errorf("aea: unsupported compression %q", f.Compression)
		}
	}
	if len(b) != int(s.size) {
		return nil, fmt.Errorf("aea: decoded segment length mismatch")
	}
	switch f.Checksum {
	case 1:
		if murmur64(b, 0xe2236fdc26a5f6d2) != binary.LittleEndian.Uint64(s.checksum) {
			return nil, fmt.Errorf("aea: segment %d Murmur checksum failed", index)
		}
	case 2:
		sum := sha256.Sum256(b)
		if !hmac.Equal(sum[:], s.checksum) {
			return nil, fmt.Errorf("aea: segment %d SHA256 checksum failed", index)
		}
	}
	return b, nil
}

func (f *File) ReadAt(p []byte, offset int64) (int, error) {
	if offset < 0 {
		return 0, fmt.Errorf("aea: negative read offset")
	}
	if len(p) == 0 {
		return 0, nil
	}
	if offset >= f.size {
		return 0, io.EOF
	}
	f.once.Do(func() { f.indexErr = f.index() })
	if f.indexErr != nil {
		return 0, f.indexErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for n < len(p) && offset < f.size {
		index := sort.Search(len(f.segments), func(i int) bool { return f.segments[i].start+int64(f.segments[i].size) > offset })
		if index != f.cachedIndex {
			data, err := f.decode(index)
			if err != nil {
				return n, err
			}
			f.cached, f.cachedIndex = data, index
		}
		count := copy(p[n:], f.cached[offset-f.segments[index].start:])
		offset += int64(count)
		n += count
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Verify forces all segment MACs/checksums and the authenticated layout/padding.
func (f *File) Verify() error {
	f.once.Do(func() { f.indexErr = f.index() })
	if f.indexErr != nil {
		return f.indexErr
	}
	_, err := io.Copy(io.Discard, io.NewSectionReader(f, 0, f.Size()))
	return err
}
