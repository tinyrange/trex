package aea

import (
	"bytes"
	"compress/zlib"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"testing"
)

// Build two clusters, with a partial last segment and authenticated padding.
// Tests exercise random reads, every authentication layer, and bounded output.
func encryptedFixture(compression byte) ([]byte, []byte, []byte) {
	key := bytes.Repeat([]byte{0x42}, 32)
	auth := metadataFixture([]byte("encryption_key\x00" + hex.EncodeToString(key)))[12:]
	plain := []byte("aaaaaaaaaaaaaaaaBBBBBBBBBBBBBBBBtail!")
	salt := bytes.Repeat([]byte{0x17}, 32)
	main := derive(key, salt, indexedInfo("AEA_AMK", 1), 32)
	padding := []byte("authenticated opaque padding")
	padMaterial := derive(main, nil, []byte("AEA_PAK"), 80)
	padMAC := hmac.New(sha256.New, padMaterial[:32])
	padMAC.Write(padding)
	next := padMAC.Sum(nil)
	var clusters []byte
	for cluster := 1; cluster >= 0; cluster-- {
		clusterKey := derive(main, nil, indexedInfo("AEA_CK", uint32(cluster)), 32)
		material := derive(clusterKey, nil, []byte("AEA_CHEK"), 80)
		headers := make([]byte, 2*40)
		macs := make([]byte, 2*32)
		var payload []byte
		for i := 0; i < 2; i++ {
			start := cluster*32 + i*16
			if start >= len(plain) {
				continue
			}
			part := plain[start:min(start+16, len(plain))]
			packed := append([]byte(nil), part...)
			if compression == 'z' {
				var out bytes.Buffer
				w := zlib.NewWriter(&out)
				w.Write(part)
				w.Close()
				if out.Len() < len(part) {
					packed = out.Bytes()
				}
			}
			h := headers[i*40:]
			binary.LittleEndian.PutUint32(h, uint32(len(part)))
			binary.LittleEndian.PutUint32(h[4:], uint32(len(packed)))
			sum := sha256.Sum256(part)
			copy(h[8:], sum[:])
			segmentMaterial := derive(clusterKey, nil, indexedInfo("AEA_SK", uint32(i)), 80)
			crypt(packed, segmentMaterial)
			copy(macs[i*32:], mac(segmentMaterial[:32], packed, nil))
			payload = append(payload, packed...)
		}
		crypt(headers, material)
		trailer := append(append([]byte(nil), next...), macs...)
		next = mac(material[:32], headers, trailer)
		current := append(append(headers, trailer...), payload...)
		clusters = append(current, clusters...)
	}
	root := make([]byte, 48)
	binary.LittleEndian.PutUint64(root, uint64(len(plain)))
	size := 12 + len(auth) + 144 + len(clusters) + len(padding)
	binary.LittleEndian.PutUint64(root[8:], uint64(size))
	binary.LittleEndian.PutUint32(root[16:], 16)
	binary.LittleEndian.PutUint32(root[20:], 2)
	root[24], root[25] = compression, 2
	material := derive(main, nil, []byte("AEA_RHEK"), 80)
	crypt(root, material)
	rootMAC := mac(material[:32], root, append(append([]byte(nil), next...), auth...))
	file := []byte{'A', 'E', 'A', '1', 1, 0, 0, 0}
	file = binary.LittleEndian.AppendUint32(file, uint32(len(auth)))
	for _, p := range [][]byte{auth, salt, rootMAC, root, next, clusters, padding} {
		file = append(file, p...)
	}
	return file, plain, key
}

func TestAuthenticatedRandomAccess(t *testing.T) {
	for _, compression := range []byte{'-', 'z'} {
		b, plain, key := encryptedFixture(compression)
		f, err := Open(bytes.NewReader(b), nil, 1024)
		if err != nil {
			t.Fatal(err)
		}
		for _, span := range [][2]int{{31, 6}, {0, 10}, {15, 18}, {36, 1}} {
			got := make([]byte, span[1])
			if _, err := f.ReadAt(got, int64(span[0])); err != nil || !bytes.Equal(got, plain[span[0]:span[0]+span[1]]) {
				t.Fatalf("read %v: %q %v", span, got, err)
			}
		}
		if err := f.Verify(); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 5)
		if n, err := f.ReadAt(got, f.Size()-2); n != 2 || err != io.EOF {
			t.Fatalf("short read: %d %v", n, err)
		}
		if _, err := Open(bytes.NewReader(b), key, int64(len(plain)-1)); err == nil {
			t.Fatal("ignored decoded limit")
		}
		if _, err := Open(bytes.NewReader(b), bytes.Repeat([]byte{1}, 32), 1024); err == nil {
			t.Fatal("accepted wrong key")
		}
	}
}

func TestRejectTamperingAndTruncation(t *testing.T) {
	b, _, _ := encryptedFixture('-')
	authLength := int(binary.LittleEndian.Uint32(b[8:]))
	cluster := 12 + authLength + 144
	for _, offset := range []int{16, 12 + authLength + 32, 12 + authLength + 64, cluster, cluster + 80, cluster + 112, cluster + 176, len(b) - 1} {
		bad := append([]byte(nil), b...)
		bad[offset] ^= 1
		f, err := Open(bytes.NewReader(bad), nil, 1024)
		if err == nil {
			err = f.Verify()
		}
		if err == nil {
			t.Fatalf("accepted corruption at %d", offset)
		}
	}
	for _, size := range []int{11, cluster - 1, cluster + 175, len(b) - 1} {
		f, err := Open(bytes.NewReader(b[:size]), nil, 1024)
		if err == nil {
			err = f.Verify()
		}
		if err == nil {
			t.Fatalf("accepted truncation at %d", size)
		}
	}
}

func TestMurmurVectors(t *testing.T) {
	// Public MurmurHash3 x64-128 test vectors (low 64-bit half).
	for _, v := range []struct {
		input string
		want  uint64
	}{
		{"", 0}, {"hello", 0xcbd8a7b341bd9b02}, {"foo", 0xe271865701f54561},
	} {
		if got := murmur64([]byte(v.input), 0); got != v.want {
			t.Fatalf("%q: %x != %x", v.input, got, v.want)
		}
	}
}
