package upx

import (
	"bytes"
	"encoding/binary"
	"hash/adler32"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestDOSImage(t *testing.T) {
	// One literal, a distance-one match of nineteen bytes, and the end marker.
	payload := []byte{0x90, 'A', 0x04, 0, 0, 0, 0, 0, 0x12, 0xff}
	image := bytes.Repeat([]byte{'A'}, 20)
	var header [27]byte
	copy(header[:], "UPX!")
	header[4], header[5], header[6] = 13, 3, 3
	binary.LittleEndian.PutUint32(header[8:], adler32.Checksum(image))
	binary.LittleEndian.PutUint32(header[12:], adler32.Checksum(payload))
	header[16], header[19], header[22] = byte(len(image)), byte(len(payload)), byte(len(image)+32)
	var sum int
	for _, b := range header[4:26] {
		sum += int(b)
	}
	header[26] = byte(sum % 251)

	const offset = 8
	file := &starfile.Bytes{Data: append(append(make([]byte, offset), header[:]...), payload...)}
	decoded, err := DOSImage(file, offset)
	if err != nil || !bytes.Equal(decoded, image) {
		t.Fatalf("DOSImage = %q, %v", decoded, err)
	}
	file.Data[len(file.Data)-1] ^= 1
	if _, err := DOSImage(file, offset); err == nil {
		t.Fatal("accepted a payload with an invalid checksum")
	}
	if _, err := DOSImage(&starfile.Bytes{Data: file.Data[:len(file.Data)-1]}, offset); err == nil {
		t.Fatal("accepted a truncated payload")
	}
}

func TestNRV2BRejectsInvalidMatchAndEnd(t *testing.T) {
	payload := []byte{0x90, 'A', 0x04, 0, 0, 0, 0, 0, 0x12, 0xff}
	for _, size := range []int{19, 21} {
		if _, err := decodeNRV2B8(payload, size); err == nil {
			t.Errorf("accepted NRV2B stream with declared image size %d", size)
		}
	}
	if _, err := decodeNRV2B8(payload[:len(payload)-1], 20); err == nil {
		t.Error("accepted truncated NRV2B end marker")
	}
}
