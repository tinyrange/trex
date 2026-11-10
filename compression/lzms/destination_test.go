package lzms

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"
)

// Independently produced Microsoft Compression API fixture, with a known
// decoded hash. Repeat blocks to catch accidental history or transform sharing.
const destinationFixture = "ClHlwBgAhAVABgAAAAAAAEAGAAAAAAAAkgAAAAQARfdrtfrZUm9WA3h6mDEAAOo527nksWWgsh4yuTA9q9eV9CaGsbpsq4gwZnNhcmIVCJ1ZGJmmLI/tzC0Nr8oBuXtDqpDmzqxTcm91cWlVkVuZnqVTpZmBVDtpdxZRpZTXZh2FQYG4nL2RgeTphbFZPnQgcmV2byBzcG11aiB4b2YgbndvcmIga2NpdXEgZWhU"
const destinationHash = "c499ced01eba23df9a46e68de3db441945f1e46d3ceb97270aeb471f1c34753c"

func TestDecompressDestinationConfinesWrites(t *testing.T) {
	frame, err := base64.StdEncoding.DecodeString(destinationFixture)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(frame)
	backing := bytes.Repeat([]byte{0xa5}, 1632)
	// Deliberately leave capacity beyond the destination. Decoder must clamp it.
	if err := decompressInto(frame[28:], backing[16:1616]); err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(backing[16:1616])); got != destinationHash {
		t.Fatal(got)
	}
	if !bytes.Equal(backing[:16], bytes.Repeat([]byte{0xa5}, 16)) || !bytes.Equal(backing[1616:], bytes.Repeat([]byte{0xa5}, 16)) || !bytes.Equal(frame, original) {
		t.Fatal("decoder changed input or adjacent destination")
	}
	for _, raw := range [][]byte{frame[28:30], frame[28:31]} {
		if err := decompressInto(raw, backing[16:1616]); err == nil {
			t.Fatal("accepted truncated block")
		}
		if !bytes.Equal(backing[:16], bytes.Repeat([]byte{0xa5}, 16)) || !bytes.Equal(backing[1616:], bytes.Repeat([]byte{0xa5}, 16)) {
			t.Fatal("failed decode changed guards")
		}
	}
}

func TestContainerDestinationIndependentMixedChunks(t *testing.T) {
	first, err := base64.StdEncoding.DecodeString(destinationFixture)
	if err != nil {
		t.Fatal(err)
	}
	frame := bytes.Clone(first)
	binary.LittleEndian.PutUint64(frame[8:16], 3204)
	frame[6] = containerHeaderCRC(frame[:24])
	frame = append(frame, first[24:]...)
	frame = append(frame, 4, 0, 0, 0, 0xe8, 0, 0, 0)
	got, err := DecompressContainer(frame, 3204)
	if err != nil || len(got) != 3204 {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
	for _, part := range [][]byte{got[:1600], got[1600:3200]} {
		if hash := fmt.Sprintf("%x", sha256.Sum256(part)); hash != destinationHash {
			t.Fatal(hash)
		}
	}
	if !bytes.Equal(got[3200:], []byte{0xe8, 0, 0, 0}) {
		t.Fatal("raw tail changed")
	}
	if partial, err := DecompressContainer(append(frame, 0), 3204); err == nil || partial != nil {
		t.Fatal("partial frame exposed")
	}

	dcs := make([]byte, 12)
	copy(dcs, "DCS\x01")
	binary.LittleEndian.PutUint32(dcs[4:], 2)
	binary.LittleEndian.PutUint32(dcs[8:], 3200)
	for range 2 {
		header := make([]byte, 8)
		binary.LittleEndian.PutUint32(header, uint32(len(first[28:])+4))
		binary.LittleEndian.PutUint32(header[4:], 1600)
		dcs = append(dcs, header...)
		dcs = append(dcs, first[28:]...)
	}
	gotDCS, err := DecompressDCS(dcs, 3200)
	if err != nil || !bytes.Equal(gotDCS, got[:3200]) {
		t.Fatalf("DCS chunk independence: %v", err)
	}
}
