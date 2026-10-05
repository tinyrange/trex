package gitstore

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	scsnative "github.com/tinyrange/trex/scs/native"
	"github.com/tinyrange/trex/scs/repo"
	"path/filepath"
	"testing"
)

func TestForwardREFDelta(t *testing.T) {
	base := []byte("abcdef")
	h := sha1.New()
	fmt.Fprintf(h, "blob %d%c", len(base), 0)
	h.Write(base)
	baseID := h.Sum(nil)
	var pack bytes.Buffer
	pack.WriteString("PACK")
	binary.Write(&pack, binary.BigEndian, uint32(2))
	binary.Write(&pack, binary.BigEndian, uint32(2))
	// Forward REF delta: insert X, then copy base[0:6].
	delta := []byte{6, 7, 1, 'X', 0x90, 6}
	pack.WriteByte(0x70 | byte(len(delta)))
	pack.Write(baseID)
	z := zlib.NewWriter(&pack)
	z.Write(delta)
	z.Close()
	pack.WriteByte(0x30 | byte(len(base)))
	z = zlib.NewWriter(&pack)
	z.Write(base)
	z.Close()
	sum := sha1.Sum(pack.Bytes())
	pack.Write(sum[:])
	h = sha1.New()
	h.Write([]byte("blob 7\x00Xabcdef"))
	target := hex.EncodeToString(h.Sum(nil))
	d := Download{Objects: 2, PackBytes: int64(pack.Len()), PackHash: hex.EncodeToString(sum[:]), Refs: map[string]string{"refs/tags/target": target}}
	r, err := scsnative.CreateOptimized(filepath.Join(t.TempDir(), "forward.scs"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if _, err = ImportPack(context.Background(), r, bytes.NewReader(pack.Bytes()), d, Options{}); err != nil {
		t.Fatal(err)
	}
	id, _ := repo.ParseGitOID(target)
	_, got, err := r.ReadGitObject(id)
	if err != nil || string(got) != "Xabcdef" {
		t.Fatal(string(got), err)
	}
	if err = r.Scrub(true); err != nil {
		t.Fatal(err)
	}
}
func TestMalformedDeltaInstructions(t *testing.T) {
	cases := [][]byte{{6, 7, 0}, {6, 7, 127}, {6, 7, 0xff}, {6, 1, 0x91, 6, 2}, {6, 1, 1, 'x', 1, 'y'}, bytes.Repeat([]byte{255}, 12)}
	for _, b := range cases {
		if _, _, err := translateDelta(b, 6); err == nil {
			t.Fatalf("accepted %x", b)
		}
	}
}
