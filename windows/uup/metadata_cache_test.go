package uup

import (
	"bytes"
	"compress/flate"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func canonicalCacheFixture(t *testing.T, payload string) []byte {
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(payload)))
	index := fmt.Sprintf(`<Container name="u.cab" type="CAB" length="%d" version="1"><Files><File id="1" name="target" length="%d"><Hash alg="SHA256" value="%s"/><Delta><Source type="RAW" name="0"><Hash alg="SHA256" value="%s"/></Source></Delta></File></Files></Container>`, len(payload), len(payload), hash, hash)
	names, contents := []string{"_manifest_.cix.xml", "0"}, []string{index, payload}
	data := make([]byte, 44)
	copy(data, "MSCF")
	data[24], data[25] = 3, 1
	binary.LittleEndian.PutUint32(data[16:], 44)
	binary.LittleEndian.PutUint16(data[26:], 1)
	binary.LittleEndian.PutUint16(data[28:], 2)
	binary.LittleEndian.PutUint16(data[40:], 1)
	var body []byte
	for i, name := range names {
		record := make([]byte, 16)
		binary.LittleEndian.PutUint32(record, uint32(len(contents[i])))
		binary.LittleEndian.PutUint32(record[4:], uint32(len(body)))
		data = append(data, record...)
		data = append(data, []byte(name)...)
		data = append(data, 0)
		body = append(body, []byte(contents[i])...)
	}
	binary.LittleEndian.PutUint32(data[36:], uint32(len(data)))
	binary.LittleEndian.PutUint16(data[42:], 1) // MSZIP exercises the shared decoded cache.
	var encoded bytes.Buffer
	encoded.WriteString("CK")
	w, err := flate.NewWriter(&encoded, flate.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 8)
	binary.LittleEndian.PutUint16(block[4:], uint16(encoded.Len()))
	binary.LittleEndian.PutUint16(block[6:], uint16(len(body)))
	data = append(append(data, block...), encoded.Bytes()...)
	binary.LittleEndian.PutUint32(data[8:], uint32(len(data)))
	return data
}

func TestCanonicalStagesShareBoundWithoutSourceCollisions(t *testing.T) {
	cache, err := NewStageMetadataCache(600) // One fixture folder, not all three.
	if err != nil {
		t.Fatal(err)
	}
	var stages []*CumulativeStage
	for _, payload := range []string{"first", "other", "third"} {
		stage, err := OpenCanonicalStageCache(payload, &starfile.Bytes{Data: canonicalCacheFixture(t, payload)}, cache)
		if err != nil {
			t.Fatal(err)
		}
		stages = append(stages, stage)
	}
	for round := 0; round < 2; round++ {
		for _, stage := range stages {
			file, err := stage.metadataCAB.Lookup("0")
			if err != nil {
				t.Fatal(err)
			}
			got, err := starfile.ReadAll(file)
			if err != nil || !bytes.Equal(got, []byte(stage.MetadataName)) {
				t.Fatalf("cache source collision: %q %v", got, err)
			}
		}
	}
	stats := cache.store.Stats()
	if stats.Bytes > 600 || stats.Evictions == 0 || stats.Loads < 6 {
		t.Fatalf("shared cache not bounded/reloaded: %+v", stats)
	}
	if _, err := OpenCanonicalStageCache("nil", &starfile.Bytes{}, nil); err == nil {
		t.Fatal("nil cache accepted")
	}
}
