package uup

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"github.com/tinyrange/trex/archive/wim"
	"github.com/tinyrange/trex/windows/msdelta"
	"hash/crc32"
	"io"
	"testing"
)

func TestReverseCheckpointPrecedesUnavailableForwardBasis(t *testing.T) {
	// Independent native UpdateCompression.dll fixture; see ../msdelta/playback.LICENSE.
	decode := func(s string) []byte {
		b, e := base64.StdEncoding.DecodeString(s)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	source := decode("ZW5k")
	delta := decode("UEEzMQAAAAAAAAAAcApgQAxAAAAACAgXEcgAKAg3/ZCZjrmtsPVtoI61wdgOKCAlk4ML4pgebBMO5bqwbiKOIAg2HkjQMI8g4y26X7VjKLrxjXLvDMtDuE9cJi0qah/GyGwMgJKaagoAAACYBAAAAAgAAAAAfAsIAAAACAAAAAgAAAAYAGAPGAJgjYiIiIiIiIiIiIiIiIiIiAg4houwKAAKUeXAGACfBHARAQAAAAAAcBEBAAAAAAApAQAAAAAAAAAGAAAAAAAAAAAAAAMAAAAAAAAAVlZmZmYAAABgAAAAAAAAYAYAAAAAAAAAQGY0VUAABAUABQUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAK3yojb3OMC4VjopZGJzyKIzzpGGbdfn+PukMvUSywC4/wAAOxEBAAAAExQAAAAIAAAAAA==")
	header, err := msdelta.Parse(delta)
	if err != nil {
		t.Fatal(err)
	}
	record := binary.LittleEndian.AppendUint32(nil, crc32.ChecksumIEEE(delta))
	record = append(record, delta...)
	const stem = "amd64_test_token_10.0.26100.9457_none_new"
	const name = "amd64_test_token_10.0.26100.1742_none_old/file.bin"
	const root = "/image6/Windows/WinSxS/" + stem + "/"
	a := &testAssemblyArchive{files: map[string][]byte{root + "file.bin": source, root + "r/file.bin": record}, entries: []wim.EntryInfo{{Name: stem, Directory: true}}}
	d := ContentDescriptor{Name: name, Length: int64(header.TargetSize)}
	copy(d.SHA256[:], header.TargetHash)
	reverse := &reverseAssemblyResolver{base: a, imagePath: "/image6"}
	state := &assemblyContentState{reverse: reverse, prior: []completedAssemblyStage{{stage: &CumulativeStage{Graph: &CumulativeGraph{Payloads: []DeltaPayload{{Target: d}}}}}}}
	query := d
	query.Name = "" // Resolve via the exact old-stage content identity.
	f, err := state.snapshotResolver()(query)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 70000 || sha256.Sum256(data) != d.SHA256 {
		t.Fatal("incorrect checkpoint")
	}
	wrong := d
	wrong.SHA256[0] ^= 1
	if _, found, err := reverse.resolve(wrong); err != nil || found {
		t.Fatalf("wrong digest matched: %v %v", found, err)
	}
	a.files[root+"file.bin"] = []byte("wrong source")
	if _, _, err := reverse.resolve(d); err == nil {
		t.Fatal("accepted incorrect reverse source")
	}
	a.files[root+"file.bin"] = source
	a.files[root+"r/file.bin"] = append([]byte(nil), record...)
	a.files[root+"r/file.bin"][0] ^= 1
	if _, _, err := reverse.resolve(d); err == nil {
		t.Fatal("accepted corrupt CRC")
	}
}
