package wise

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"hash/crc32"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
)

func TestOpenWiseOverlay(t *testing.T) {
	payload := bytes.Repeat([]byte("portable-wise-payload\n"), 64)
	image := testWiseImage(t, payload, nil, false, true)
	archive, err := Open(&starfile.Bytes{Name: "setup.exe", Data: image}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	member, err := archive.Lookup("/payload/0001/program.bin")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := starfile.ReadAll(member)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("decoded payload differs: got %d bytes, want %d", len(decoded), len(payload))
	}
}

func testWiseImage(t *testing.T, payload, support []byte, legacyLengths, declareExtent bool) []byte {
	t.Helper()
	payloadDeflated := testDeflate(t, payload)
	script := testWiseScript(payloadDeflated, payload)
	if declareExtent {
		binary.LittleEndian.PutUint32(script[5:9], uint32(len(payloadDeflated)))
	}
	scriptDeflated := testDeflate(t, script)

	image := make([]byte, 640)
	copy(image, "MZ")
	binary.LittleEndian.PutUint32(image[0x3c:0x40], 64)
	copy(image[64:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(image[70:72], 1)
	section := image[88:128]
	binary.LittleEndian.PutUint32(section[16:20], 512)
	binary.LittleEndian.PutUint32(section[20:24], 128)

	overlay := []byte{0} // no external Wise runtime DLL name
	header := make([]byte, 80)
	values := header[24:]
	binary.LittleEndian.PutUint32(values[0:4], uint32(len(script)))
	binary.LittleEndian.PutUint32(values[4:8], uint32(len(scriptDeflated)))
	if legacyLengths {
		binary.LittleEndian.PutUint32(values[20:24], uint32(len(support)))
	} else {
		binary.LittleEndian.PutUint32(values[16:20], 0x00ff2bd8)
	}
	overlay = append(overlay, header...)
	overlay = binary.LittleEndian.AppendUint32(overlay, 0) // no DIB
	overlay = binary.LittleEndian.AppendUint32(overlay, 0)
	overlay = binary.LittleEndian.AppendUint16(overlay, 0x0008)
	overlay = append(overlay, 0) // initialization text length
	overlay = append(overlay, scriptDeflated...)
	overlay = append(overlay, support...)
	overlay = append(overlay, payloadDeflated...)
	image = append(image, overlay...)

	return image
}

func TestWiseSupportFramesAndRuntimeMetadata(t *testing.T) {
	payload := bytes.Repeat([]byte("application data"), 100)
	data := bytes.Repeat([]byte("support data"), 100)
	support := testDeflate(t, data)
	support = binary.LittleEndian.AppendUint32(support, crc32.ChecksumIEEE(data))
	for _, legacy := range []bool{false, true} {
		image := testWiseImage(t, payload, support, legacy, !legacy)
		archive, err := Open(&starfile.Bytes{Data: image}, 1<<20)
		if err != nil {
			t.Fatalf("legacy=%v: %v", legacy, err)
		}
		file, err := archive.Lookup("/support/0001.bin")
		if err != nil {
			t.Fatal(err)
		}
		actual, err := starfile.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, data) {
			t.Fatal("support contents differ")
		}
	}
	corrupt := append([]byte(nil), support...)
	corrupt[len(corrupt)-1] ^= 1
	for _, bad := range [][]byte{corrupt, support[:len(support)-2]} {
		image := testWiseImage(t, payload, bad, false, true)
		if _, err := Open(&starfile.Bytes{Data: image}, 1<<20); err == nil {
			t.Fatal("corrupt/truncated support checksum accepted")
		}
	}
	if _, _, err := readSupportStream(&starfile.Bytes{Data: support}, 0, int64(len(support)), 32); err == nil {
		t.Fatal("support expansion limit ignored")
	}
}

func TestWiseTruncatedOverlayHeader(t *testing.T) {
	image := testWiseImage(t, bytes.Repeat([]byte("payload"), 100), nil, false, true)
	for end := 640; end < 732; end++ {
		if _, err := parseOverlayHeader(&starfile.Bytes{Data: image[:end]}, 640, 1<<20); err == nil {
			t.Fatalf("accepted header truncated at %d", end-640)
		}
	}
}

func testWiseScript(payloadDeflated, payload []byte) []byte {
	data := make([]byte, 43)
	for _, value := range []string{"product", "company", "language"} {
		data = append(data, value...)
		data = append(data, 0)
	}
	data = append(data, make([]byte, 6)...)
	data = append(data, 1)
	fixed := make([]byte, 42)
	binary.LittleEndian.PutUint32(fixed[6:10], uint32(len(payloadDeflated)))
	binary.LittleEndian.PutUint32(fixed[14:18], uint32(len(payload)))
	binary.LittleEndian.PutUint32(fixed[38:42], crc32.ChecksumIEEE(payload))
	data = append(data, 0x00)
	data = append(data, fixed...)
	for _, value := range []string{`%MAINDIR%\program.bin`, "Program file", "PROGRAM.BIN"} {
		data = append(data, value...)
		data = append(data, 0)
	}
	return data
}

func testDeflate(t *testing.T, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := flate.NewWriter(&output, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}
