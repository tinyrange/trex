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
	payloadDeflated := testDeflate(t, payload)
	script := testWiseScript(payloadDeflated, payload)
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
	overlay = append(overlay, header...)
	overlay = binary.LittleEndian.AppendUint32(overlay, 0) // no DIB
	overlay = binary.LittleEndian.AppendUint32(overlay, 0)
	overlay = binary.LittleEndian.AppendUint16(overlay, 0x0008)
	overlay = append(overlay, 0) // initialization text length
	overlay = append(overlay, scriptDeflated...)
	overlay = append(overlay, payloadDeflated...)
	image = append(image, overlay...)

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
