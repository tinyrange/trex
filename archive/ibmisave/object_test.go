package ibmisave

import (
	"bytes"
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"golang.org/x/text/encoding/charmap"
)

func objectFixture(t *testing.T, typ uint16) Object {
	t.Helper()
	name := bytes.Repeat([]byte{0x40}, 30)
	copy(name, []byte{0xe3, 0xc5, 0xe2, 0xe3})
	b := make([]byte, 8192)
	binary.BigEndian.PutUint16(b[0x22:], typ)
	copy(b[0x24:], name)
	binary.BigEndian.PutUint64(b[0x18:], 0x123450001000)
	return Object{Name: "TEST", RawName: name, Type: typ, Header: &starfile.Bytes{Data: make([]byte, 4096)}, Data: &starfile.Bytes{Data: b}, Trailer: &starfile.Bytes{}, Sections: []Section{{Address: 0x123450000000, LogicalSize: 8192, Data: &starfile.Bytes{Data: b}}}}
}
func putText(t *testing.T, b []byte, text string) {
	t.Helper()
	for i := range b {
		b[i] = 0x40
	}
	encoded, err := charmap.CodePage037.NewEncoder().String(text)
	if err != nil {
		t.Fatal(err)
	}
	copy(b, encoded)
}

func TestJobDescriptionMetadata(t *testing.T) {
	o := objectFixture(t, 0x1903)
	b := o.Data.(*starfile.Bytes).Data[4096:]
	putText(t, b[2:12], "*RQD")
	putText(t, b[12:22], "QSYSNOMAX")
	putText(t, b[22:32], "QSYS")
	putText(t, b[34:114], "QCMDI")
	v := &objectMetadataView{object: o}
	format, m, err := v.Metadata()
	if err != nil || format != "ibmi_object" {
		t.Fatal(format, err)
	}
	j := m["job_description"].(map[string]any)
	if j["user"] != "*RQD" || j["job_queue"] != "QSYSNOMAX" || j["job_queue_library"] != "QSYS" || j["routing_data"] != "QCMDI" {
		t.Fatal(j)
	}
	if m["decoding"].(map[string]any)["complete"] != false {
		t.Fatal("claimed full decoding")
	}
}

func TestTableAndDataArea(t *testing.T) {
	o := objectFixture(t, 0x1906)
	b := o.Data.(*starfile.Bytes).Data[4096:]
	for i := range 256 {
		b[i] = byte(255 - i)
	}
	v := &objectMetadataView{object: o}
	_, m, err := v.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	mapping := m["table"].(map[string]any)["byte_mapping"].(map[string]string)
	if mapping["00"] != "ff" || mapping["ff"] != "00" {
		t.Fatal(mapping)
	}
	o = objectFixture(t, 0x190a)
	b = o.Data.(*starfile.Bytes).Data[4096:]
	b[0] = 0x84
	binary.BigEndian.PutUint16(b[1:], 3)
	putText(t, b[3:6], "YES")
	v = &objectMetadataView{object: o}
	_, m, err = v.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if m["data_area"].(map[string]any)["text_invariant_ebcdic"] != "YES" {
		t.Fatal(m)
	}
	binary.BigEndian.PutUint16(b[1:], 65535)
	v = &objectMetadataView{object: o}
	_, m, err = v.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if m["data_area"].(map[string]any)["recognized"] != false {
		t.Fatal("accepted oversized data area")
	}
}

func TestUnknownHeaderPreserved(t *testing.T) {
	o := objectFixture(t, 0x1903)
	o.Data.(*starfile.Bytes).Data[0x22] = 0
	v := &objectMetadataView{object: o}
	_, m, err := v.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	if m["object_header"].(map[string]any)["recognized"] != false || m["job_description"] != nil {
		t.Fatal(m)
	}
	entries, err := v.Entries()
	if err != nil || len(entries) != 3 {
		t.Fatal(entries, err)
	}
}

func TestSourceRecords(t *testing.T) {
	b := make([]byte, 4096)
	binary.BigEndian.PutUint16(b, 3)
	binary.BigEndian.PutUint32(b[24:], 93)
	for i := range 2 {
		row := b[32+i*93 : 32+(i+1)*93]
		row[0] = 0x80
		putText(t, row[1:13], "000100000000")
		putText(t, row[13:], "     A          R SIGNON")
	}
	s := Section{Data: &starfile.Bytes{Data: b}, LogicalSize: 8192}
	m, file, err := sourceRecords(s, 2)
	if err != nil || file == nil || m["record_count"] != 2 {
		t.Fatal(m, file, err)
	}
	raw, err := starfile.ReadAll(file.Reader.(starfile.File))
	if err != nil || !bytes.Contains(raw, []byte("R SIGNON")) {
		t.Fatal(string(raw), err)
	}
	b[32+93] = 'X'
	m, file, err = sourceRecords(s, 2)
	if err != nil || file != nil || m["decoded"] != false {
		t.Fatal("accepted malformed row", m, file, err)
	}
}
