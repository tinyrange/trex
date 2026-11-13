package s390

import (
	"bytes"
	"testing"
)

// ddm builds a host D0 structured field.
func ddm(req uint16, body []byte) []byte {
	sf := append([]byte{0, 0, 0xd0, byte(req >> 8), byte(req)}, body...)
	sf[0], sf[1] = byte(len(sf)>>8), byte(len(sf))
	return sf
}

func dftOpenField(name string) []byte {
	body := make([]byte, 35-5)
	copy(body[23:], name+"       ")
	return ddm(dftOpen, body[:30])
}

func dataInsert(data []byte) []byte {
	body := []byte{0xc0, 0x80, 0x61, byte((len(data) + 5) >> 8), byte(len(data) + 5)}
	return ddm(dftDataInsert, append(body, data...))
}

// host writes a structured field and reads the reply as the host does.
func host(t *testing.T, c *Console3270, sf []byte) []byte {
	t.Helper()
	if _, _, st := c.Exec(0x11, sf, false); st != usCE|usDE {
		t.Fatalf("WSF status %X", st)
	}
	out, _, _ := c.Exec(0x06, nil, false)
	return out
}

func TestDFTDownloadAndUpload(t *testing.T) {
	c := NewConsole3270(24, 80)
	var q []byte
	c.Exec(0x11, []byte{0, 5, 1, 0xff, 2}, false)
	q, _, _ = c.Exec(0x02, nil, false)
	if !bytes.Contains(q, []byte{0x81, 0x95, 0x00, 0x00, 0x10, 0x00, 0x10, 0x00, 0x01, 0x01}) {
		t.Fatalf("no DDM query reply: %X", q)
	}

	// Without a transfer the open is refused.
	if r := host(t, c, dftOpenField("FT:DATA")); !bytes.Equal(r, []byte{0x88, 0, 9, 0xd0, 0x00, 0x08, 0x69, 0x04, 0x01, 0x00}) {
		t.Fatalf("refusal %X", r)
	}

	// Download: two inserts, then the closing message.
	x := &Transfer{}
	c.SetTransfer(x)
	if r := host(t, c, dftOpenField("FT:DATA")); !bytes.Equal(r, []byte{0x88, 0, 5, 0xd0, 0, 9}) {
		t.Fatalf("open ack %X", r)
	}
	c.Exec(0x11, ddm(dftSetCursor, nil), false)
	if r := host(t, c, dataInsert([]byte("HELLO\r\n"))); !bytes.Equal(r, []byte{0x88, 0, 0x0b, 0xd0, 0x47, 0x05, 0x63, 0x06, 0, 0, 0, 1}) {
		t.Fatalf("insert ack %X", r)
	}
	if r := host(t, c, dataInsert([]byte("WORLD\r\n"))); r[11] != 2 {
		t.Fatalf("second ack %X", r)
	}
	if r := host(t, c, ddm(dftClose, nil)); !bytes.Equal(r, []byte{0x88, 0, 5, 0xd0, 0x41, 9}) {
		t.Fatalf("close ack %X", r)
	}
	host(t, c, dftOpenField("FT:MSG"))
	host(t, c, dataInsert([]byte("TRANS03 File transfer complete$")))
	if !x.Done || x.Failed || x.Download.String() != "HELLO\r\nWORLD\r\n" || x.Message != "TRANS03 File transfer complete" {
		t.Fatalf("download %+v %q", x, x.Download.String())
	}

	// Upload: the host GETs until end of file; data larger than one
	// buffer arrives in several records.
	up := bytes.Repeat([]byte("0123456789"), 900)
	x = &Transfer{Upload: up}
	c.SetTransfer(x)
	host(t, c, dftOpenField("FT:DATA"))
	var got []byte
	for i := 0; ; i++ {
		r := host(t, c, ddm(dftGet, nil))
		if bytes.Equal(r, []byte{0x88, 0, 9, 0xd0, 0x46, 0x08, 0x69, 0x04, 0x22, 0x00}) {
			break
		}
		if r[4] != 0x46 || r[5] != 0x05 || r[11] != byte(i+1) || r[12] != 0xc0 || r[14] != 0x61 {
			t.Fatalf("get reply %X", r[:17])
		}
		n := int(r[15])<<8 | int(r[16]) - 5
		if int(r[1])<<8|int(r[2]) != 16+n || len(r) != 17+n || n > dftBuffer-27 {
			t.Fatalf("get reply lengths %X n %d", r[:17], n)
		}
		got = append(got, r[17:]...)
	}
	if !bytes.Equal(got, up) || x.Records != 3 {
		t.Fatalf("uploaded %d bytes in %d records", len(got), x.Records)
	}
	host(t, c, ddm(dftClose, nil))
	host(t, c, dftOpenField("FT:MSG"))
	host(t, c, dataInsert([]byte("TRANS13 Error writing file to host$")))
	if !x.Done || !x.Failed {
		t.Fatalf("failure not reported: %+v", x)
	}
}

// A remote terminal receives the structured field and answers it.
func TestDFTPassesThroughToRemoteTerminal(t *testing.T) {
	c := NewConsole3270(24, 80)
	var sent [][]byte
	c.Observe(func(rec []byte) { sent = append(sent, append([]byte(nil), rec...)) })
	sf := dftOpenField("FT:DATA")
	c.Exec(0x11, sf, false)
	if len(sent) != 1 || !bytes.Equal(sent[0], append([]byte{0xf3}, sf...)) {
		t.Fatalf("forwarded %X", sent)
	}
	c.Inbound([]byte{0x88, 0, 5, 0xd0, 0, 9})
	if out, _, _ := c.Exec(0x06, nil, false); !bytes.Equal(out, []byte{0x88, 0, 5, 0xd0, 0, 9}) {
		t.Fatalf("host read %X", out)
	}
}
