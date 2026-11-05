package c2r

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"testing"
)

func compress(p []byte) []byte {
	var b bytes.Buffer
	z := zlib.NewWriter(&b)
	_, _ = z.Write(p)
	_ = z.Close()
	return b.Bytes()
}
func envelope(sql string) []byte {
	plain := []byte(sql + "\x00")
	compressed := compress(plain)
	h := make([]byte, 95)
	copy(h, "C2RxUnityDB\xff")
	binary.LittleEndian.PutUint16(h[12:], 0x30)
	binary.LittleEndian.PutUint32(h[14:], 80)
	binary.LittleEndian.PutUint16(h[18:], 15)
	binary.LittleEndian.PutUint32(h[20:], 95)
	binary.LittleEndian.PutUint32(h[24:], uint32(len(compressed)))
	binary.LittleEndian.PutUint32(h[28:], 48)
	binary.LittleEndian.PutUint16(h[32:], 32)
	binary.LittleEndian.PutUint16(h[34:], 1)
	binary.LittleEndian.PutUint32(h[36:], uint32(len(plain)))
	sum := sha256.Sum256(plain)
	copy(h[48:], sum[:])
	copy(h[80:], "16.0.20522\x00OMR\x00")
	return append(h, compressed...)
}
func TestDatabase(t *testing.T) {
	sql := "-- ignored comment\nPRAGMA encoding='UTF-8'; BEGIN TRANSACTION;CREATE TABLE T(id INTEGER, value TEXT);INSERT INTO T VALUES (1,'a,b;()''quote'),(2,'C:\\Office\\Word');COMMIT;"
	data := envelope(sql)
	db, err := ReadDatabase(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Tables["T"]; len(got) != 2 || got[0][1].Text != "a,b;()'quote" || got[1][1].Text != `C:\Office\Word` {
		t.Fatalf("wrong literal decoding: %#v", got)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"hash":           func(p []byte) []byte { p[48] ^= 1; return p },
		"offset":         func(p []byte) []byte { binary.LittleEndian.PutUint32(p[20:], 0xffffffff); return p },
		"output bound":   func(p []byte) []byte { binary.LittleEndian.PutUint32(p[36:], maxDatabase+1); return p },
		"decoded length": func(p []byte) []byte { p[36]++; return p },
		"truncated":      func(p []byte) []byte { return p[:len(p)-1] },
		"trailing":       func(p []byte) []byte { return append(p, 0) },
		"codec":          func(p []byte) []byte { p[34] = 2; return p },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadDatabase(bytes.NewReader(mutate(bytes.Clone(data)))); err == nil {
				t.Fatal("accepted malformed envelope")
			}
		})
	}
}
func TestSQLNeverExecutesExpressions(t *testing.T) {
	for _, sql := range []string{"ATTACH DATABASE 'host' AS X;", "INSERT INTO T VALUES (readfile('/etc/passwd'));", "INSERT INTO T VALUES (1+2);", "INSERT INTO T VALUES ('unterminated);", "INSERT INTO T VALUES (NULL);", "INSERT INTO T VALUES (9223372036854775808);"} {
		if _, err := parseSQL(sql); err == nil {
			t.Fatalf("accepted %q", sql)
		}
	}
}
func fixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	parts := [][]byte{[]byte("first block; "), []byte("second block with Office metadata")}
	plain := append(bytes.Clone(parts[0]), parts[1]...)
	z1, z2 := compress(parts[0]), compress(parts[1])
	stream := append(bytes.Clone(z1), z2...)
	hash := func(p []byte) string { s := sha256.Sum256(p); return base64.StdEncoding.EncodeToString(s[:]) }
	sql := fmt.Sprintf(`INSERT INTO SchemaVersions VALUES (1,5,'OMR');
INSERT INTO Builds VALUES (1,1,1,1,4503600972648056);
INSERT INTO Algorithms VALUES (1,'SHA256');
INSERT INTO Digests VALUES (1,'%s'),(2,'%s'),(3,'%s');
INSERT INTO Hashes VALUES (1,1,0,%d,1),(2,1,0,%d,2),(3,1,0,%d,2),(4,1,%d,%d,3),(5,1,%d,%d,3);
INSERT INTO Directories VALUES (1,''),(2,'root\\Office16');
INSERT INTO Paths VALUES (1,1,'FileSystemMetadata.xml',0),(2,2,'WINWORD.EXE',0);
INSERT INTO Files VALUES (1,1,1,1,1,1,1024),(2,1,2,1,1,2,0);
INSERT INTO Blocks VALUES (1,1,1,2),(2,1,1,4),(3,1,2,2),(4,1,2,4);
INSERT INTO BlockSource VALUES (1,1,1,3),(2,1,2,5),(3,1,3,3),(4,1,4,5);
INSERT INTO Media VALUES (1,1,1,'stream.x64.x-none.dat','');
INSERT INTO Packages VALUES (1,1,1,'Word.x64.x-none.16',0);
INSERT INTO PackagesToPaths VALUES (1,1,1,1),(2,1,2,1);`, hash(plain), hash(z1), hash(z2), len(plain), len(parts[0]), len(z1), len(parts[0]), len(parts[1]), len(z1), len(z2))
	return envelope(sql), stream, plain
}
func TestStreamRandomAccessAndIntegrity(t *testing.T) {
	db, stream, plain := fixture(t)
	a, err := Open(bytes.NewReader(db), bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Entries) != 2 || a.Entries[1].Path != "root/Office16/WINWORD.EXE" || a.Entries[0].Packages[0] != "Word.x64.x-none.16" {
		t.Fatalf("bad index: %+v", a.Entries)
	}
	for _, e := range a.Entries {
		if err := e.Verify(); err != nil {
			t.Fatal(err)
		}
		for _, off := range []int64{0, 10, 14, int64(len(plain) - 2)} {
			b := make([]byte, 9)
			n, err := e.ReadAt(b, off)
			want := plain[off:]
			if len(want) > 9 {
				want = want[:9]
			}
			if !bytes.Equal(b[:n], want) || (n < 9 && err != io.EOF) || (n == 9 && err != nil) {
				t.Fatalf("read %d: %q %v", off, b[:n], err)
			}
		}
		if _, err := e.ReadAt(make([]byte, 1), -1); err == nil {
			t.Fatal("negative offset accepted")
		}
	}
	stream[3] ^= 1
	a, err = Open(bytes.NewReader(db), bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Entries[0].Verify(); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("corruption not detected: %v", err)
	}
}
func TestStreamRejectsInvalidReferencesAndExtents(t *testing.T) {
	data, stream, _ := fixture(t)
	for name, mutate := range map[string]func(*Database){
		"missing hash":   func(d *Database) { d.Tables["Files"][0][3].Number = 999 },
		"duplicate id":   func(d *Database) { d.Tables["Files"] = append(d.Tables["Files"], d.Tables["Files"][0]) },
		"path traversal": func(d *Database) { d.Tables["Paths"][0][2].Text = "../escape" },
		"absolute path":  func(d *Database) { d.Tables["Directories"][0][1].Text = "/host" },
		"collision": func(d *Database) {
			d.Tables["Paths"][1][1].Number = 1
			d.Tables["Paths"][1][2].Text = "FILESYSTEMMETADATA.XML"
		},
		"missing block":   func(d *Database) { d.Tables["BlockSource"] = d.Tables["BlockSource"][1:] },
		"gap":             func(d *Database) { d.Tables["Hashes"][3][2].Number++ },
		"source bounds":   func(d *Database) { d.Tables["Hashes"][2][2].Number = int64(len(stream)) },
		"expansion bound": func(d *Database) { d.Tables["Hashes"][1][3].Number = maxBlock + 1 },
		"codec tag":       func(d *Database) { d.Tables["Files"][0][6].Number = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			d, err := ReadDatabase(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			mutate(d)
			if _, err := openDatabase(d, bytes.NewReader(stream)); err == nil {
				t.Fatal("accepted malformed stream metadata")
			}
		})
	}
}
func TestInflateBounds(t *testing.T) {
	encoded := compress([]byte("abc"))
	for _, p := range [][]byte{append(bytes.Clone(encoded), 0), encoded[:len(encoded)-1], compress([]byte("abcd"))} {
		if _, err := inflate(p, 3); err == nil {
			t.Fatal("accepted bad zlib extent")
		}
	}
}

func TestCompleteFileHashIsIndependent(t *testing.T) {
	db, stream, _ := fixture(t)
	d, err := ReadDatabase(bytes.NewReader(db))
	if err != nil {
		t.Fatal(err)
	}
	wrong := sha256.Sum256([]byte("not the decoded file"))
	d.Tables["Digests"][0][1].Text = base64.StdEncoding.EncodeToString(wrong[:])
	a, err := openDatabase(d, bytes.NewReader(stream))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Entries[0].ReadAt(make([]byte, 4), 0); err != nil {
		t.Fatalf("stored block should still verify: %v", err)
	}
	if err := a.Entries[0].Verify(); err == nil || !strings.Contains(err.Error(), "file SHA-256") {
		t.Fatalf("whole-file hash ignored: %v", err)
	}
}
