// Package c2r reads Office Click-to-Run Unity stream metadata without executing SQL.
package c2r

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/storage"
)

const maxDatabase = 64 << 20

// Cell is either a string literal or a signed integer. No expressions are evaluated.
type Cell struct {
	Text   string
	Number int64
	IsText bool
}
type Database struct{ Tables map[string][][]Cell }

// ReadDatabase decodes the version-0x30 UnityDB envelope and checks its length and
// SHA-256. This is integrity checking, not publisher signature authentication.
func ReadDatabase(r storage.Reader) (*Database, error) {
	if r.Size() < 80 || r.Size() > maxDatabase {
		return nil, fmt.Errorf("c2r: invalid database size")
	}
	h := make([]byte, 80)
	if _, err := r.ReadAt(h, 0); err != nil {
		return nil, err
	}
	u16 := func(n int) uint16 { return binary.LittleEndian.Uint16(h[n:]) }
	u32 := func(n int) int64 { return int64(binary.LittleEndian.Uint32(h[n:])) }
	if string(h[:12]) != "C2RxUnityDB\xff" || u16(12) != 0x30 || u32(14) != 80 || u16(18) < 2 || u32(20) != 80+int64(u16(18)) || u32(28) != 48 || u16(32) != 32 || u16(34) != 1 || u32(40) != 0 || u32(44) != 0 {
		return nil, fmt.Errorf("c2r: unsupported UnityDB header")
	}
	off, size, decoded := u32(20), u32(24), u32(36)
	if off > r.Size() || size != r.Size()-off || decoded > maxDatabase {
		return nil, fmt.Errorf("c2r: invalid UnityDB extents")
	}
	encoded := make([]byte, size)
	if _, err := r.ReadAt(encoded, off); err != nil {
		return nil, err
	}
	plain, err := inflate(encoded, decoded)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(plain)
	if !bytes.Equal(hash[:], h[48:80]) {
		return nil, fmt.Errorf("c2r: database SHA-256 mismatch")
	}
	return parseSQL(strings.TrimSuffix(string(plain), "\x00"))
}

func inflate(encoded []byte, size int64) ([]byte, error) {
	src := bytes.NewReader(encoded)
	z, err := zlib.NewReader(src)
	if err != nil {
		return nil, fmt.Errorf("c2r: zlib: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(z, size+1))
	closeErr := z.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) != size || src.Len() != 0 {
		return nil, fmt.Errorf("c2r: decoded length or trailing data mismatch")
	}
	return data, nil
}

// sqlTokens recognizes only the literal subset emitted by UnityDB. CREATE and
// PRAGMA statements are ignored as data, never handed to a database engine.
type sqlTokens struct {
	text string
	pos  int
}

func (s *sqlTokens) next() (string, bool, error) {
	for s.pos < len(s.text) {
		c := s.text[s.pos]
		if c == ' ' || c == '\r' || c == '\n' || c == '\t' {
			s.pos++
			continue
		}
		if strings.HasPrefix(s.text[s.pos:], "--") {
			n := strings.IndexByte(s.text[s.pos:], '\n')
			if n < 0 {
				s.pos = len(s.text)
				break
			}
			s.pos += n + 1
			continue
		}
		if c == '\'' || c == '"' {
			quote := c
			s.pos++
			var out strings.Builder
			for s.pos < len(s.text) {
				c = s.text[s.pos]
				s.pos++
				if c == quote {
					if s.pos < len(s.text) && s.text[s.pos] == quote {
						out.WriteByte(c)
						s.pos++
						continue
					}
					return out.String(), true, nil
				}
				out.WriteByte(c)
			}
			return "", false, fmt.Errorf("c2r: unterminated SQL string")
		}
		start := s.pos
		s.pos++
		if strings.ContainsRune("(),;", rune(c)) {
			return string(c), false, nil
		}
		for s.pos < len(s.text) && !strings.ContainsRune(" \r\n\t(),;'\"", rune(s.text[s.pos])) {
			s.pos++
		}
		return s.text[start:s.pos], false, nil
	}
	return "", false, io.EOF
}
func parseSQL(text string) (*Database, error) {
	s := &sqlTokens{text: text}
	d := &Database{Tables: map[string][][]Cell{}}
	expect := func(want string) error {
		got, quoted, err := s.next()
		if err != nil {
			return err
		}
		if quoted || got != want {
			return fmt.Errorf("c2r: expected %s, got %q", want, got)
		}
		return nil
	}
	rows := 0
	cells := 0
	for {
		token, quoted, err := s.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if quoted {
			return nil, fmt.Errorf("c2r: quoted SQL statement")
		}
		if token != "INSERT" {
			if token != "PRAGMA" && token != "BEGIN" && token != "COMMIT" && token != "CREATE" {
				return nil, fmt.Errorf("c2r: unsupported SQL statement %q", token)
			}
			for {
				token, quoted, err = s.next()
				if err != nil {
					return nil, err
				}
				if token == ";" && !quoted {
					break
				}
			}
			continue
		}
		if err := expect("INTO"); err != nil {
			return nil, err
		}
		table, quoted, err := s.next()
		if err != nil {
			return nil, err
		}
		if quoted || table == "" || strings.IndexFunc(table, func(r rune) bool {
			return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_')
		}) >= 0 {
			return nil, fmt.Errorf("c2r: invalid table name")
		}
		if len(d.Tables) >= 128 {
			return nil, fmt.Errorf("c2r: too many tables")
		}
		if err := expect("VALUES"); err != nil {
			return nil, err
		}
		for {
			if err := expect("("); err != nil {
				return nil, err
			}
			var row []Cell
			for {
				t, q, err := s.next()
				if err != nil {
					return nil, err
				}
				cell := Cell{Text: t, IsText: q}
				if !q {
					cell.Number, err = strconv.ParseInt(t, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("c2r: nonliteral SQL value %q", t)
					}
				}
				cells++
				if cells > 2000000 {
					return nil, fmt.Errorf("c2r: too many cells")
				}
				row = append(row, cell)
				if len(row) > 64 {
					return nil, fmt.Errorf("c2r: too many columns")
				}
				t, q, err = s.next()
				if err != nil {
					return nil, err
				}
				if !q && t == ")" {
					break
				}
				if q || t != "," {
					return nil, fmt.Errorf("c2r: invalid row separator")
				}
			}
			rows++
			if rows > 1000000 {
				return nil, fmt.Errorf("c2r: too many rows")
			}
			d.Tables[table] = append(d.Tables[table], row)
			t, q, err := s.next()
			if err != nil {
				return nil, err
			}
			if !q && t == ";" {
				break
			}
			if q || t != "," {
				return nil, fmt.Errorf("c2r: invalid record separator")
			}
		}
	}
	return d, nil
}
