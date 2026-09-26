package cab

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
	starfile "github.com/tinyrange/trex/storage/star"
)

func companionFixture(sequence uint16, previous, next string, folder uint16, payload string) []byte {
	data := make([]byte, 36)
	copy(data, "MSCF")
	data[24], data[25] = 3, 1
	binary.LittleEndian.PutUint16(data[26:], 1)
	binary.LittleEndian.PutUint16(data[28:], 1)
	binary.LittleEndian.PutUint16(data[32:], 123)
	binary.LittleEndian.PutUint16(data[34:], sequence)
	for index, name := range []string{previous, next} {
		if name != "" {
			data[30] |= byte(1 << index)
			data = append(data, []byte(name)...)
			data = append(data, 0, 0)
		}
	}
	folderAt := len(data)
	data = append(data, make([]byte, 8)...)
	binary.LittleEndian.PutUint16(data[folderAt+4:], 1)
	binary.LittleEndian.PutUint32(data[16:], uint32(len(data)))
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record, 9)
	binary.LittleEndian.PutUint16(record[8:], folder)
	data = append(data, record...)
	data = append(data, []byte("whole.txt\x00")...)
	binary.LittleEndian.PutUint32(data[folderAt:], uint32(len(data)))
	block := make([]byte, 8)
	binary.LittleEndian.PutUint16(block[4:], uint16(len(payload)))
	binary.LittleEndian.PutUint16(block[6:], uint16(len(payload)))
	data = append(data, block...)
	data = append(data, []byte(payload)...)
	binary.LittleEndian.PutUint32(data[8:], uint32(len(data)))
	return data
}

func companionFiles() map[string][]byte {
	return map[string][]byte{
		"one.cab":   companionFixture(0, "", "two.cab", cabFolderContinuedToNext, "abc"),
		"two.cab":   companionFixture(1, "one.cab", "three.cab", cabFolderContinuedBoth, "def"),
		"three.cab": companionFixture(2, "two.cab", "", cabFolderContinuedFromPrevious, "ghi"),
	}
}

func companionOptions(t *testing.T, files map[string][]byte, entry string) auto.Options {
	t.Helper()
	var entries []auto.Entry
	for name, data := range files {
		entries = append(entries, auto.Entry{Name: "media/" + name, Kind: "file", Reader: &starfile.Bytes{Data: data}})
	}
	tree, err := auto.Tree(entries, auto.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return auto.Options{Source: &auto.SourceContext{Tree: tree, Path: "media/" + entry}}
}

func TestAutoDiscoversCompleteCABSetFromAnyVolume(t *testing.T) {
	files := companionFiles()
	for name, data := range files {
		t.Run(name, func(t *testing.T) {
			root := auto.Open(&starfile.Bytes{Data: data}, name, companionOptions(t, files, name))
			member, err := root.Resolve("whole.txt")
			if err != nil {
				t.Fatal(err)
			}
			for _, offset := range []int64{6, 0, 3} {
				buffer := make([]byte, 3)
				if _, err := member.Reader().ReadAt(buffer, offset); err != nil || string(buffer) != "abcdefghi"[offset:offset+3] {
					t.Fatalf("read at %d = %q, %v", offset, buffer, err)
				}
			}
		})
	}
}

func TestAutoCABRejectsInvalidCompanions(t *testing.T) {
	for _, test := range []struct {
		name, want string
		change     func(map[string][]byte)
	}{
		{"missing", "companion", func(m map[string][]byte) { delete(m, "two.cab") }},
		{"wrong set", "set ID", func(m map[string][]byte) { binary.LittleEndian.PutUint16(m["two.cab"][32:], 124) }},
		{"wrong sequence", "sequence", func(m map[string][]byte) { binary.LittleEndian.PutUint16(m["two.cab"][34:], 4) }},
		{"cycle", "cycle", func(m map[string][]byte) {
			m["one.cab"] = companionFixture(0, "", "one.cab", cabFolderContinuedToNext, "abc")
		}},
		{"reciprocal", "link back", func(m map[string][]byte) {
			m["two.cab"] = companionFixture(1, "wrong.cab", "three.cab", cabFolderContinuedBoth, "def")
		}},
		{"missing link", "missing previous", func(m map[string][]byte) {
			m["two.cab"] = companionFixture(1, "", "three.cab", cabFolderContinuedBoth, "def")
		}},
		{"non cabinet", "signature", func(m map[string][]byte) { copy(m["two.cab"], "NOPE") }},
		{"traversal", "invalid companion path", func(m map[string][]byte) {
			m["one.cab"] = companionFixture(0, "", "../two.cab", cabFolderContinuedToNext, "abc")
		}},
		{"absolute", "invalid companion path", func(m map[string][]byte) {
			m["one.cab"] = companionFixture(0, "", "/two.cab", cabFolderContinuedToNext, "abc")
		}},
		{"drive", "invalid companion path", func(m map[string][]byte) {
			m["one.cab"] = companionFixture(0, "", "C:\\two.cab", cabFolderContinuedToNext, "abc")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			files := companionFiles()
			test.change(files)
			_, err := auto.Identify(&starfile.Bytes{Data: files["one.cab"]}, companionOptions(t, files, "one.cab"))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want %s", err, test.want)
			}
		})
	}
	files := companionFiles()
	if _, err := auto.Identify(&starfile.Bytes{Data: files["one.cab"]}, auto.Options{}); err == nil || !strings.Contains(err.Error(), "source tree") {
		t.Fatalf("missing source error = %v", err)
	}
	options := companionOptions(t, files, "one.cab")
	options.MaxEntries = 2
	if _, err := auto.Identify(&starfile.Bytes{Data: files["one.cab"]}, options); !errors.Is(err, auto.ErrLimit) {
		t.Fatalf("budget error = %v", err)
	}
}

func TestAutoCABDoesNotFollowCompanionLinks(t *testing.T) {
	files := companionFiles()
	tree := auto.ViewFunc(func() ([]auto.Entry, error) {
		return []auto.Entry{{Name: "two.cab", Kind: "symlink", Reader: &starfile.Bytes{Data: files["two.cab"]}}}, nil
	})
	_, err := auto.Identify(&starfile.Bytes{Data: files["one.cab"]}, auto.Options{Source: &auto.SourceContext{Tree: tree, Path: "one.cab"}})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlink companion error = %v", err)
	}
}

func TestOpenSetRejectsEmptyAndSequenceWrap(t *testing.T) {
	for _, archives := range [][]*Archive{nil, {nil}, {{cabinet: 65535}, {cabinet: 0}}} {
		if _, err := OpenSetWithCache(archives, false, nil, 1); err == nil {
			t.Fatal("invalid set accepted")
		}
	}
}
