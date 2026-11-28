// Package nixstore converts a Nix closure registration to its SQLite store database.
package nixstore

import (
	"bufio"
	"cmp"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/tinyrange/trex/database/sqlite"
	"github.com/tinyrange/trex/storage"
)

type registration struct {
	path, hash, deriver string
	size                int64
	references          []string
}

const nix32Alphabet = "0123456789abcdfghijklmnpqrsvwxyz"

func storeHash(text string) (string, bool) {
	text = strings.TrimPrefix(text, "sha256:")
	if len(text) == 64 {
		digest, err := hex.DecodeString(text)
		return "sha256:" + hex.EncodeToString(digest), err == nil
	}
	if len(text) != 52 {
		return "", false
	}
	var digest [32]byte
	// Nix32 prints the most significant five-bit group first, with the
	// groups counted from the least significant bit of the first byte.
	for i := range len(text) {
		value := strings.IndexByte(nix32Alphabet, text[len(text)-1-i])
		bit := 5 * i
		byteIndex, shift := bit/8, bit%8
		if value < 0 || byteIndex == len(digest)-1 && value<<shift > 255 {
			return "", false
		}
		digest[byteIndex] |= byte(value << shift)
		if shift > 3 && byteIndex+1 < len(digest) {
			digest[byteIndex+1] |= byte(value >> (8 - shift))
		}
	}
	return "sha256:" + hex.EncodeToString(digest[:]), true
}

func readRegistration(source storage.Reader) ([]registration, error) {
	if source == nil || source.Size() <= 0 || source.Size() > 32<<20 {
		return nil, fmt.Errorf("Nix store: invalid registration size")
	}
	input := bufio.NewScanner(io.NewSectionReader(source, 0, source.Size()))
	input.Buffer(make([]byte, 4096), 65536)
	next := func() (string, error) {
		if input.Scan() {
			return input.Text(), nil
		}
		if err := input.Err(); err != nil {
			return "", err
		}
		return "", io.ErrUnexpectedEOF
	}
	var paths []registration
	for input.Scan() {
		path := input.Text()
		hash, err := next()
		if err != nil {
			return nil, err
		}
		sizeText, err := next()
		if err != nil {
			return nil, err
		}
		deriver, err := next()
		if err != nil {
			return nil, err
		}
		countText, err := next()
		if err != nil {
			return nil, err
		}
		digest, hashOK := storeHash(hash)
		size, sizeErr := strconv.ParseInt(sizeText, 10, 64)
		count, countErr := strconv.Atoi(countText)
		if !validPath(path) || !hashOK || sizeErr != nil || size < 0 || countErr != nil || count < 0 || count > 32768 || (deriver != "" && !validPath(deriver)) {
			return nil, fmt.Errorf("Nix store: malformed registration for %q", path)
		}
		entry := registration{path: path, hash: digest, size: size, deriver: deriver}
		for range count {
			ref, err := next()
			if err != nil {
				return nil, err
			}
			if !validPath(ref) {
				return nil, fmt.Errorf("Nix store: malformed reference %q", ref)
			}
			entry.references = append(entry.references, ref)
		}
		paths = append(paths, entry)
	}
	if err := input.Err(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("Nix store: registration has no paths")
	}
	return paths, nil
}

func validPath(path string) bool {
	name, found := strings.CutPrefix(path, "/nix/store/")
	if !found || len(name) < 34 || len(name) > 244 || name[32] != '-' {
		return false
	}
	for _, c := range name[:32] {
		if !strings.ContainsRune(nix32Alphabet, c) {
			return false
		}
	}
	for _, c := range name[33:] {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("+-._?=", c)) {
			return false
		}
	}
	return true
}

// Build produces the Nix schema-10 store database from a complete original
// closure manifest. The caller must put the registered paths into the image.
func Build(source storage.Reader) (storage.Reader, error) {
	paths, err := readRegistration(source)
	if err != nil {
		return nil, err
	}
	return build(paths)
}

// BuildClosure produces the store database and installed path list for the
// transitive references of the selected store paths.
func BuildClosure(source storage.Reader, roots []string) (storage.Reader, []string, error) {
	records, err := readRegistration(source)
	if err != nil {
		return nil, nil, err
	}
	if len(roots) == 0 {
		return nil, nil, fmt.Errorf("Nix store: closure needs at least one root")
	}
	byPath := make(map[string]registration, len(records))
	for _, record := range records {
		if _, duplicate := byPath[record.path]; duplicate {
			return nil, nil, fmt.Errorf("Nix store: duplicate path %s", record.path)
		}
		byPath[record.path] = record
	}
	var closure []registration
	var selected []string
	seen := make(map[string]bool)
	pending := slices.Clone(roots)
	for len(pending) > 0 {
		path := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if seen[path] {
			continue
		}
		record, ok := byPath[path]
		if !ok {
			return nil, nil, fmt.Errorf("Nix store: closure path %s is missing", path)
		}
		seen[path] = true
		closure = append(closure, record)
		selected = append(selected, path)
		pending = append(pending, record.references...)
	}
	slices.Sort(selected)
	db, err := build(closure)
	if err != nil {
		return nil, nil, err
	}
	return db, selected, nil
}

func build(paths []registration) (storage.Reader, error) {
	slices.SortFunc(paths, func(a, b registration) int { return strings.Compare(a.path, b.path) })
	ids := make(map[string]int64, len(paths))
	var data, pathIndex, refs, refsIndex, refReverse []sqlite.Row
	for i, p := range paths {
		if ids[p.path] != 0 {
			return nil, fmt.Errorf("Nix store: duplicate path %s", p.path)
		}
		id := int64(i + 1)
		ids[p.path] = id
		var deriver any
		if p.deriver != "" {
			deriver = p.deriver
		}
		data = append(data, sqlite.Row{RowID: &id, Values: []any{nil, p.path, p.hash, int64(0), deriver, p.size, nil, nil, nil}})
		pathIndex = append(pathIndex, sqlite.Row{Values: []any{p.path, id}})
	}
	for _, p := range paths {
		from := ids[p.path]
		references := make([]int64, 0, len(p.references))
		for _, ref := range p.references {
			id := ids[ref]
			if id == 0 {
				return nil, fmt.Errorf("Nix store: %s references missing %s", p.path, ref)
			}
			references = append(references, id)
		}
		slices.Sort(references)
		for i, to := range references {
			if i != 0 && references[i-1] == to {
				return nil, fmt.Errorf("Nix store: duplicate reference from %s", p.path)
			}
			row := int64(len(refs) + 1)
			refs = append(refs, sqlite.Row{RowID: &row, Values: []any{from, to}})
			refsIndex = append(refsIndex, sqlite.Row{Values: []any{from, to, row}})
			refReverse = append(refReverse, sqlite.Row{Values: []any{to, row}})
		}
	}
	slices.SortStableFunc(refReverse, func(a, b sqlite.Row) int {
		return cmp.Compare(a.Values[0].(int64), b.Values[0].(int64))
	})
	sequenceID := int64(1)
	return sqlite.Build([]sqlite.Object{
		{Type: "table", Name: "ValidPaths", SQL: "CREATE TABLE ValidPaths (id integer primary key autoincrement not null, path text unique not null, hash text not null, registrationTime integer not null, deriver text, narSize integer, ultimate integer, sigs text, ca text)", Rows: data},
		{Type: "index", Name: "sqlite_autoindex_ValidPaths_1", TableName: "ValidPaths", Rows: pathIndex},
		{Type: "table", Name: "sqlite_sequence", SQL: "CREATE TABLE sqlite_sequence(name,seq)", Rows: []sqlite.Row{{RowID: &sequenceID, Values: []any{"ValidPaths", int64(len(paths))}}}},
		{Type: "table", Name: "Refs", SQL: "CREATE TABLE Refs (referrer integer not null, reference integer not null, primary key (referrer, reference), foreign key (referrer) references ValidPaths(id) on delete cascade, foreign key (reference) references ValidPaths(id) on delete restrict)", Rows: refs},
		{Type: "index", Name: "sqlite_autoindex_Refs_1", TableName: "Refs", Rows: refsIndex},
		{Type: "index", Name: "IndexReference", TableName: "Refs", SQL: "CREATE INDEX IndexReference on Refs(reference)", Rows: refReverse},
		{Type: "trigger", Name: "DeleteSelfRefs", TableName: "ValidPaths", SQL: "CREATE TRIGGER DeleteSelfRefs before delete on ValidPaths begin delete from Refs where referrer = old.id and reference = old.id; end"},
		{Type: "table", Name: "DerivationOutputs", SQL: "CREATE TABLE DerivationOutputs (drv integer not null, id text not null, path text not null, primary key (drv, id), foreign key (drv) references ValidPaths(id) on delete cascade)"},
		{Type: "index", Name: "sqlite_autoindex_DerivationOutputs_1", TableName: "DerivationOutputs"},
		{Type: "index", Name: "IndexDerivationOutputs", TableName: "DerivationOutputs", SQL: "CREATE INDEX IndexDerivationOutputs on DerivationOutputs(path)"},
	}, sqlite.BuildOptions{})
}
