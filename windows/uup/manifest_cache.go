package uup

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"reflect"
	"sort"

	"github.com/tinyrange/trex/internal/xmltoken"
	"github.com/tinyrange/trex/storage"
)

// Change the schema when the layout or the interpretation of a manifest changes.
const assemblyCacheSchema = "windows.cbs.assembly/v1"
const maximumAssemblyRecord = 64 << 20

// ManifestCache retains typed parser results only. Every consumer still binds
// an exact package or component identity and evaluates its own policy.
type ManifestCache struct {
	ctx     context.Context
	records storage.DerivedCache
}

func NewManifestCache(ctx context.Context, records storage.DerivedCache) *ManifestCache {
	if records == nil {
		return nil
	}
	return &ManifestCache{ctx: ctx, records: records}
}

func (c *ManifestCache) Parse(source string) (*AssemblyManifest, error) {
	parse := func() (*AssemblyManifest, error) {
		return parseAssemblyManifest(xml.NewTokenDecoder(xmltoken.NewString(source, false)))
	}
	if c == nil {
		return parse()
	}
	var parsed *AssemblyManifest
	var parseErr error
	key := storage.DerivedKey(assemblyCacheSchema, sha256.Sum256([]byte(source)))
	record, err := c.records.GetOrBuild(c.ctx, key, maximumAssemblyRecord, func() ([]byte, error) {
		parsed, parseErr = parse()
		if parseErr != nil {
			return nil, parseErr
		}
		return packAssemblyManifest(parsed)
	})
	if parseErr != nil || parsed != nil {
		// Source validation still owns the result if the optional store cannot
		// publish it. No cached record was used to interpret these bytes.
		return parsed, parseErr
	}
	if err == nil {
		if cached, err := unpackAssemblyManifest(record); err == nil {
			return cached, nil
		}
	}
	return parse()
}

// A fixed field order is implicit in the schema. Numbers and table references
// use varints. Structs add no tags, while a shared string table stores repeated
// identities, XML namespaces, names and values once per record.
type assemblyEncoder struct {
	index map[string]uint64
	table []byte
	body  []byte
}

func packAssemblyManifest(manifest *AssemblyManifest) ([]byte, error) {
	return packCBSRecord(reflect.ValueOf(manifest).Elem())
}

func packCBSRecord(value reflect.Value) ([]byte, error) {
	e := assemblyEncoder{index: make(map[string]uint64)}
	if err := e.encode(value); err != nil {
		return nil, err
	}
	header := binary.AppendUvarint(nil, uint64(len(e.table)))
	record := make([]byte, 0, len(header)+len(e.table)+len(e.body))
	record = append(record, header...)
	record = append(record, e.table...)
	return append(record, e.body...), nil
}

func (e *assemblyEncoder) encode(v reflect.Value) error {
	switch v.Kind() {
	case reflect.String:
		text := v.String()
		if text == "" {
			e.body = binary.AppendUvarint(e.body, 0)
			break
		}
		id, found := e.index[text]
		if !found {
			id = uint64(len(e.index) + 1)
			e.index[text] = id
			e.table = binary.AppendUvarint(e.table, uint64(len(text)))
			e.table = append(e.table, text...)
		}
		e.body = binary.AppendUvarint(e.body, id)
	case reflect.Int, reflect.Int64:
		e.body = binary.AppendVarint(e.body, v.Int())
	case reflect.Uint32, reflect.Uint64:
		e.body = binary.AppendUvarint(e.body, v.Uint())
	case reflect.Array:
		if v.Type().Elem().Kind() != reflect.Uint8 {
			return fmt.Errorf("unsupported assembly cache field %v", v.Type())
		}
		for i := 0; i < v.Len(); i++ {
			e.body = append(e.body, byte(v.Index(i).Uint()))
		}
	case reflect.Bool:
		if v.Bool() {
			e.body = append(e.body, 1)
		} else {
			e.body = append(e.body, 0)
		}
	case reflect.Pointer:
		if v.IsNil() {
			e.body = append(e.body, 0)
		} else {
			e.body = append(e.body, 1)
			return e.encode(v.Elem())
		}
	case reflect.Slice:
		if v.IsNil() {
			e.body = append(e.body, 0)
			break
		}
		e.body = binary.AppendUvarint(e.body, uint64(v.Len())+1)
		if v.Type().Elem().Kind() == reflect.Uint8 {
			e.body = append(e.body, v.Bytes()...)
			return nil
		}
		for i := 0; i < v.Len(); i++ {
			if err := e.encode(v.Index(i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("unsupported assembly cache field %v", v.Type())
		}
		if v.IsNil() {
			e.body = append(e.body, 0)
			break
		}
		keys := v.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		e.body = binary.AppendUvarint(e.body, uint64(len(keys))+1)
		for _, key := range keys {
			if err := e.encode(key); err != nil {
				return err
			}
			if err := e.encode(v.MapIndex(key)); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if err := e.encode(v.Field(i)); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported assembly cache field %v", v.Type())
	}
	return nil
}

type assemblyDecoder struct {
	body    []byte
	strings []string
	budget  uint64
}

func unpackAssemblyManifest(record []byte) (*AssemblyManifest, error) {
	var manifest AssemblyManifest
	if err := unpackCBSRecord(record, reflect.ValueOf(&manifest).Elem()); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func unpackCBSRecord(record []byte, value reflect.Value) error {
	badRecord := fmt.Errorf("invalid CBS cache record")
	size, n := binary.Uvarint(record)
	if n <= 0 || len(record) > maximumAssemblyRecord || size > uint64(len(record)-n) {
		return badRecord
	}
	table := record[n : n+int(size)]
	text := string(table)
	d := assemblyDecoder{
		body: record[n+int(size):], strings: []string{""}, budget: 128 << 20,
	}
	for offset := 0; offset < len(table); {
		length, consumed := binary.Uvarint(table[offset:])
		if consumed <= 0 || length == 0 || length > uint64(len(table)-offset-consumed) || len(d.strings) >= maximumManifestElements {
			return badRecord
		}
		offset += consumed
		d.strings = append(d.strings, text[offset:offset+int(length)])
		offset += int(length)
	}
	if !d.decode(value, 0) || len(d.body) != 0 {
		return badRecord
	}
	return nil
}

func (d *assemblyDecoder) number() (uint64, bool) {
	number, n := binary.Uvarint(d.body)
	if n <= 0 {
		return 0, false
	}
	d.body = d.body[n:]
	return number, true
}

func (d *assemblyDecoder) decode(v reflect.Value, depth int) bool {
	if depth > maximumManifestDepth*3 {
		return false
	}
	switch v.Kind() {
	case reflect.String:
		id, ok := d.number()
		if !ok || id >= uint64(len(d.strings)) {
			return false
		}
		v.SetString(d.strings[id])
	case reflect.Int, reflect.Int64:
		number, n := binary.Varint(d.body)
		if n <= 0 || v.OverflowInt(number) {
			return false
		}
		d.body = d.body[n:]
		v.SetInt(number)
	case reflect.Uint32, reflect.Uint64:
		number, ok := d.number()
		if !ok || v.OverflowUint(number) {
			return false
		}
		v.SetUint(number)
	case reflect.Array:
		if v.Type().Elem().Kind() != reflect.Uint8 || len(d.body) < v.Len() {
			return false
		}
		for i := 0; i < v.Len(); i++ {
			v.Index(i).SetUint(uint64(d.body[i]))
		}
		d.body = d.body[v.Len():]
	case reflect.Bool, reflect.Pointer:
		if len(d.body) == 0 || d.body[0] > 1 {
			return false
		}
		present := d.body[0] != 0
		d.body = d.body[1:]
		if v.Kind() == reflect.Bool {
			v.SetBool(present)
		} else if present {
			size := uint64(v.Type().Elem().Size())
			if size > d.budget {
				return false
			}
			d.budget -= size
			v.Set(reflect.New(v.Type().Elem()))
			return d.decode(v.Elem(), depth+1)
		}
	case reflect.Slice:
		count, ok := d.number()
		if !ok {
			return false
		}
		if count == 0 {
			return true
		}
		count--
		size := uint64(v.Type().Elem().Size())
		if size == 0 || count > uint64(len(d.body)) || count > d.budget/size {
			return false
		}
		d.budget -= size * count
		if v.Type().Elem().Kind() == reflect.Uint8 {
			v.SetBytes(d.body[:int(count):int(count)])
			d.body = d.body[int(count):]
			return true
		}
		v.Set(reflect.MakeSlice(v.Type(), int(count), int(count)))
		for i := 0; i < v.Len(); i++ {
			if !d.decode(v.Index(i), depth+1) {
				return false
			}
		}
	case reflect.Map:
		count, ok := d.number()
		if !ok || v.Type().Key().Kind() != reflect.String {
			return false
		}
		if count == 0 {
			return true
		}
		count--
		size := uint64(v.Type().Key().Size() + v.Type().Elem().Size() + 32)
		if count > uint64(len(d.body))/2 || count > d.budget/size {
			return false
		}
		d.budget -= size * count
		v.Set(reflect.MakeMapWithSize(v.Type(), int(count)))
		key, value := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		for i := uint64(0); i < count; i++ {
			value.SetZero()
			if !d.decode(key, depth+1) || v.MapIndex(key).IsValid() || !d.decode(value, depth+1) {
				return false
			}
			v.SetMapIndex(key, value)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !d.decode(v.Field(i), depth+1) {
				return false
			}
		}
	default:
		return false
	}
	return true
}
