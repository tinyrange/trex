package ckd

import (
	"bytes"
	"fmt"

	"github.com/tinyrange/trex/auto"
)

// AlternateIndexRecord is the observed nonunique KSDS alternate-index record.
// Keys are bytes, not text. ESDS/extended-address references need other layouts.
type AlternateIndexRecord struct {
	Key         []byte
	PrimaryKeys [][]byte
}

func ParseAlternateIndexRecord(b []byte) (*AlternateIndexRecord, error) {
	if len(b) < 5 || b[0] != 1 || b[1] == 0 || b[4] == 0 {
		return nil, fmt.Errorf("VSAM AIX: unsupported reference header")
	}
	width, count, keyLength := int(b[1]), int(be.Uint16(b[2:])), int(b[4])
	if count == 0 || 5+keyLength+width*count != len(b) {
		return nil, fmt.Errorf("VSAM AIX: inconsistent reference count")
	}
	out := &AlternateIndexRecord{Key: bytes.Clone(b[5 : 5+keyLength])}
	seen := map[string]bool{}
	for pos := 5 + keyLength; pos < len(b); pos += width {
		key := b[pos : pos+width]
		if seen[string(key)] {
			return nil, fmt.Errorf("VSAM AIX: duplicate primary key")
		}
		seen[string(key)] = true
		out.PrimaryKeys = append(out.PrimaryKeys, bytes.Clone(key))
	}
	return out, nil
}

// AlternateRecords resolves a local KSDS AIX through its catalog's true-name
// relationship, then dereferences each primary key in alternate-key order.
// It never mistakes AIX reference payloads for the user's base records.
func (ds *Dataset) AlternateRecords(limit int) ([]VSAMRecord, error) {
	return ds.alternateRecords(limit, 64<<20)
}

func (ds *Dataset) alternateRecords(limit int, maximumBytes uint64) ([]VSAMRecord, error) {
	alternate, metadata, err := ds.vsamRecords(limit, maximumBytes)
	if err != nil {
		return nil, err
	}
	if metadata.KeyOffset != 5 {
		return nil, fmt.Errorf("VSAM AIX: incompatible key position")
	}
	volume, err := ds.Disk.ReadVTOC(1000000)
	if err != nil {
		return nil, err
	}
	var catalog *Dataset
	for _, candidate := range volume.Datasets {
		if candidate.Name == metadata.Catalog {
			catalog = candidate
		}
	}
	if catalog == nil || catalog.Name == ds.Name {
		return nil, fmt.Errorf("VSAM AIX: catalog is not local")
	}
	catalogRecords, _, err := catalog.VSAMRecords(100000)
	if err != nil {
		return nil, err
	}
	catalogByName := map[string]*CatalogRecord{}
	for _, r := range catalogRecords {
		c, err := ParseCatalogRecord(r.Data)
		if err != nil {
			return nil, err
		}
		if _, exists := catalogByName[c.Name]; exists {
			return nil, fmt.Errorf("VSAM AIX: duplicate catalog name")
		}
		catalogByName[c.Name] = c
	}
	entry := catalogByName[metadata.Cluster]
	if entry == nil || entry.Kind != 0xe3 || len(entry.References) != 1 {
		return nil, fmt.Errorf("VSAM AIX: missing base-cluster relationship")
	}
	baseEntry := catalogByName[entry.References[0]]
	if baseEntry == nil || baseEntry.Kind != 0xc3 {
		return nil, fmt.Errorf("VSAM AIX: missing base-cluster record")
	}
	// In the observed C record, the base D/I pair precedes the G AIX group.
	baseName := ""
	for _, cell := range baseEntry.Cells {
		if cell.Kind == 0xc7 {
			break
		}
		if cell.Kind == 0xc4 {
			if baseName != "" {
				return nil, fmt.Errorf("VSAM AIX: ambiguous base data component")
			}
			baseName = cell.Name
		}
	}
	var base *Dataset
	for _, candidate := range volume.Datasets {
		if candidate.Name == baseName {
			base = candidate
		}
	}
	if base == nil || base.Name == ds.Name {
		return nil, fmt.Errorf("VSAM AIX: base data component is not local")
	}
	primary, baseMetadata, err := base.vsamRecords(limit, maximumBytes)
	if err != nil {
		return nil, err
	}
	if baseMetadata.Cluster != baseEntry.Name || baseMetadata.KeyLength == 0 || baseMetadata.DataFlags&0x80 == 0 {
		return nil, fmt.Errorf("VSAM AIX: base is not the resolved KSDS")
	}
	return ResolveAlternateRecords(alternate, primary, metadata.KeyLength, baseMetadata.KeyOffset, baseMetadata.KeyLength, limit, maximumBytes)
}

// ResolveAlternateRecords verifies every reference against an independently
// read base stream. Missing, duplicate, mis-sized and out-of-budget references
// fail instead of silently omitting records. Returned payloads share immutable
// bytes with primary; the caller retains ownership of the input snapshots.
func ResolveAlternateRecords(alternate, primary []VSAMRecord, alternateLength, primaryOffset, primaryLength uint16, maxRecords int, maxBytes uint64) ([]VSAMRecord, error) {
	if primaryLength == 0 || alternateLength == 0 || maxRecords <= 0 || maxBytes == 0 {
		return nil, fmt.Errorf("VSAM AIX: invalid limits or key geometry")
	}
	keys := map[string]VSAMRecord{}
	for _, r := range primary {
		if int(primaryOffset)+int(primaryLength) > len(r.Data) {
			return nil, fmt.Errorf("VSAM AIX: primary key outside record")
		}
		key := string(r.Data[primaryOffset : int(primaryOffset)+int(primaryLength)])
		if _, exists := keys[key]; exists {
			return nil, fmt.Errorf("VSAM AIX: duplicate base key")
		}
		keys[key] = r
	}
	var out []VSAMRecord
	var previous []byte
	var total uint64
	referenced := map[string]bool{}
	for _, r := range alternate {
		a, err := ParseAlternateIndexRecord(r.Data)
		if err != nil {
			return nil, err
		}
		if len(a.Key) != int(alternateLength) || (previous != nil && bytes.Compare(previous, a.Key) >= 0) {
			return nil, fmt.Errorf("VSAM AIX: alternate key geometry or order")
		}
		previous = a.Key
		for _, key := range a.PrimaryKeys {
			p, ok := keys[string(key)]
			if !ok || len(key) != int(primaryLength) || referenced[string(key)] {
				return nil, fmt.Errorf("VSAM AIX: missing, repeated or mis-sized base reference")
			}
			if len(out) >= maxRecords || uint64(len(p.Data)) > maxBytes-total {
				return nil, fmt.Errorf("VSAM AIX: output budget exceeded")
			}
			referenced[string(key)] = true
			total += uint64(len(p.Data))
			out = append(out, VSAMRecord{RBA: p.RBA, Number: uint64(len(out)) + 1, Data: p.Data})
		}
	}
	return out, nil
}

func (ds *Dataset) alternateView(limit int, maximumBytes uint64) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		records, err := ds.alternateRecords(limit, maximumBytes)
		if err != nil {
			return nil, err
		}
		var out []auto.Entry
		for _, r := range records {
			entry := file(fmt.Sprintf("%012d.bin", r.Number), raw(r.Data))
			entry.Attributes = map[string]any{"base_rba": r.RBA, "alternate_sequence": r.Number}
			out = append(out, entry)
		}
		return out, nil
	})
}
