package ckd

import (
	"bytes"
	"fmt"
	"github.com/tinyrange/trex/auto"
)

// volumeVVRs uses live CI record descriptors, never signature-carves free space.
// Raw records are retained so an unrelated unsupported component need not
// prevent a supported component from being resolved.
func (v *Volume) volumeVVRs(limit int) (map[string][]byte, error) {
	var ds *Dataset
	for _, candidate := range v.Datasets {
		if candidate.Name == "SYS1.VVDS.V"+v.Serial {
			ds = candidate
			break
		}
	}
	if ds == nil {
		return nil, fmt.Errorf("VSAM: volume has no VVDS")
	}
	pages, err := ds.OpenPages(4096)
	if err != nil {
		return nil, err
	}
	if limit <= 0 || pages.Count() > 1000000 {
		return nil, fmt.Errorf("VSAM: VVDS scan limit")
	}
	first, err := pages.Page(0)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first[4:8], []byte{0xe5, 0xe5, 0xc3, 0xd9}) {
		return nil, fmt.Errorf("VSAM: invalid VVDS control record")
	}
	out := map[string][]byte{}
	for i := uint64(1); i < pages.Count(); i++ {
		b, err := pages.Page(i)
		if err != nil {
			return nil, err
		}
		ci, err := ParseControlInterval(b)
		if err != nil {
			return nil, err
		}
		for _, record := range ci.Records {
			if len(record) < 12 || int(be.Uint16(record)) != len(record) {
				return nil, fmt.Errorf("VVDS: invalid record length")
			}
			if record[4] != 0xe9 {
				continue
			} // NVR and extension records are not primary VVRs.
			n := int(record[10])
			end := int(be.Uint16(record[2:])) + 2
			if n < 2 || n > 45 || 10+n >= end || end > len(record) {
				return nil, fmt.Errorf("VVDS: invalid primary key")
			}
			name := Identifier(record[11 : 10+n])
			if _, exists := out[name]; exists {
				return nil, fmt.Errorf("VVDS: duplicate primary record for %s", name)
			}
			if len(out) >= limit {
				return nil, fmt.Errorf("VVDS: record limit")
			}
			out[name] = bytes.Clone(record)
		}
	}
	return out, nil
}

// VSAMRecords resolves the local primary VVR and an index component by cluster
// identity, not filename suffixes. The component cell supplies the root RBA;
// unused and stale index CIs are never used to guess the highest-level root.
// Linear, multivolume and extended-RBA layouts are not inferred. For an AIX,
// this returns reference records; AlternateRecords resolves base-record access.
func (ds *Dataset) VSAMRecords(limit int) ([]VSAMRecord, *VVR, error) {
	return ds.vsamRecords(limit, 64<<20)
}

func (ds *Dataset) vsamRecords(limit int, maximumBytes uint64) ([]VSAMRecord, *VVR, error) {
	if ds.Organization != 8 || ds.VolumeSequence != 1 {
		return nil, nil, fmt.Errorf("VSAM: not a single-volume component")
	}
	volume, err := ds.Disk.ReadVTOC(1000000)
	if err != nil {
		return nil, nil, err
	}
	primary, err := volume.volumeVVRs(1000000)
	if err != nil {
		return nil, nil, err
	}
	b, ok := primary[ds.Name]
	if !ok {
		return nil, nil, fmt.Errorf("VSAM: component missing from VVDS")
	}
	metadata, err := ParseVVR(b)
	if err != nil {
		return nil, nil, err
	}
	if metadata.Index {
		return nil, nil, fmt.Errorf("VSAM: index component is not a data record stream")
	}
	source, err := ds.OpenVSAMPages(metadata.CIBytes)
	if err != nil {
		return nil, nil, err
	}
	if uint64(source.Size()) != metadata.AllocatedBytes || source.PerTrack != uint32(metadata.CIsPerTrack) {
		return nil, nil, fmt.Errorf("VSAM: VTOC and VVR allocation disagree")
	}
	org, err := metadata.recordOrganization()
	if err != nil {
		return nil, nil, err
	}
	o := VSAMReadOptions{Organization: org, CIBytes: metadata.CIBytes, UsedBytes: metadata.UsedBytes, CIsPerCA: uint32(metadata.CIsPerTrack) * uint32(metadata.TracksPerCA), KeyOffset: uint32(metadata.KeyOffset), KeyLength: uint32(metadata.KeyLength), MaxRecords: limit, MaxRecordBytes: 16 << 20, MaxIntervals: 1000000, MaxBytes: maximumBytes}
	if org == VSAMKSDS {
		var im *VVR
		for name, record := range primary {
			if name == ds.Name {
				continue
			}
			candidate, e := ParseVVR(record)
			if e != nil {
				continue
			}
			if candidate.Index && candidate.Cluster == metadata.Cluster {
				if im != nil {
					return nil, nil, fmt.Errorf("VSAM: ambiguous local index relationship")
				}
				im = candidate
			}
		}
		if im == nil {
			return nil, nil, fmt.Errorf("VSAM: related index is absent from this volume")
		}
		var ids *Dataset
		for _, candidate := range volume.Datasets {
			if candidate.Name == im.Name {
				ids = candidate
				break
			}
		}
		if ids == nil {
			return nil, nil, fmt.Errorf("VSAM: related index has no VTOC allocation")
		}
		ix, e := ids.OpenVSAMPages(im.CIBytes)
		if e != nil {
			return nil, nil, e
		}
		if uint64(ix.Size()) != im.AllocatedBytes || ix.PerTrack != uint32(im.CIsPerTrack) || ids.VolumeSequence != 1 || im.KeyLength != metadata.KeyLength {
			return nil, nil, fmt.Errorf("VSAM: index allocation or key geometry mismatch")
		}
		o.Order, e = VSAMIndexOrder(ix, im.CIBytes, im.UsedBytes, im.IndexRootRBA, metadata.CIBytes, metadata.UsedBytes, int(metadata.KeyLength), 1000000)
		if e != nil {
			return nil, nil, e
		}
	}
	records, err := ReadVSAMRecords(source, o)
	return records, metadata, err
}

func (ds *Dataset) vsamView(limit int, maximumBytes uint64) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		records, metadata, err := ds.vsamRecords(limit, maximumBytes)
		if err != nil {
			return nil, err
		}
		entries := []auto.Entry{file("$component.json", jsonFile(metadata))}
		for _, r := range records {
			entry := file(fmt.Sprintf("%012d.bin", r.Number), raw(r.Data))
			entry.Attributes = map[string]any{"rba": r.RBA, "record_number": r.Number}
			entries = append(entries, entry)
		}
		return entries, nil
	})
}
