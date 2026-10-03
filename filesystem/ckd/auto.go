package ckd

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/tinyrange/trex/auto"
	"github.com/tinyrange/trex/storage"
)

func init() {
	auto.Register("ckd", 20, func(p []byte, r storage.Reader, o auto.Options) (auto.View, error) {
		if len(p) < 8 || string(p[:8]) != "CKD_P370" {
			return nil, auto.ErrNoMatch
		}
		d, e := Open(r)
		if e != nil {
			return nil, e
		}
		return d.view(o.MaxEntries, uint64(o.MaxExpandedBytes)), nil
	})
}

type byteFile struct{ *bytes.Reader }

func raw(b []byte) storage.Reader { return byteFile{bytes.NewReader(b)} }
func jsonFile(v any) storage.Reader {
	b, _ := json.MarshalIndent(v, "", "  ")
	return raw(append(b, '\n'))
}
func file(name string, r storage.Reader) auto.Entry {
	return auto.Entry{Name: name, Kind: "file", Reader: r}
}
func dir(name string, v auto.View) auto.Entry {
	return auto.Entry{Name: name, Kind: "directory", View: v}
}

// View is the same lazy tree used by auto(), the archive browser and web UI.
// Entire-volume geometry is resolved only when raw tracks are browsed; normal
// dataset enumeration reads the VTOC rather than decompressing the entire disk.
func (d *Disk) View(limit int) auto.View { return d.view(limit, 64<<20) }

func (d *Disk) view(limit int, maximumBytes uint64) auto.View {
	if maximumBytes == 0 {
		maximumBytes = 64 << 20
	}
	if limit <= 0 {
		limit = 100000
	}
	return &auto.DescribedView{Format: "ckd", Attributes: map[string]any{"heads": d.Heads, "track_bytes": d.TrackSize, "device": d.Device}, View: auto.ViewFunc(func() ([]auto.Entry, error) {
		return []auto.Entry{
			dir("datasets", auto.ViewFunc(func() ([]auto.Entry, error) {
				// Reserved free DSCBs are not browser entries. Large VTOCs
				// need a separate, bounded physical metadata budget.
				v, e := d.ReadVTOC(1000000)
				if e != nil {
					return nil, e
				}
				if len(v.Datasets) > limit {
					return nil, fmt.Errorf("%w: ckd datasets", auto.ErrLimit)
				}
				entries := []auto.Entry{file("$volume.json", jsonFile(map[string]any{"serial": v.Serial, "vtoc": v.VTOC, "datasets": len(v.Datasets)}))}
				for _, ds := range v.Datasets {
					ds := ds
					entries = append(entries, dir(ds.Name, ds.view(limit, maximumBytes)))
				}
				return entries, nil
			})),
			dir("tracks", auto.ViewFunc(func() ([]auto.Entry, error) {
				size := d.Source.Size()
				if size < 512 || ((size-512)%int64(d.TrackSize*d.Heads)) != 0 {
					return nil, fmt.Errorf("ckd: invalid complete image size %d", size)
				}
				cylinders := (size - 512) / int64(d.TrackSize*d.Heads)
				if cylinders > 65536 || cylinders > int64(limit) {
					return nil, fmt.Errorf("ckd: cylinder limit exceeded")
				}
				out := make([]auto.Entry, 0, cylinders)
				for c := uint32(0); int64(c) < cylinders; c++ {
					c := c
					out = append(out, dir(fmt.Sprintf("%05d", c), auto.ViewFunc(func() ([]auto.Entry, error) {
						entries := make([]auto.Entry, d.Heads)
						for h := uint32(0); h < d.Heads; h++ {
							t := c*d.Heads + h
							entries[h] = dir(fmt.Sprintf("%03d", h), d.trackView(t))
						}
						return entries, nil
					})))
				}
				return out, nil
			})),
			file("header.bin", &Content{source: d.Source, spans: []span{{0, 512, 0}}, size: 512}),
		}, nil
	})}
}
func (d *Disk) trackView(t uint32) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		rs, e := d.Track(t)
		if e != nil {
			return nil, e
		}
		out := []auto.Entry{file("track.bin", &Content{source: d.Source, spans: []span{{512 + int64(t)*int64(d.TrackSize), int64(d.TrackSize), 0}}, size: int64(d.TrackSize)})}
		for i, r := range rs {
			attrs := map[string]any{"count_cylinder": r.Cylinder, "count_head": r.Head, "record": r.Number, "offset": r.Offset}
			data := file(fmt.Sprintf("%03d-r%03d.data", i, r.Number), raw(r.Data))
			data.Attributes = attrs
			out = append(out, data, file(fmt.Sprintf("%03d-r%03d.key", i, r.Number), raw(r.Key)))
		}
		return out, nil
	})
}
func (ds *Dataset) view(limit int, maximumBytes uint64) auto.View {
	return auto.ViewFunc(func() ([]auto.Entry, error) {
		info := map[string]any{"name": ds.Name, "volume": ds.Volume, "volume_sequence": ds.VolumeSequence, "organization": fmt.Sprintf("%04x", ds.Organization), "record_format": fmt.Sprintf("%02x", ds.RecordFormat), "record_length": ds.RecordLength, "block_size": ds.BlockSize, "sms_flags": fmt.Sprintf("%02x", ds.SMSFlags), "flags": fmt.Sprintf("%02x", ds.Flags), "extents": ds.Extents, "traditional_pds": ds.IsPDS(), "raw_allocation": true}
		out := []auto.Entry{file("metadata.json", jsonFile(info)), file("dscb.bin", raw(ds.DSCB)), file("allocation.ckd", ds.Allocation())}
		// Explicit physical access, not logical format support.
		if ds.Organization == 0x0008 || ds.SMSFlags&0x0a != 0 {
			out = append(out, dir("pages4096", auto.ViewFunc(func() ([]auto.Entry, error) {
				p, e := ds.OpenPages(4096)
				if e != nil {
					return nil, e
				}
				return []auto.Entry{file("data.bin", p), file("layout.json", jsonFile(map[string]any{"page_size": p.PageSize, "pages_per_track": p.PerTrack, "allocated_pages": p.Count(), "logical_contents": false}))}, nil
			})))
		}
		if ds.Organization == 0x0008 {
			out = append(out, dir("records", ds.vsamView(limit, maximumBytes)), dir("alternate_records", ds.alternateView(limit, maximumBytes)))
			out = append(out, dir("filesets", auto.ViewFunc(func() ([]auto.Entry, error) {
				pages, err := ds.OpenPages(4096)
				if err != nil {
					return nil, err
				}
				z, err := OpenEpisode(pages, limit)
				if err != nil {
					return nil, err
				}
				return z.View().Entries()
			})))
		}
		if ds.SMSFlags&0x02 != 0 {
			out = append(out, dir("files", auto.ViewFunc(func() ([]auto.Entry, error) {
				pages, err := ds.OpenPages(4096)
				if err != nil {
					return nil, err
				}
				h, err := OpenHFS(pages, limit)
				if err != nil {
					return nil, err
				}
				return h.View().Entries()
			})))
		}
		if ds.IsPDS() {
			out = append(out, dir("members", auto.ViewFunc(func() ([]auto.Entry, error) {
				ms, e := ds.Members(limit)
				if e != nil {
					return nil, e
				}
				entries := make([]auto.Entry, 0, len(ms))
				for _, m := range ms {
					m := m
					entry := dir(m.Name, auto.ViewFunc(func() ([]auto.Entry, error) {
						c, e := ds.Content(&m, limit)
						if e != nil {
							return nil, e
						}
						return []auto.Entry{file("data.bin", c), file("directory.json", jsonFile(m))}, nil
					}))
					entry.Attributes = map[string]any{"alias": m.Alias, "relative_track": m.Track, "record": m.Record}
					entries = append(entries, entry)
				}
				return entries, nil
			})))
		} else if ds.SMSFlags&0x0a == 8 {
			out = append(out, dir("members", auto.ViewFunc(func() ([]auto.Entry, error) {
				var members []PDSEMember
				var e error
				if ds.RecordFormat == 0xc0 {
					members, e = ds.ProgramMembers(limit)
				} else {
					members, e = ds.DataMembers(limit)
				}
				if e != nil {
					return nil, e
				}
				entries := make([]auto.Entry, 0, len(members))
				for _, m := range members {
					m := m
					entry := dir(m.Name, auto.ViewFunc(func() ([]auto.Entry, error) {
						info := map[string]any{"name": m.Name, "alias": m.Alias, "object": m.Object, "record_format": fmt.Sprintf("%02x", ds.RecordFormat)}
						if ds.RecordFormat == 0xc0 {
							info["format"] = "IEWPLMH"
							info["stored_bytes"] = m.Data.Size()
							info["declared_bytes"] = m.DeclaredSize
						} else {
							info["format"] = "PDSE data"
							info["logical_bytes"] = m.Data.Size()
							info["record_lengths"] = m.RecordLengths
						}
						return []auto.Entry{file("data.bin", m.Data), file("directory.json", jsonFile(info))}, nil
					}))
					entries = append(entries, entry)
				}
				return entries, nil
			})))
		} else if ds.Organization == 0x4000 && ds.SMSFlags&0x0e == 0 && ds.Flags&0x84 == 0 {
			out = append(out, dir("content", auto.ViewFunc(func() ([]auto.Entry, error) {
				c, e := ds.Content(nil, limit)
				if e != nil {
					return nil, e
				}
				return []auto.Entry{file("data.bin", c)}, nil
			})))
		}
		return out, nil
	})
}
