package perf

import (
	"fmt"
	"sort"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func optionalInteger(value uint64, present bool) starlark.Value {
	if !present {
		return starlark.None
	}
	return starlark.MakeUint64(value)
}

func fieldValues(f Fields) starlark.StringDict {
	return starlark.StringDict{
		"present":    starlark.MakeUint64(f.Present),
		"ip":         optionalInteger(f.IP, f.Present&SampleIP != 0),
		"pid":        optionalInteger(uint64(f.PID), f.Present&SampleTID != 0),
		"tid":        optionalInteger(uint64(f.TID), f.Present&SampleTID != 0),
		"time":       optionalInteger(f.Time, f.Present&SampleTime != 0),
		"address":    optionalInteger(f.Address, f.Present&SampleAddress != 0),
		"id":         optionalInteger(f.ID, f.Present&SampleID != 0),
		"stream_id":  optionalInteger(f.StreamID, f.Present&SampleStreamID != 0),
		"cpu":        optionalInteger(uint64(f.CPU), f.Present&SampleCPU != 0),
		"period":     optionalInteger(f.Period, f.Present&SamplePeriod != 0),
		"identifier": optionalInteger(f.Identifier, f.Present&SampleIdentifier != 0),
	}
}

// Builtin exposes bounded perf.data records without resolving host paths or
// assigning symbols or a clock domain that the input does not identify.
func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	options := Options{MaximumRecords: 1000000, MaximumSamples: 1000000, MaximumStringBytes: 1 << 20}
	if err := starlark.UnpackArgs("perf", args, kwargs, "file", &value, "maximum_records?", &options.MaximumRecords, "maximum_samples?", &options.MaximumSamples, "maximum_string_bytes?", &options.MaximumStringBytes); err != nil {
		return nil, err
	}
	if options.MaximumRecords <= 0 || options.MaximumSamples <= 0 || options.MaximumStringBytes <= 0 {
		return nil, fmt.Errorf("perf: limits must be positive")
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("perf: expected file")
	}
	f, err := Open(source, options)
	if err != nil {
		return nil, err
	}
	attributes := make([]starlark.Value, len(f.Attributes))
	for i, a := range f.Attributes {
		ids := make([]starlark.Value, len(a.IDs))
		for j, id := range a.IDs {
			ids[j] = starlark.MakeUint64(id)
		}
		var clockID starlark.Value = starlark.None
		if a.UseClockID {
			clockID = starlark.MakeInt64(int64(a.ClockID))
		}
		attributes[i] = starfile.NewRecord(starlark.StringDict{
			"type": starlark.MakeUint64(uint64(a.Type)), "size": starlark.MakeUint64(uint64(a.Size)),
			"config": starlark.MakeUint64(a.Config), "sample_period": starlark.MakeUint64(a.SamplePeriod),
			"sample_type": starlark.MakeUint64(a.SampleType), "read_format": starlark.MakeUint64(a.ReadFormat),
			"flags": starlark.MakeUint64(a.Flags), "clock_id": clockID, "use_clock_id": starlark.Bool(a.UseClockID),
			"sample_id_all": starlark.Bool(a.SampleIDAll), "ids": starlark.NewList(ids),
		})
	}
	samples := make([]starlark.Value, len(f.Samples))
	for i, s := range f.Samples {
		fields := fieldValues(s.Fields)
		fields["offset"], fields["misc"] = starlark.MakeUint64(s.Offset), starlark.MakeUint64(uint64(s.Misc))
		samples[i] = starfile.NewRecord(fields)
	}
	mappings := make([]starlark.Value, len(f.Mappings))
	for i, m := range f.Mappings {
		var buildID starlark.Value = starlark.None
		if len(m.BuildID) != 0 {
			buildID = starlark.Bytes(string(m.BuildID))
		}
		mmap2 := m.Type == 10
		inode := mmap2 && m.Misc&(1<<14) == 0
		mappings[i] = starfile.NewRecord(starlark.StringDict{
			"offset": starlark.MakeUint64(m.Offset), "misc": starlark.MakeUint64(uint64(m.Misc)), "type": starlark.MakeUint64(uint64(m.Type)),
			"pid": starlark.MakeUint64(uint64(m.PID)), "tid": starlark.MakeUint64(uint64(m.TID)),
			"address": starlark.MakeUint64(m.Address), "length": starlark.MakeUint64(m.Length), "page_offset": starlark.MakeUint64(m.PageOffset),
			"major": optionalInteger(uint64(m.Major), inode), "minor": optionalInteger(uint64(m.Minor), inode),
			"inode": optionalInteger(m.Inode, inode), "inode_generation": optionalInteger(m.InodeGeneration, inode),
			"prot": optionalInteger(uint64(m.Prot), mmap2), "flags": optionalInteger(uint64(m.Flags), mmap2),
			"build_id": buildID, "filename": starlark.String(m.Filename), "sample_id": starfile.NewRecord(fieldValues(m.SampleID)),
		})
	}
	comms := make([]starlark.Value, len(f.Comms))
	for i, c := range f.Comms {
		comms[i] = starfile.NewRecord(starlark.StringDict{
			"offset": starlark.MakeUint64(c.Offset), "misc": starlark.MakeUint64(uint64(c.Misc)),
			"pid": starlark.MakeUint64(uint64(c.PID)), "tid": starlark.MakeUint64(uint64(c.TID)),
			"name": starlark.String(c.Name), "sample_id": starfile.NewRecord(fieldValues(c.SampleID)),
		})
	}
	lost := make([]starlark.Value, len(f.Lost))
	for i, l := range f.Lost {
		lost[i] = starfile.NewRecord(starlark.StringDict{
			"offset": starlark.MakeUint64(l.Offset), "misc": starlark.MakeUint64(uint64(l.Misc)),
			"type": starlark.MakeUint64(uint64(l.Type)), "id": optionalInteger(l.ID, l.Type == 2),
			"count": starlark.MakeUint64(l.Count), "sample_id": starfile.NewRecord(fieldValues(l.SampleID)),
		})
	}
	unknown := starlark.NewDict(len(f.UnknownRecords))
	kinds := make([]uint32, 0, len(f.UnknownRecords))
	for kind := range f.UnknownRecords {
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i] < kinds[j] })
	for _, kind := range kinds {
		if err := unknown.SetKey(starlark.MakeUint64(uint64(kind)), starlark.MakeUint64(f.UnknownRecords[kind])); err != nil {
			return nil, err
		}
	}
	return starfile.NewRecord(starlark.StringDict{
		"little_endian": starlark.Bool(f.LittleEndian), "attributes": starlark.NewList(attributes),
		"samples": starlark.NewList(samples), "mappings": starlark.NewList(mappings), "comms": starlark.NewList(comms),
		"lost": starlark.NewList(lost), "total_lost": starlark.MakeUint64(f.TotalLost),
		"unknown_records": unknown, "records": starlark.MakeUint64(f.Records),
	}), nil
}
