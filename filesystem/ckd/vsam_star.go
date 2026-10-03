package ckd

import (
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func VVRBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if e := starlark.UnpackArgs("ckd_vvr", args, kwargs, "data", &value); e != nil {
		return nil, e
	}
	b, e := starfile.BytesForValue(value, 32768)
	if e != nil {
		return nil, e
	}
	v, e := ParseVVR(b)
	if e != nil {
		return nil, e
	}
	return starfile.NewRecord(starlark.StringDict{
		"name": starlark.String(v.Name), "cluster": starlark.String(v.Cluster), "catalog": starlark.String(v.Catalog), "index": starlark.Bool(v.Index),
		"ci_addressed": starlark.Bool(v.CIAddressed), "maximum_record_length": starlark.MakeUint(uint(v.MaximumRecordLength)),
		"index_root_rba": starlark.MakeUint64(v.IndexRootRBA), "flags": starlark.MakeInt(int(v.Flags)), "data_flags": starlark.MakeInt(int(v.DataFlags)), "ci_bytes": starlark.MakeUint(uint(v.CIBytes)), "used_bytes": starlark.MakeUint64(v.UsedBytes), "allocated_bytes": starlark.MakeUint64(v.AllocatedBytes), "cis_per_ca": starlark.MakeUint(uint(v.CIsPerTrack) * uint(v.TracksPerCA)), "key_offset": starlark.MakeInt(int(v.KeyOffset)), "key_length": starlark.MakeInt(int(v.KeyLength)),
	}), nil
}
func CatalogRecordBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if e := starlark.UnpackArgs("ckd_catalog_record", args, kwargs, "data", &value); e != nil {
		return nil, e
	}
	b, e := starfile.BytesForValue(value, 32768)
	if e != nil {
		return nil, e
	}
	v, e := ParseCatalogRecord(b)
	if e != nil {
		return nil, e
	}
	var cells func([]CatalogCell) *starlark.List
	cells = func(input []CatalogCell) *starlark.List {
		out := make([]starlark.Value, 0, len(input))
		for _, c := range input {
			out = append(out, starfile.NewRecord(starlark.StringDict{"kind": starlark.MakeInt(int(c.Kind)), "name": starlark.String(c.Name), "raw": starlark.Bytes(c.Raw), "children": cells(c.Children)}))
		}
		return starlark.NewList(out)
	}
	references := make([]starlark.Value, len(v.References))
	for i, name := range v.References {
		references[i] = starlark.String(name)
	}
	return starfile.NewRecord(starlark.StringDict{"references": starlark.NewList(references), "kind": starlark.MakeInt(int(v.Kind)), "name": starlark.String(v.Name), "key": starlark.Bytes(v.Key), "cells": cells(v.Cells)}), nil
}
func VSAMRecordsBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	var organization string
	var ci uint32
	var used uint64
	var perCA uint32
	var keyOffset, keyLength uint32
	var index starlark.Value = starlark.None
	var indexCI uint32 = 4096
	var indexUsed, root uint64
	maxRecords, maxRecordBytes := 100000, 16<<20
	maxIntervals, maxBytes := uint64(1000000), uint64(64<<20)
	if e := starlark.UnpackArgs("ckd_vsam_records", args, kwargs, "data", &value, "organization", &organization, "ci_bytes", &ci, "used_bytes", &used, "cis_per_ca", &perCA, "key_offset?", &keyOffset, "key_length?", &keyLength, "index?", &index, "index_ci_bytes?", &indexCI, "index_used_bytes?", &indexUsed, "index_root_rba?", &root, "max_records?", &maxRecords, "max_record_bytes?", &maxRecordBytes, "max_intervals?", &maxIntervals, "max_bytes?", &maxBytes); e != nil {
		return nil, e
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("ckd_vsam_records: data must be a portable file")
	}
	o := VSAMReadOptions{Organization: VSAMOrganization(organization), CIBytes: ci, UsedBytes: used, CIsPerCA: perCA, KeyOffset: keyOffset, KeyLength: keyLength, MaxRecords: maxRecords, MaxRecordBytes: maxRecordBytes, MaxIntervals: maxIntervals, MaxBytes: maxBytes}
	if index != starlark.None {
		r, ok := index.(storage.Reader)
		if !ok {
			return nil, fmt.Errorf("ckd_vsam_records: index must be a portable file")
		}
		if maxIntervals > 10000000 {
			return nil, fmt.Errorf("ckd_vsam_records: excessive index budget")
		}
		var e error
		o.Order, e = VSAMIndexOrder(r, indexCI, indexUsed, root, ci, used, int(keyLength), int(maxIntervals))
		if e != nil {
			return nil, e
		}
	}
	records, e := ReadVSAMRecords(source, o)
	if e != nil {
		return nil, e
	}
	out := make([]starlark.Value, 0, len(records))
	for _, r := range records {
		out = append(out, starfile.NewRecord(starlark.StringDict{"rba": starlark.MakeUint64(r.RBA), "number": starlark.MakeUint64(r.Number), "data": starlark.Bytes(r.Data)}))
	}
	return starlark.NewList(out), nil
}
