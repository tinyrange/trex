package ckd

import (
	"fmt"

	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// AttributePageBuiltin exposes bounded native parsing; callers own tree traversal.
func AttributePageBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	if err := starlark.UnpackArgs("ckd_attribute_page", args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	b, ok := data.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("ckd_attribute_page: expected 4096 bytes")
	}
	p, err := ParseAttributePage([]byte(b))
	if err != nil {
		return nil, err
	}
	cells := make([]starlark.Value, 0, len(p.Cells))
	for _, c := range p.Cells {
		cells = append(cells, starfile.NewRecord(starlark.StringDict{"flags": starlark.MakeInt(int(c.Flags)), "key": starlark.Bytes(c.Key[:]), "value": starlark.Bytes(c.Value)}))
	}
	return starfile.NewRecord(starlark.StringDict{"level": starlark.MakeInt(int(p.Level)), "cells": starlark.NewList(cells)}), nil
}

// ControlIntervalBuiltin parses a single explicitly selected data CI.
func ControlIntervalBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	if err := starlark.UnpackArgs("ckd_control_interval", args, kwargs, "data", &data); err != nil {
		return nil, err
	}
	b, ok := data.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("ckd_control_interval: expected bytes")
	}
	c, err := ParseControlInterval([]byte(b))
	if err != nil {
		return nil, err
	}
	records := make([]starlark.Value, 0, len(c.Records))
	for _, r := range c.Records {
		records = append(records, starlark.Bytes(r))
	}
	return starfile.NewRecord(starlark.StringDict{"eof": starlark.Bool(c.EOF), "free_offset": starlark.MakeInt(int(c.FreeOffset)), "free_length": starlark.MakeInt(int(c.FreeLength)), "records": starlark.NewList(records)}), nil
}

// IGWAttributesBuiltin exposes bounded active-tree enumeration for metadata
// inspection. It uses the same native map and tree reader as HFS and PDSE.
func IGWAttributesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	limit := 100000
	if err := starlark.UnpackArgs("ckd_igw_attributes", args, kwargs, "data", &value, "max_cells?", &limit); err != nil {
		return nil, err
	}
	source, ok := value.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("ckd_igw_attributes: data must be a portable file")
	}
	g, err := OpenIGW(source)
	if err != nil {
		return nil, err
	}
	cells, err := g.Attributes(limit)
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, 0, len(cells))
	for _, c := range cells {
		out = append(out, starfile.NewRecord(starlark.StringDict{"flags": starlark.MakeInt(int(c.Flags)), "key": starlark.Bytes(c.Key[:]), "value": starlark.Bytes(c.Value)}))
	}
	return starlark.NewList(out), nil
}
