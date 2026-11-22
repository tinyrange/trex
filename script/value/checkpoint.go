package value

import (
	"fmt"
	"reflect"
	"strings"

	"go.starlark.net/starlark"
)

type savedDict struct {
	value *starlark.Dict
	items []starlark.Tuple
}

type savedList struct {
	value *starlark.List
	items []starlark.Value
}

type savedSet struct {
	value *starlark.Set
	items []starlark.Value
}

// GraphCheckpoint restores mutable script containers in place, preserving
// references held by callbacks. Native resources supply their own checkpoint.
type GraphCheckpoint struct {
	dicts     []savedDict
	lists     []savedList
	sets      []savedSet
	resources []func() error
	checks    []func() error
}

// CaptureGraph visits roots together so aliases and cycles are preserved.
// extra can capture runtime-specific leaf values and return their child state.
func CaptureGraph(roots []starlark.Value, extra func(starlark.Value) starlark.Value) (*GraphCheckpoint, error) {
	c := &GraphCheckpoint{}
	seen := make(map[starlark.Value]bool)
	pending := append([]starlark.Value(nil), roots...)
	for len(pending) > 0 {
		i := len(pending) - 1
		v := pending[i]
		pending = pending[:i]
		if v == nil {
			continue
		}
		// Native resource identities, records and mutable Starlark containers
		// are pointers. Tuples can contain unhashable values.
		if reflect.ValueOf(v).Kind() == reflect.Pointer {
			if seen[v] {
				continue
			}
			seen[v] = true
		}
		switch v := v.(type) {
		case interface {
			CheckpointResource() (validate, restore func() error, err error)
		}:
			check, restore, err := v.CheckpointResource()
			if err != nil {
				return nil, fmt.Errorf("checkpoint resource: %w", err)
			}
			if check != nil {
				c.checks = append(c.checks, check)
			}
			c.resources = append(c.resources, restore)
		case interface{ CaptureCheckpoint() (func() error, error) }:
			restore, err := v.CaptureCheckpoint()
			if err != nil {
				return nil, fmt.Errorf("checkpoint resource: %w", err)
			}
			c.resources = append(c.resources, restore)
		case *starlark.Dict:
			items := v.Items()
			c.dicts = append(c.dicts, savedDict{v, items})
			for _, pair := range items {
				pending = append(pending, pair[0], pair[1])
			}
		case *starlark.List:
			items := make([]starlark.Value, v.Len())
			for i := range items {
				items[i] = v.Index(i)
			}
			c.lists = append(c.lists, savedList{v, items})
			pending = append(pending, items...)
		case *starlark.Set:
			items := make([]starlark.Value, 0, v.Len())
			iter := v.Iterate()
			var item starlark.Value
			for iter.Next(&item) {
				items = append(items, item)
			}
			iter.Done()
			c.sets = append(c.sets, savedSet{v, items})
			pending = append(pending, items...)
		case starlark.Tuple:
			pending = append(pending, v...)
		case *Record:
			for _, item := range v.Values {
				pending = append(pending, item)
			}
		default:
			if extra != nil {
				pending = append(pending, extra(v))
			}
		}
	}
	return c, nil
}

func (c *GraphCheckpoint) Containers() int { return len(c.dicts) + len(c.lists) + len(c.sets) }

func (c *GraphCheckpoint) Restore() error {
	// A published disk can invalidate a pause-time checkpoint. Verify all
	// such resources before rewinding even the first channel or device.
	for _, check := range c.checks {
		if err := check(); err != nil {
			return fmt.Errorf("restore checkpoint resource: %w", err)
		}
	}
	for _, restore := range c.resources {
		if err := restore(); err != nil {
			return fmt.Errorf("restore checkpoint resource: %w", err)
		}
	}
	for _, saved := range c.dicts {
		if err := saved.value.Clear(); err != nil {
			// Frozen values are immutable configuration reachable from a
			// plugin's mutable state. They cannot have changed since capture,
			// so preserving them is already an exact restore.
			if strings.Contains(err.Error(), "frozen") {
				continue
			}
			return fmt.Errorf("restore checkpoint dict: %w", err)
		}
		for _, item := range saved.items {
			if err := saved.value.SetKey(item[0], item[1]); err != nil {
				return fmt.Errorf("restore checkpoint dict item: %w", err)
			}
		}
	}
	for _, saved := range c.lists {
		if err := saved.value.Clear(); err != nil {
			if strings.Contains(err.Error(), "frozen") {
				continue
			}
			return fmt.Errorf("restore checkpoint list: %w", err)
		}
		for _, item := range saved.items {
			if err := saved.value.Append(item); err != nil {
				return fmt.Errorf("restore checkpoint list item: %w", err)
			}
		}
	}
	for _, saved := range c.sets {
		if err := saved.value.Clear(); err != nil {
			if strings.Contains(err.Error(), "frozen") {
				continue
			}
			return fmt.Errorf("restore checkpoint set: %w", err)
		}
		for _, item := range saved.items {
			if err := saved.value.Insert(item); err != nil {
				return fmt.Errorf("restore checkpoint set item: %w", err)
			}
		}
	}
	return nil
}
