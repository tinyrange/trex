package star

import (
	"fmt"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

// Record is a small immutable-shape Starlark object used by format adapters.
type Record struct {
	names  []string
	values starlark.StringDict
}

func NewRecord(values starlark.StringDict) *Record {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return &Record{names: names, values: values}
}

func (r *Record) String() string { return "<record " + strings.Join(r.names, ", ") + ">" }
func (*Record) Type() string     { return "record" }
func (r *Record) Freeze() {
	for _, value := range r.values {
		value.Freeze()
	}
}
func (*Record) Truth() starlark.Bool                       { return starlark.True }
func (*Record) Hash() (uint32, error)                      { return 0, fmt.Errorf("unhashable: record") }
func (r *Record) Attr(name string) (starlark.Value, error) { return r.values[name], nil }
func (r *Record) AttrNames() []string                      { return append([]string(nil), r.names...) }

func (r *Record) Get(name string) starlark.Value { return r.values[name] }
