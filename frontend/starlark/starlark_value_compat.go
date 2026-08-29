package starlarkfrontend

import (
	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

type starlarkRecord = starvalue.Record

func newStarlarkRecord(values starlark.StringDict) *starlarkRecord {
	return starvalue.NewRecord(values)
}
