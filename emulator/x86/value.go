package x86

import (
	binaryapi "github.com/tinyrange/trex/binary"
	starvalue "github.com/tinyrange/trex/script/value"
	"go.starlark.net/starlark"
)

type starlarkRecord = starvalue.Record

var newStarlarkRecord = starvalue.NewRecord

type Machine = emulatorX86

var binaryScalarCodecs = binaryapi.ScalarCodecs

func binaryScalarCodecNamed(name string) (binaryapi.ScalarCodec, bool) {
	return binaryapi.ScalarCodecNamed(name)
}

func bytesForBinaryValue(value starlark.Value) ([]byte, error) {
	return binaryapi.BytesForValue(value)
}

const defaultBinaryBuilderLimit = int(binaryapi.DefaultValueLimit)
