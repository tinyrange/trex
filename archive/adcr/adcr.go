// Package adcr decodes Aladdin's ADCR01 and ADCR03 resource wrappers. Format facts were
// recovered from original installer bytes and checked with independent REPL
// probes; no third-party decoder implementation is used.
package adcr

import (
	"fmt"
	"github.com/tinyrange/trex/archive/internal/aladdin"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// Open returns decoded resource bytes. The dictionary is explicit because
// installers can seed compression with their own loader code, not zeroes.
// ADCR03 has a size field but no checksum; callers should validate the payload
// structure or independent hashes. No executable resource is run.
func Open(file, dictionary starfile.File, maximum int64) (starfile.File, error) {
	if maximum < 0 || file.Size() < 9 || file.Size()-8 > maximum {
		return nil, fmt.Errorf("adcr: input outside limits")
	}
	var header [8]byte
	if _, err := starfile.ReadFullAt(file, header[:], 0); err != nil {
		return nil, err
	}
	if string(header[:4]) != "ADCR" || (header[4] != 1 && header[4] != 3) {
		return nil, fmt.Errorf("adcr: unsupported resource header")
	}
	target := int(header[5])<<16 | int(header[6])<<8 | int(header[7])
	if int64(target) > maximum {
		return nil, fmt.Errorf("adcr: decoded size exceeds limit")
	}
	input, err := starfile.ReadAll(&starfile.Slice{Base: file, Offset: 8, Length: file.Size() - 8})
	if err != nil {
		return nil, err
	}
	var seed []byte
	if dictionary != nil {
		if dictionary.Size() < 0 {
			return nil, fmt.Errorf("adcr: invalid dictionary size")
		}
		// Version3 uses trailing history; version1's initial phrase pointers
		// refer to the beginning of an explicit, at most18-byte seed phrase.
		n, offset := min(dictionary.Size(), 65535), max(int64(0), dictionary.Size()-65535)
		if header[4] == 1 {
			n, offset = min(dictionary.Size(), 18), 0
		}
		seed, err = starfile.ReadAll(&starfile.Slice{Base: dictionary, Offset: offset, Length: n})
		if err != nil {
			return nil, err
		}
	}
	var output []byte
	if header[4] == 1 {
		output, err = decodeVersion1(input, seed, target)
	} else {
		output, err = aladdin.Decode(input, seed, target, aladdin.Resource03)
	}
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: output}, nil
}

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	dictionary := starlark.Value(starlark.None)
	maximum := int64(256 << 20)
	if err := starlark.UnpackArgs("adcr", args, kwargs, "file", &value, "dictionary?", &dictionary, "maximum_decoded_bytes?", &maximum); err != nil {
		return nil, err
	}
	file, ok := value.(starfile.File)
	if !ok {
		return nil, fmt.Errorf("adcr: expected file")
	}
	var seed starfile.File
	if dictionary != starlark.None {
		seed, ok = dictionary.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("adcr: dictionary must be a file")
		}
	}
	return Open(file, seed, maximum)
}
