package windows

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

var stateRepositoryBase32 = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// StateRepositoryHash implements Windows StateRepository's hash_base32 SQL
// function for NULL, INTEGER, TEXT and BLOB values. Integers contribute eight
// little-endian bytes. Text contributes ASCII-lowercased UTF-16LE up to its first
// NUL, without a terminator. NULL and empty values contribute nothing; there
// are no type tags, separators or lengths. The digest is SHA-256.
func StateRepositoryHash(values []any) (string, error) {
	const maximumBytes = 64 << 20
	if len(values) > 1024 {
		return "", fmt.Errorf("StateRepository hash has too many values")
	}
	h := sha256.New()
	total := 0
	for _, value := range values {
		var data []byte
		switch v := value.(type) {
		case nil:
			continue
		case int64:
			data = make([]byte, 8)
			binary.LittleEndian.PutUint64(data, uint64(v))
		case string:
			if !utf8.ValidString(v) {
				return "", fmt.Errorf("StateRepository hash text is not valid UTF-8")
			}
			if at := strings.IndexByte(v, 0); at >= 0 {
				v = v[:at]
			}
			if len(v) > maximumBytes/2 {
				return "", fmt.Errorf("StateRepository hash text exceeds limit")
			}
			units := utf16.Encode([]rune(v))
			data = make([]byte, len(units)*2)
			for i, unit := range units {
				// Native Text::ToLowerUntilNull folds only ASCII A-Z.
				if unit >= 'A' && unit <= 'Z' {
					unit += 'a' - 'A'
				}
				binary.LittleEndian.PutUint16(data[i*2:], unit)
			}
		case []byte:
			data = v
		default:
			return "", fmt.Errorf("unsupported StateRepository hash value %T", value)
		}
		if len(data) > maximumBytes-total {
			return "", fmt.Errorf("StateRepository hash input exceeds limit")
		}
		total += len(data)
		_, _ = h.Write(data)
	}
	return stateRepositoryBase32.EncodeToString(h.Sum(nil)), nil
}

func stateRepositoryHashBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var list *starlark.List
	if err := starlark.UnpackArgs("state_repository_hash", args, kwargs, "values", &list); err != nil {
		return nil, err
	}
	if list.Len() > 1024 {
		return nil, fmt.Errorf("state_repository_hash: too many values")
	}
	values := make([]any, list.Len())
	// Bound blob copies before materializing the Go argument list. The native
	// encoder below additionally bounds the combined encoded text/blob input.
	blobBytes := 0
	for i := range values {
		switch v := list.Index(i).(type) {
		case starlark.NoneType:
		case starlark.Int:
			n, ok := v.Int64()
			if !ok {
				return nil, fmt.Errorf("state_repository_hash: integer exceeds int64")
			}
			values[i] = n
		case starlark.String:
			values[i] = string(v)
		case starlark.Bytes:
			if len(v) > (64<<20)-blobBytes {
				return nil, fmt.Errorf("state_repository_hash: blob input exceeds limit")
			}
			blobBytes += len(v)
			values[i] = []byte(v)
		default:
			return nil, fmt.Errorf("state_repository_hash: unsupported value type %s", v.Type())
		}
	}
	value, err := StateRepositoryHash(values)
	if err != nil {
		return nil, err
	}
	return starlark.String(value), nil
}
