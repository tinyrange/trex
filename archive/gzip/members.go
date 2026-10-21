package gzip

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"io"
	"math"
)

// Members finds exact compressed-member boundaries, validating every CRC and
// size while retaining no expanded payload. This supports multipart APK v2.
func Members(source storage.Reader, maximum int64, maximumMembers int) ([]storage.Reader, error) {
	if source == nil || source.Size() < 0 || maximum <= 0 || maximumMembers <= 0 {
		return nil, fmt.Errorf("gzip_members: invalid source or limits")
	}
	size := source.Size()
	var out []storage.Reader
	var expanded int64
	counter := &memberCounter{r: io.NewSectionReader(source, 0, size)}
	input := bufio.NewReader(counter)
	for {
		start := counter.n - int64(input.Buffered())
		if _, err := input.Peek(1); err == io.EOF {
			return out, nil
		} else if err != nil {
			return nil, err
		}
		if len(out) >= maximumMembers {
			return nil, fmt.Errorf("gzip_members: maximum_members exceeded")
		}
		decoder, err := gzip.NewReader(input)
		if err != nil {
			return nil, err
		}
		decoder.Multistream(false)
		remaining := maximum - expanded
		limit := remaining
		if limit < math.MaxInt64 {
			limit++
		}
		n, err := io.Copy(io.Discard, io.LimitReader(decoder, limit))
		closeErr := decoder.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if n > remaining {
			return nil, fmt.Errorf("gzip_members: maximum_bytes exceeded")
		}
		expanded += n
		end := counter.n - int64(input.Buffered())
		if end <= start {
			return nil, fmt.Errorf("gzip_members: no progress")
		}
		out = append(out, io.NewSectionReader(source, start, end-start))
	}
}

type memberCounter struct {
	r io.Reader
	n int64
}

func (c *memberCounter) Read(p []byte) (int, error) {
	n, e := c.r.Read(p)
	c.n += int64(n)
	return n, e
}
func MembersBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var v starlark.Value
	maximum := int64(512 << 20)
	count := 1024
	if err := starlark.UnpackArgs("gzip_members", args, kwargs, "file", &v, "maximum_bytes?", &maximum, "maximum_members?", &count); err != nil {
		return nil, err
	}
	r, ok := v.(storage.Reader)
	if !ok {
		return nil, fmt.Errorf("gzip_members: expected file")
	}
	members, err := Members(r, maximum, count)
	if err != nil {
		return nil, err
	}
	out := make([]starlark.Value, len(members))
	for i, m := range members {
		out[i] = starfile.NewReader("gzip member", m)
	}
	return starlark.NewList(out), nil
}
