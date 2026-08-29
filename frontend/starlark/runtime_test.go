package starlarkfrontend

import (
	"crypto/sha1"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

func TestClockUnixBuiltin(t *testing.T) {
	before := time.Now().Unix()
	value, err := clockUnixBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now().Unix()
	got, ok := value.(starlark.Int).Int64()
	if !ok || got < before || got > after {
		t.Fatalf("clock.unix() = %d, want value in [%d, %d]", got, before, after)
	}
}

func TestDigestBuiltin(t *testing.T) {
	value, err := digestBuiltin(nil, nil, starlark.Tuple{starlark.String("catalog")}, []starlark.Tuple{
		{starlark.String("algorithm"), starlark.String("sha1")},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := sha1.Sum([]byte("catalog"))
	if got := []byte(value.(starlark.Bytes)); string(got) != string(want[:]) {
		t.Fatalf("digest() = %x, want %x", got, want)
	}
}

func TestHexBuiltin(t *testing.T) {
	tests := []struct {
		name  string
		value starlark.Value
		width int
		want  string
	}{
		{name: "int", value: starlark.MakeInt(255), want: "0xff"},
		{name: "negative int with width", value: starlark.MakeInt(-255), width: 4, want: "-0x00ff"},
		{name: "bytes", value: starlark.Bytes([]byte{0x00, 0x0f, 0xff}), want: "000fff"},
		{name: "string", value: starlark.String("AZ"), want: "415a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := starlark.Tuple{tt.value}
			var kwargs []starlark.Tuple
			if tt.width != 0 {
				kwargs = []starlark.Tuple{{starlark.String("width"), starlark.MakeInt(tt.width)}}
			}
			got, err := hexBuiltin(nil, nil, args, kwargs)
			if err != nil {
				t.Fatal(err)
			}
			if string(got.(starlark.String)) != tt.want {
				t.Fatalf("hex() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBytesConcatBuiltin(t *testing.T) {
	parts := starlark.NewList([]starlark.Value{
		starlark.Bytes("\x00\x01"),
		starlark.String("AZ"),
		starlark.Bytes("\xff"),
	})
	got, err := bytesConcatBuiltin(nil, nil, starlark.Tuple{parts}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := []byte(got.(starlark.Bytes)); string(got) != "\x00\x01AZ\xff" {
		t.Fatalf("bytes_concat() = %x", got)
	}
}
