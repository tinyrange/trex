package tn3270

import (
	"bytes"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
	"image/png"
)

type clientValue struct{ client *Client }

func (*clientValue) String() string        { return "<tn3270.client>" }
func (*clientValue) Type() string          { return "tn3270_client" }
func (*clientValue) Freeze()               {}
func (*clientValue) Truth() starlark.Bool  { return true }
func (*clientValue) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: tn3270 client") }
func Builtins() starlark.StringDict {
	return starlark.StringDict{"client": starlark.NewBuiltin("tn3270.client", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		if err := starlark.UnpackArgs("tn3270.client", args, kwargs); err != nil {
			return nil, err
		}
		return &clientValue{NewClient()}, nil
	})}
}
func (*clientValue) AttrNames() []string {
	return []string{"feed", "key", "screen", "screens", "screenshot", "type", "records", "locked", "error"}
}
func (v *clientValue) Attr(name string) (starlark.Value, error) {
	if name == "error" {
		if v.client.Err != nil {
			return starlark.String(v.client.Err.Error()), nil
		}
		return starlark.String(""), nil
	}
	if name == "locked" {
		return starlark.Bool(v.client.Display.Locked()), nil
	}
	if name == "records" {
		return starlark.MakeUint64(v.client.Records), nil
	}
	switch name {
	case "feed", "key", "screen", "screens", "screenshot", "type":
	default:
		return nil, nil
	}
	return starlark.NewBuiltin("tn3270_client."+name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		switch name {
		case "feed":
			var data starlark.Bytes
			raiseError := true
			if err := starlark.UnpackArgs(name, args, kwargs, "data", &data, "raise_error?", &raiseError); err != nil {
				return nil, err
			}
			out, err := v.client.Feed([]byte(data))
			if err != nil && !raiseError {
				// Preserve even pre-error Telnet replies. The poisoned client
				// remains unusable; callers can record evidence and clean up.
				v.client.Err = err
				return starlark.Bytes(out), nil
			}
			if err != nil {
				return nil, err
			}
			return starlark.Bytes(out), nil
		case "type", "key":
			var text string
			if err := starlark.UnpackArgs(name, args, kwargs, "text", &text); err != nil {
				return nil, err
			}
			if name == "type" {
				if err := v.client.Type(text); err != nil {
					return nil, err
				}
				return starlark.None, nil
			}
			out, err := v.client.Key(text)
			if err != nil {
				return nil, err
			}
			return starlark.Bytes(out), nil
		}
		if err := starlark.UnpackArgs(name, args, kwargs); err != nil {
			return nil, err
		}
		switch name {
		case "screen":
			return starlark.String(v.client.Display.Text()), nil
		case "screens":
			out := make([]starlark.Value, len(v.client.Display.Log))
			for i, line := range v.client.Display.Log {
				out[i] = starlark.String(line)
			}
			return starlark.NewList(out), nil
		case "screenshot":
			var b bytes.Buffer
			if err := png.Encode(&b, v.client.Display.Capture()); err != nil {
				return nil, err
			}
			return &starfile.Bytes{Name: "tn3270.png", Data: b.Bytes()}, nil
		}
		return nil, nil
	}), nil
}
