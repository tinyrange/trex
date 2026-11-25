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
	return []string{"error", "feed", "key", "locked", "move", "records", "screen", "screens", "screenshot", "state", "type"}
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
	case "feed", "key", "move", "screen", "screens", "screenshot", "state", "type":
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
		case "move":
			// Operator cursor positioning, as a pointer click on a display
			// station. It sends nothing; the next attention key reports it.
			var position int
			if err := starlark.UnpackArgs(name, args, kwargs, "position", &position); err != nil {
				return nil, err
			}
			d := v.client.Display
			if position < 0 || position >= d.Rows*d.Cols {
				return nil, fmt.Errorf("tn3270_client.move: position %d outside %dx%d buffer", position, d.Rows, d.Cols)
			}
			d.SetCursor(position/d.Cols, position%d.Cols)
			return starlark.None, nil
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
		case "state":
			return screenState(v.client), nil
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

// screenState is the structured presentation space for interactive
// frontends: one character per buffer position in text, attr, color and
// hilite (see s390.Screen3270), plus the host write count so a frontend can
// tell host output from its own operator edits. Nondisplay fields are blank.
func screenState(c *Client) starlark.Value {
	s := c.Display.Screen()
	d := starlark.NewDict(12)
	for _, item := range []struct {
		key   string
		value starlark.Value
	}{
		{"rows", starlark.MakeInt(s.Rows)}, {"cols", starlark.MakeInt(s.Cols)},
		{"cursor", starlark.MakeInt(s.Cursor)}, {"locked", starlark.Bool(s.Locked)},
		{"insert", starlark.Bool(s.Insert)}, {"text", starlark.String(s.Text)},
		{"attr", starlark.String(s.Attr)}, {"color", starlark.String(s.Color)},
		{"hilite", starlark.String(s.Hilite)}, {"alarms", starlark.MakeUint64(s.Alarms)},
		{"writes", starlark.MakeUint64(c.Display.Writes)}, {"records", starlark.MakeUint64(c.Records)},
	} {
		_ = d.SetKey(starlark.String(item.key), item.value)
	}
	return d
}
