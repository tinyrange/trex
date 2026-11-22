package star

import (
	"fmt"
	"github.com/tinyrange/trex/network/tn5250"
	"go.starlark.net/starlark"
)

type terminal5250 struct{ terminal *tn5250.Terminal }

func (v *terminal5250) CaptureCheckpoint() (func() error, error) {
	return v.terminal.CaptureCheckpoint()
}

func (*terminal5250) String() string        { return "<terminal5250>" }
func (*terminal5250) Type() string          { return "terminal5250" }
func (*terminal5250) Freeze()               {}
func (*terminal5250) Truth() starlark.Bool  { return starlark.True }
func (*terminal5250) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: terminal5250") }
func (*terminal5250) AttrNames() []string {
	return []string{"feed", "apply", "key", "rows", "cursor", "records", "last_record", "fields", "set_field", "set_lenient", "skipped", "skip_error"}
}
func (t *terminal5250) Attr(name string) (starlark.Value, error) {
	switch name {
	case "fields":
		values := make([]starlark.Value, len(t.terminal.Fields))
		for i, f := range t.terminal.Fields {
			values[i] = starlark.Tuple{starlark.MakeInt(f.Row), starlark.MakeInt(f.Column), starlark.MakeInt(f.Length), starlark.MakeInt(int(f.Attribute))}
		}
		return starlark.NewList(values), nil
	case "set_field":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var index int
			var value string
			if err := starlark.UnpackArgs(name, args, kwargs, "index", &index, "value", &value); err != nil {
				return nil, err
			}
			if err := t.terminal.SetField(index, value); err != nil {
				return nil, err
			}
			return starlark.None, nil
		}), nil
	case "rows":
		rows := t.terminal.Rows()
		values := make([]starlark.Value, len(rows))
		for i, row := range rows {
			values[i] = starlark.String(row)
		}
		return starlark.NewList(values), nil
	case "cursor":
		row, col := t.terminal.Cursor()
		return starlark.Tuple{starlark.MakeInt(row), starlark.MakeInt(col)}, nil
	case "records":
		return starlark.MakeInt(t.terminal.Records), nil
	case "skipped":
		return starlark.MakeInt(t.terminal.Skipped), nil
	case "skip_error":
		return starlark.String(t.terminal.SkipError), nil
	case "set_lenient":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var on bool
			if err := starlark.UnpackArgs(name, args, kwargs, "enabled", &on); err != nil {
				return nil, err
			}
			t.terminal.Lenient = on
			return starlark.None, nil
		}), nil
	case "last_record":
		return starlark.Bytes(t.terminal.LastRecord), nil
	case "feed", "apply":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var data starlark.Bytes
			if err := starlark.UnpackArgs(name, args, kwargs, "data", &data); err != nil {
				return nil, err
			}
			if name == "apply" {
				if err := t.terminal.Apply([]byte(data)); err != nil {
					return nil, err
				}
				return starlark.None, nil
			}
			output, err := t.terminal.Feed([]byte(data))
			if err != nil {
				return nil, err
			}
			return starlark.Bytes(output), nil
		}), nil
	case "key":
		return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var aid int
			if err := starlark.UnpackArgs("key", args, kwargs, "aid", &aid); err != nil {
				return nil, err
			}
			if aid < 0 || aid > 255 {
				return nil, fmt.Errorf("tn5250: AID must fit a byte")
			}
			return starlark.Bytes(t.terminal.Key(byte(aid))), nil
		}), nil
	}
	return nil, nil
}
func tn5250Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	kind := "IBM-3179-2"
	var env *starlark.Dict
	if err := starlark.UnpackArgs("tn5250", args, kwargs, "terminal_type?", &kind, "environment?", &env); err != nil {
		return nil, err
	}
	if len(kind) == 0 || len(kind) > 40 {
		return nil, fmt.Errorf("tn5250: invalid terminal type")
	}
	t := tn5250.New()
	t.TerminalType = kind
	t.Environment = map[string]string{}
	total := 0
	if env != nil {
		for _, pair := range env.Items() {
			k, kok := starlark.AsString(pair[0])
			v, vok := starlark.AsString(pair[1])
			if !kok || !vok {
				return nil, fmt.Errorf("tn5250: environment must map strings to strings")
			}
			total += len(k) + len(v)
			if total > 65535 {
				return nil, fmt.Errorf("tn5250: environment exceeds64KiB")
			}
			t.Environment[k] = v
		}
	}
	return &terminal5250{terminal: t}, nil
}

// Terminal5250 returns the protocol state behind a channel.tn5250 value.
func Terminal5250(v starlark.Value) (*tn5250.Terminal, bool) {
	t, ok := v.(*terminal5250)
	if !ok {
		return nil, false
	}
	return t.terminal, true
}
