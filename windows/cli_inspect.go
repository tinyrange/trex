package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/msdelta"
	"go.starlark.net/starlark"
)

func cliInspectBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	method := ""
	if err := starlark.UnpackArgs("cli_inspect", args, kwargs, "value", &value, "method?", &method); err != nil {
		return nil, err
	}
	data, err := bytesForBinaryValueLimited(value, 32<<20)
	if err != nil {
		return nil, err
	}
	info, err := msdelta.InspectCLI(data, method)
	if err != nil {
		return nil, fmt.Errorf("cli_inspect: %w", err)
	}
	rows := make([]starlark.Value, 0, len(info.Rows))
	for _, row := range info.Rows {
		cols := []starlark.Value{}
		for _, v := range row.Columns {
			switch v := v.(type) {
			case uint32:
				cols = append(cols, starlark.MakeUint(uint(v)))
			case string:
				cols = append(cols, starlark.String(v))
			case []byte:
				cols = append(cols, starlark.Bytes(v))
			}
		}
		rows = append(rows, starfile.NewRecord(starlark.StringDict{"token": starlark.MakeUint(uint(row.Token)), "columns": starlark.NewList(cols)}))
	}
	methods := []starlark.Value{}
	for _, m := range info.Methods {
		instructions := []starlark.Value{}
		for _, i := range m.Instructions {
			instructions = append(instructions, starfile.NewRecord(starlark.StringDict{
				"offset": starlark.MakeInt(i.Offset), "opcode": starlark.MakeUint(uint(i.Opcode)), "operand": starlark.Bytes(i.Operand), "token": starlark.MakeUint(uint(i.Token)),
			}))
		}
		methods = append(methods, starfile.NewRecord(starlark.StringDict{"token": starlark.MakeUint(uint(m.Token)), "name": starlark.String(m.Name), "instructions": starlark.NewList(instructions)}))
	}
	strings := starlark.NewDict(len(info.Strings))
	for token, text := range info.Strings {
		if err := strings.SetKey(starlark.MakeUint(uint(token)), starlark.String(text)); err != nil {
			return nil, err
		}
	}
	return starfile.NewRecord(starlark.StringDict{"runtime_version": starlark.String(info.RuntimeVersion), "cor_flags": starlark.MakeUint(uint(info.CorFlags)), "entry_point": starlark.MakeUint(uint(info.EntryPoint)), "rows": starlark.NewList(rows), "methods": starlark.NewList(methods), "strings": strings}), nil
}
