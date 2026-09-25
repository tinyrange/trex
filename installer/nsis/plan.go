package nsis

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

// CodeRange selects an explicitly audited straight-line installation region.
// Branches/calls are rejected, not silently flattened into unconditional writes.
type CodeRange struct{ Start, End int }

var variableToken = regexp.MustCompile(`\$\$|\$\{[^}]*\}|\$R[0-9]|\$[0-9]|\$[A-Z_]+`)

func planDict(values starlark.StringDict) *starlark.Dict {
	d := starlark.NewDict(len(values))
	for k, v := range values {
		_ = d.SetKey(starlark.String(k), v)
	}
	return d
}
func stringValues(values []string) *starlark.List {
	v := make([]starlark.Value, len(values))
	for i, s := range values {
		v[i] = starlark.String(s)
	}
	return starlark.NewList(v)
}
func guestPath(value, directory string) (string, error) {
	value = strings.ReplaceAll(value, "/", `\`)
	if len(value) < 3 || value[1:3] != `:\` {
		if strings.HasPrefix(value, `\`) || strings.Contains(value, ":") {
			return "", fmt.Errorf("nsis: ambiguous guest path %q", value)
		}
		value = strings.TrimRight(directory, `\`) + `\` + value
	}
	if len(value) < 3 || value[1:3] != `:\` || !((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) {
		return "", fmt.Errorf("nsis: absolute guest directory required: %q", value)
	}
	return value[:2] + strings.ReplaceAll(path.Clean("/"+strings.ReplaceAll(value[3:], `\`, "/")), "/", `\`), nil
}

// Plan evaluates only declarative, straight-line NSIS operations. Without ranges
// it inspects selected sections and fails closed on control flow. Product recipes
// may supply audited ranges and inputs for a documented fresh-install policy;
// the result explicitly retains that limited scope, never claiming whole-script
// execution. No host environment or registry is consulted.
func (a *Archive) Plan(locations, supplied map[string]string, ranges []CodeRange) (*starlark.Dict, error) {
	vars := map[string]string{}
	for k, v := range supplied {
		if !strings.HasPrefix(k, "$") {
			k = "$" + k
		}
		vars[strings.ToUpper(k)] = v
	}
	for k, v := range locations {
		if strings.EqualFold(k, "<TARGETDIR>") {
			vars["$INSTDIR"] = v
		}
	}
	if _, ok := vars["$OUTDIR"]; !ok {
		vars["$OUTDIR"] = vars["$INSTDIR"]
	}
	explicit := ranges != nil
	if ranges == nil {
		for _, s := range a.Listing.Sections {
			if s.Flags&1 != 0 {
				ranges = append(ranges, CodeRange{s.Start, s.Start + s.Count})
			}
		}
	}
	expand := func(offset int32) (string, error) {
		text, err := a.Listing.String(offset)
		if err != nil {
			return "", err
		}
		var missing string
		text = variableToken.ReplaceAllStringFunc(text, func(token string) string {
			if token == "$$" {
				return "$"
			}
			v, ok := vars[token]
			if !ok {
				missing = token
			}
			return v
		})
		if missing != "" {
			return "", fmt.Errorf("unresolved variable %s", missing)
		}
		return text, nil
	}
	type planned struct {
		source, destination string
		file                starfile.File
	}
	files := map[string]planned{}
	byInstruction := map[int]Entry{}
	for _, e := range a.Listing.Entries {
		byInstruction[e.Instruction] = e
	}
	writes := []starlark.Value{}
	directories := []string{}
	unresolved := []string{}
	attrs := []starlark.Value{}
	for _, r := range ranges {
		if r.Start < 0 || r.End < r.Start || r.End > len(a.Listing.Code) {
			return nil, fmt.Errorf("nsis: code range out of bounds")
		}
		for pc := r.Start; pc < r.End; pc++ {
			ins := a.Listing.Code[pc]
			p := ins.Operands
			failAt := func(err error) {
				unresolved = append(unresolved, fmt.Sprintf("instruction %d opcode %d: %v", pc, ins.Opcode, err))
			}
			getPath := func(off int32) (string, error) {
				s, e := expand(off)
				if e != nil {
					return "", e
				}
				return guestPath(s, vars["$OUTDIR"])
			}
			switch ins.Opcode {
			case 1: // Return ends this selected straight-line range.
				pc = r.End
			case 6: // progress text
			case 10:
				target, err := getPath(p[0])
				if err != nil {
					failAt(err)
					break
				}
				attrs = append(attrs, planDict(starlark.StringDict{"path": starlark.String(target), "attributes": starlark.MakeUint64(uint64(uint32(p[1])))}))
			case 11:
				target, err := getPath(p[0])
				if err != nil {
					failAt(err)
					break
				}
				directories = append(directories, target)
				if p[1] != 0 {
					vars["$OUTDIR"] = target
				}
			case 62:
				target, err := getPath(p[0])
				if err != nil {
					failAt(err)
					break
				}
				file, err := a.Uninstaller(pc)
				if err != nil {
					failAt(err)
					break
				}
				files[strings.ToLower(target)] = planned{fmt.Sprintf("/uninstallers/%06d", pc), target, file}
			case 20:
				e, ok := byInstruction[pc]
				if !ok {
					return nil, fmt.Errorf("nsis: missing file instruction %d", pc)
				}
				target, err := getPath(p[1])
				if err != nil {
					failAt(err)
					break
				}
				source := MemberName(e)
				files[strings.ToLower(target)] = planned{source, target, a.members[source]}
			case 21, 23:
				target, err := getPath(p[0])
				if err != nil {
					failAt(err)
					break
				}
				pattern := strings.ToLower(strings.ReplaceAll(target, `\`, "/"))
				for k, f := range files {
					name := strings.ToLower(strings.ReplaceAll(f.destination, `\`, "/"))
					matched, err := path.Match(pattern, name)
					if err != nil {
						failAt(err)
						break
					}
					if matched || ins.Opcode == 23 && p[1]&1 != 0 && strings.HasPrefix(name, strings.TrimRight(pattern, "/")+"/") {
						delete(files, k)
					}
				}
			case 25:
				s, err := expand(p[1])
				if err != nil {
					failAt(err)
					break
				}
				length, err := expand(p[2])
				if err != nil {
					failAt(err)
					break
				}
				start, err := expand(p[3])
				if err != nil {
					failAt(err)
					break
				}
				parse := func(s string) (int, error) {
					if s == "" {
						return 0, nil
					}
					n, err := strconv.ParseInt(s, 0, 32)
					return int(n), err
				}
				n, err := parse(length)
				if err != nil {
					failAt(err)
					break
				}
				at, err := parse(start)
				if err != nil {
					failAt(err)
					break
				}
				if at < 0 {
					at = len(s) + at
				}
				at = max(0, min(at, len(s)))
				s = s[at:]
				if n > 0 {
					s = s[:min(n, len(s))]
				} else if n < 0 {
					s = s[:max(0, len(s)+n)]
				}
				if p[0] < 0 {
					failAt(fmt.Errorf("negative variable index"))
					break
				}
				vars[variable(int(p[0]))] = s
			case 46:
				from, err := getPath(p[0])
				if err != nil {
					failAt(err)
					break
				}
				to, err := getPath(p[1])
				if err != nil {
					failAt(err)
					break
				}
				f, ok := files[strings.ToLower(from)]
				if !ok {
					failAt(fmt.Errorf("copy source is not in native plan: %s", from))
					break
				}
				f.destination = to
				files[strings.ToLower(to)] = f
			case 51:
				root := map[uint32]string{0x80000000: "HKEY_CLASSES_ROOT", 0x80000001: "HKEY_CURRENT_USER", 0x80000002: "HKEY_LOCAL_MACHINE"}[uint32(p[0])]
				if root == "" {
					failAt(fmt.Errorf("unsupported registry root"))
					break
				}
				key, err := expand(p[1])
				if err != nil {
					failAt(err)
					break
				}
				name, err := expand(p[2])
				if err != nil {
					failAt(err)
					break
				}
				data, err := expand(p[3])
				if err != nil {
					failAt(err)
					break
				}
				kind := "REG_SZ"
				value := starlark.Value(starlark.String(data))
				switch p[4] {
				case 1:
				case 2:
					kind = "REG_EXPAND_SZ"
				case 4:
					n, err := strconv.ParseInt(data, 0, 64)
					if err != nil {
						failAt(err)
						break
					}
					kind = "REG_DWORD"
					value = starlark.MakeUint64(uint64(uint32(n)))
				default:
					failAt(fmt.Errorf("unsupported registry type %d", p[4]))
				}
				if len(unresolved) > 0 {
					break
				}
				writes = append(writes, planDict(starlark.StringDict{"operation": starlark.String("set_value"), "root": starlark.String(root), "key": starlark.String(key), "name": starlark.String(name), "type": starlark.String(kind), "data": value, "resolved": starlark.True}))
			default:
				failAt(fmt.Errorf("requires control-flow or action semantics; no instruction was executed"))
			}
			if len(unresolved) > 0 {
				break
			} // no guessed writes after an unknown effect
		}
		if len(unresolved) > 0 {
			break
		}
	}
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	output := make([]starlark.Value, 0, len(keys))
	for _, k := range keys {
		f := files[k]
		output = append(output, planDict(starlark.StringDict{"source": starlark.String(f.source), "destination": starlark.String(f.destination), "file": f.file, "resolved": starlark.True, "container": starlark.False, "component": starlark.String("")}))
	}
	result := starlark.StringDict{"format": starlark.String("nsis"), "files": starlark.NewList(output), "unresolved": stringValues(unresolved), "directories": stringValues(directories), "attributes": starlark.NewList(attrs), "definitive_registry_writes": starlark.NewList(writes), "registry_writes": starlark.NewList(writes), "script_evaluation": starlark.None, "explicit_ranges": starlark.Bool(explicit)}
	for _, name := range []string{"registry", "artifacts", "custom_actions", "shortcuts", "target_defaults"} {
		result[name] = starlark.NewList(nil)
	}
	return planDict(result), nil
}
