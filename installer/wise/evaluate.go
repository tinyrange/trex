package wise

import (
	"fmt"
	"maps"
	"strconv"
	"strings"
)

type wiseEvaluation struct {
	variables  map[string]string
	states     []map[string]string
	active     []bool
	uncertain  []bool
	unresolved []string
}

type wiseBlock struct {
	parentActive    bool
	parentUncertain bool
	matched         bool
	known           bool
	conditional     bool
}

// evaluateWiseScript selects the default path through WiseScript's structured
// condition blocks. It evaluates only value comparisons whose operands are
// known from caller-supplied locations, registry-query fallbacks, and f16
// assignments; uncertain branches remain visible to Plan instead of being
// silently combined.
func evaluateWiseScript(script *wiseScript, variables map[string]string) wiseEvaluation {
	result := wiseEvaluation{
		variables: variables,
		states:    make([]map[string]string, len(script.actions)),
		active:    make([]bool, len(script.actions)),
		uncertain: make([]bool, len(script.actions)),
	}
	blocks := make([]wiseBlock, 0, 16)
	active := true
	uncertain := false
	restore := func() {
		if len(blocks) == 0 {
			active = true
			uncertain = false
			return
		}
		block := blocks[len(blocks)-1]
		if block.conditional {
			if block.known {
				active = block.parentActive && block.matched
				uncertain = block.parentUncertain
			} else {
				active = false
				uncertain = block.parentActive || block.parentUncertain
			}
			return
		}
		active = block.parentActive
		uncertain = block.parentUncertain
	}

	for index, action := range script.actions {
		switch action.opcode {
		case 0x0c:
			matched, known := wiseCondition(action, variables)
			blocks = append(blocks, wiseBlock{
				parentActive: active, parentUncertain: uncertain,
				matched: matched, known: known, conditional: true,
			})
			restore()
			continue
		case 0x0d:
			if len(blocks) != 0 && blocks[len(blocks)-1].conditional {
				block := &blocks[len(blocks)-1]
				if block.known {
					block.matched = !block.matched
				}
				restore()
			}
			continue
		case 0x08:
			if len(action.fixed) != 0 && action.fixed[0] == 0 && len(blocks) != 0 {
				blocks = blocks[:len(blocks)-1]
				restore()
			}
			continue
		}

		result.states[index] = maps.Clone(variables)
		result.active[index] = active
		result.uncertain[index] = uncertain
		if active && action.opcode == 0x09 {
			wiseApplyVariableAction(action, variables)
		}
		// These operations open blocks that are terminated by an EndBlock
		// record with flag zero. Their return value is not statically known,
		// so preserve the parent's selected state while maintaining nesting.
		if (action.opcode == 0x09 && len(action.fixed) != 0 && (action.fixed[0] == 0x0a || action.fixed[0] == 0x4a)) || action.opcode == 0x1c {
			blocks = append(blocks, wiseBlock{parentActive: active, parentUncertain: uncertain})
		}
	}
	return result
}

func wiseCondition(action scriptAction, variables map[string]string) (bool, bool) {
	if len(action.fixed) == 0 || len(action.strings) < 2 {
		return false, false
	}
	left, found := variables[strings.ToUpper(action.strings[0])]
	if !found {
		left = ""
	}
	right, resolved := expandWiseVariables(action.strings[1], variables)
	if !resolved {
		return false, false
	}
	switch action.fixed[0] & 0x0f {
	case 2:
		return strings.Contains(left, right), true
	case 3:
		return !strings.Contains(left, right), true
	case 0:
		return left == right, true
	case 1:
		return left != right, true
	case 4:
		return strings.EqualFold(left, right), true
	case 5:
		return !strings.EqualFold(left, right), true
	case 10:
		// Wise uses this comparison for digit-only registration fields: the
		// value must be non-empty and every character must belong to the
		// supplied character set.
		if left == "" {
			return false, true
		}
		for _, character := range left {
			if !strings.ContainsRune(right, character) {
				return false, true
			}
		}
		return true, true
	default:
		return false, false
	}
}

func wiseApplyVariableAction(action scriptAction, variables map[string]string) {
	if len(action.strings) < 5 || action.strings[0] != "" {
		return
	}
	parts := strings.Split(action.strings[4], "\x7f")
	switch strings.ToLower(action.strings[1]) {
	case "f9":
		if len(parts) >= 5 && parts[1] != "" {
			name := strings.ToUpper(parts[1])
			value, _ := expandWiseVariables(parts[3], variables)
			variables[name] = value
		}
	case "f27":
		if len(parts) >= 5 {
			value, ok := expandWiseVariables(parts[1], variables)
			delimiter, delimiterOK := expandWiseVariables(parts[2], variables)
			if ok && delimiterOK && delimiter != "" {
				before, after, _ := strings.Cut(value, delimiter)
				variables[strings.ToUpper(parts[3])] = before
				variables[strings.ToUpper(parts[4])] = after
			}
		}
	case "f16":
		if len(parts) < 3 || parts[1] == "" {
			return
		}
		name := strings.ToUpper(parts[1])
		if wiseProtectedVariable(name) {
			return
		}
		flags, _ := strconv.Atoi(parts[0])
		if flags&128 != 0 {
			if _, found := variables[name]; found {
				return
			}
		}
		value, _ := expandWiseVariables(parts[2], variables)
		switch flags & 0x1c {
		case 12:
			value = strings.TrimRight(value, `\`)
		case 16, 20:
			// Native image construction accepts long paths. DOS aliases are assigned
			// by the target filesystem, not guessed while evaluating the script.
		}
		if validWiseVariableValue(value) {
			variables[name] = value
		}
	}
}

func (e *wiseEvaluation) unresolvedAction(action scriptAction) {
	e.unresolved = append(e.unresolved, fmt.Sprintf("uncertain WiseScript condition affects %s at %#x", actionName(action.opcode), action.offset))
}
