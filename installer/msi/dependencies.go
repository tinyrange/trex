package msi

import "go.starlark.net/starlark"

// Dependencies describe work whose answer belongs to the target machine.
// They are part of a static plan, not parse errors or permission to execute it.
func (p *planContext) dependency(kind, expression string, declaration starlark.Value) {
	p.runtime = append(p.runtime, record(map[string]starlark.Value{
		"kind": starlark.String(kind), "expression": starlark.String(expression),
		"declaration": declaration,
	}))
}
