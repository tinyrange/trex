package installscript

import (
	"encoding/binary"
	"testing"

	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func appendISU8(data []byte, value byte) []byte { return append(data, value) }

func appendISU16(data []byte, value uint16) []byte {
	return binary.LittleEndian.AppendUint16(data, value)
}

func appendISU32(data []byte, value uint32) []byte {
	return binary.LittleEndian.AppendUint32(data, value)
}

func appendISString(data []byte, value string) []byte {
	data = appendISU16(data, uint16(len(value)))
	return append(data, value...)
}

func installScriptFixture() []byte {
	data := make([]byte, installScriptHeaderSize)
	binary.LittleEndian.PutUint32(data, installScriptSignature)

	variablesOffset := len(data)
	data = appendISU16(data, 0) // numbers
	data = appendISU16(data, 0) // objects
	data = appendISU16(data, 0) // strings
	data = appendISU16(data, 0) // string records

	typesOffset := len(data)
	data = appendISU16(data, 0)

	prototypesOffset := len(data)
	data = appendISU16(data, 2)
	data = appendISU8(data, 2) // script function
	data = appendISU8(data, 0)
	data = appendISU16(data, 0)
	data = appendISString(data, "program")
	data = appendISU16(data, 0) // first block
	data = appendISU16(data, 0) // arguments
	data = appendISU8(data, 1)  // DLL function
	data = appendISU8(data, 0)
	data = appendISString(data, "ISRT")
	data = appendISString(data, "_RegSetKeyValue")
	data = appendISU16(data, 0xffff)
	data = appendISU16(data, 3)
	for range 3 {
		data = appendISU8(data, 0)
		data = appendISU8(data, 0)
	}

	blocksOffset := len(data)
	data = appendISU16(data, 1)
	blockOffsetPosition := len(data)
	data = appendISU32(data, 0)
	blockOffset := len(data)
	binary.LittleEndian.PutUint32(data[blockOffsetPosition:], uint32(blockOffset))
	data = appendISU16(data, 3)

	data = appendISU16(data, 34) // function prologue
	data = appendISU16(data, 0)
	data = appendISU8(data, 7)
	declarationsRelativePosition := len(data)
	data = appendISU32(data, 0)

	data = appendISU16(data, 32) // external call
	data = appendISU16(data, 1)
	data = appendISU16(data, 4)
	data = appendISU8(data, 5)
	data = appendISU16(data, 44)
	data = appendISU8(data, 7)
	data = appendISU32(data, 0x80000002)
	data = appendISU8(data, 6)
	data = appendISString(data, `Software\Example`)
	data = appendISU8(data, 6)
	data = appendISString(data, "Installed")

	data = appendISU16(data, 35) // return
	data = appendISU16(data, 0)
	declarationsOffset := len(data)
	data = appendISU16(data, 0)
	data = appendISU16(data, 0)
	data = appendISU16(data, 0)
	data = appendISU16(data, 0)
	binary.LittleEndian.PutUint32(data[declarationsRelativePosition:], uint32(declarationsOffset-declarationsRelativePosition))

	binary.LittleEndian.PutUint32(data[104:], uint32(variablesOffset))
	binary.LittleEndian.PutUint32(data[108:], uint32(prototypesOffset))
	binary.LittleEndian.PutUint32(data[112:], uint32(typesOffset))
	binary.LittleEndian.PutUint32(data[116:], uint32(blocksOffset))
	return data
}

func TestInstallScriptParsesFunctionsAndCalls(t *testing.T) {
	script, err := Open(&starfile.Bytes{Name: "setup.inx", Data: installScriptFixture()})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(script.prototypes), 2; got != want {
		t.Fatalf("functions = %d, want %d", got, want)
	}
	if got, want := script.prototypes[1].name, "_RegSetKeyValue"; got != want {
		t.Fatalf("function name = %q, want %q", got, want)
	}
	calls := script.callsValue()
	if got, want := calls.Len(), 1; got != want {
		t.Fatalf("calls = %d, want %d", got, want)
	}
	strings := script.stringsValue()
	if got, want := strings.Len(), 2; got != want {
		t.Fatalf("strings = %d, want %d", got, want)
	}
	if value, err := script.Attr("functions"); err != nil || value.Type() != "list" {
		t.Fatalf("functions attribute = %v, %v", value, err)
	}
	if _, err := script.Hash(); err == nil {
		t.Fatal("installscript unexpectedly hashable")
	}
	if script.Truth() != starlark.True {
		t.Fatal("installscript is false")
	}
	effects := script.effectsValue()
	registryValue, found, err := effects.Get(starlark.String("registry"))
	if err != nil || !found {
		t.Fatalf("registry effects: found=%v err=%v", found, err)
	}
	registry := registryValue.(*starlark.List)
	if got, want := registry.Len(), 1; got != want {
		t.Fatalf("registry effects = %d, want %d", got, want)
	}
	effect := registry.Index(0).(*starlark.Dict)
	root, found, err := effect.Get(starlark.String("root"))
	if err != nil || !found || string(root.(starlark.String)) != "HKEY_LOCAL_MACHINE" {
		t.Fatalf("registry root = %v, found=%v err=%v", root, found, err)
	}
	evaluated, err := script.evaluateBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	evaluatedRegistry, found, err := evaluated.(*starlark.Dict).Get(starlark.String("registry"))
	if err != nil || !found || evaluatedRegistry.(*starlark.List).Len() != 1 {
		t.Fatalf("evaluated registry = %v, found=%v err=%v", evaluatedRegistry, found, err)
	}
	resolved, found, err := evaluatedRegistry.(*starlark.List).Index(0).(*starlark.Dict).Get(starlark.String("resolved"))
	if err != nil || !found || resolved != starlark.True {
		t.Fatalf("evaluated registry resolved = %v, found=%v err=%v", resolved, found, err)
	}
}

func TestInstallScriptRejectsTruncatedTables(t *testing.T) {
	data := installScriptFixture()
	binary.LittleEndian.PutUint32(data[108:], uint32(len(data)-1))
	if _, err := Open(&starfile.Bytes{Name: "bad.inx", Data: data}); err == nil {
		t.Fatal("truncated prototype table accepted")
	}
}

func TestInstallScriptLogicalAndPathOperators(t *testing.T) {
	known := func(number int32) installScriptValue { return installScriptValue{kind: 5, num: number, known: true} }
	if got := installScriptBinary(24, known(1), known(0)); !got.known || got.num != 1 {
		t.Fatalf("logical OR = %+v", got)
	}
	if got := installScriptBinary(25, known(1), known(0)); !got.known || got.num != 0 {
		t.Fatalf("logical AND = %+v", got)
	}
	left, right := installScriptValue{kind: 4, text: `C:\Program Files`, known: true}, installScriptValue{kind: 4, text: "Example", known: true}
	if got := installScriptBinary(20, left, right); !got.known || got.text != `C:\Program Files\Example` {
		t.Fatalf("path concatenation = %+v", got)
	}
}

func TestInstallScriptProfileWrapperWritesOutput(t *testing.T) {
	script := &Script{
		prototypes: []installScriptPrototype{{name: "wrapper"}, {name: "GetPrivateProfileIntA"}},
		blocks:     []installScriptBlock{{functionID: 0, actions: []installScriptAction{{opcode: 32, functionID: 1}}}},
	}
	operands := []installScriptArgument{{kind: 6, text: "setup.ini"}, {kind: 6, text: "Setup"}, {kind: 6, text: "AppType"}, {kind: 5, address: 31}}
	values := []installScriptValue{{kind: 4, text: "setup.ini", known: true}, {kind: 4, text: "Setup", known: true}, {kind: 4, text: "AppType", known: true}, {kind: 5, num: 101, known: true}}
	state := installScriptEvalState{vars: make(map[installScriptVariable]installScriptValue)}
	profiles := installScriptProfiles{"setup.ini": {"setup": {"apptype": "100"}}}
	script.applyInstallScriptProfileWrapper(0, operands, values, &state, profiles)
	got := state.vars[installScriptVariable{kind: 5, address: 31}]
	if !got.known || got.num != 100 {
		t.Fatalf("profile output = %+v, want 100", got)
	}
}

func TestInstallScriptCallbackEntriesAreCallGraphRoots(t *testing.T) {
	script := &Script{
		prototypes: []installScriptPrototype{
			{name: "root", flags: 2, blockIndex: 0},
			{name: "helper", flags: 2, blockIndex: 1},
			{name: "second_root", flags: 2, blockIndex: 2},
			{name: "External", flags: 1, blockIndex: 0xffff},
		},
		blocks: []installScriptBlock{
			{functionID: 0, actions: []installScriptAction{{opcode: 33, functionID: 1}}},
			{functionID: 1}, {functionID: 2},
		},
	}
	entries := script.installScriptCallbackEntries()
	if len(entries) != 2 || entries[0] != 0 || entries[1] != 2 {
		t.Fatalf("callback entries = %v, want [0 2]", entries)
	}
}

func TestInstallScriptFixedPointIsComplete(t *testing.T) {
	script := &Script{
		prototypes: []installScriptPrototype{{name: "loop", flags: 2, blockIndex: 0}},
		blocks:     []installScriptBlock{{functionID: 0, actions: []installScriptAction{{opcode: 5, target: 0}}}},
	}
	value, err := script.evaluateBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	incomplete, found, err := value.(*starlark.Dict).Get(starlark.String("incomplete"))
	if err != nil || !found || incomplete != starlark.False {
		t.Fatalf("fixed point incomplete = %v, found=%v err=%v", incomplete, found, err)
	}
}

func TestInstallScriptLoopWidensChangingConstants(t *testing.T) {
	script := &Script{
		prototypes: []installScriptPrototype{{name: "loop", flags: 2, blockIndex: 0}},
		blocks: []installScriptBlock{
			{functionID: 0, actions: []installScriptAction{{opcode: 6, operands: []installScriptArgument{{kind: 5, address: -101}, {kind: 7, number: 0}}}}},
			{functionID: 0, actions: []installScriptAction{
				{opcode: 7, operands: []installScriptArgument{{kind: 5, address: -101}, {kind: 5, address: -101}, {kind: 7, number: 1}}},
				{opcode: 5, target: 0},
			}},
		},
	}
	value, err := script.evaluateBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(*starlark.Dict)
	incomplete, _, _ := result.Get(starlark.String("incomplete"))
	steps, _, _ := result.Get(starlark.String("steps"))
	stepCount, _ := starlark.AsInt32(steps)
	if incomplete != starlark.False || stepCount > 8 {
		t.Fatalf("widened loop: incomplete=%v steps=%d", incomplete, stepCount)
	}
}

func TestInstallScriptByteAndSubstringOperations(t *testing.T) {
	script := &Script{
		prototypes: []installScriptPrototype{{name: "strings", flags: 2, blockIndex: 0}},
		blocks: []installScriptBlock{{functionID: 0, actions: []installScriptAction{
			{opcode: 6, operands: []installScriptArgument{{kind: 4, address: 0}, {kind: 6, text: "abcd"}}},
			{opcode: 29, operands: []installScriptArgument{{kind: 4, address: 0}, {kind: 7, number: 1}, {kind: 7, number: 'Z'}}},
			{opcode: 41, operands: []installScriptArgument{{kind: 4, address: 1}, {kind: 4, address: 0}, {kind: 7, number: 1}, {kind: 7, number: 2}}},
			{opcode: 35},
		}}},
	}
	value, err := script.evaluateBuiltin(nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	finalsValue, _, _ := value.(*starlark.Dict).Get(starlark.String("final_globals"))
	finals := finalsValue.(*starlark.List)
	got := make(map[int]string)
	for index := 0; index < finals.Len(); index++ {
		entry := finals.Index(index).(*starlark.Dict)
		addressValue, _, _ := entry.Get(starlark.String("address"))
		value, _, _ := entry.Get(starlark.String("value"))
		address, _ := starlark.AsInt32(addressValue)
		text, _ := starlark.AsString(value)
		got[int(address)] = text
	}
	if got[0] != "aZcd" || got[1] != "Zc" {
		t.Fatalf("string results = %#v, want 0:aZcd and 1:Zc", got)
	}
}

func TestInstallScriptStepBudgetIsPerCallback(t *testing.T) {
	script := &Script{
		prototypes: []installScriptPrototype{
			{name: "first", flags: 2, blockIndex: 0},
			{name: "second", flags: 2, blockIndex: 1},
		},
		blocks: []installScriptBlock{
			{functionID: 0, actions: []installScriptAction{{opcode: 1}, {opcode: 35}}},
			{functionID: 1, actions: []installScriptAction{{opcode: 1}, {opcode: 35}}},
		},
	}
	value, err := script.evaluateBuiltin(nil, nil, nil, []starlark.Tuple{{starlark.String("maximum_steps"), starlark.MakeInt(1)}})
	if err != nil {
		t.Fatal(err)
	}
	stepsValue, _, _ := value.(*starlark.Dict).Get(starlark.String("steps"))
	steps, _ := starlark.AsInt32(stepsValue)
	if steps != 2 {
		t.Fatalf("steps = %d, want one step for each callback", steps)
	}
}
