package x86

import (
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sort"
	"strings"

	binaryapi "github.com/tinyrange/trex/binary"
	windowsapi "github.com/tinyrange/trex/windows"
	"go.starlark.net/starlark"
	"golang.org/x/arch/x86/x86asm"
)

const (
	defaultEmulatorInstructionLimit = 2_000_000
	defaultEmulatorMemoryLimit      = 32 << 20
	defaultEmulatorStackSize        = 1 << 20
	defaultEmulatorCallDepthLimit   = 4096
	emulatorAcceleratedWorkUnit     = 4096
	emulatorAcceleratedChunkSize    = 1 << 20
	emulatorStackTop                = uint32(0x7ff00000)
	emulatorImportBase              = uint32(0xf0000000)
	emulatorAllocationBase          = uint32(0x60000000)
	emulatorVirtualModuleBase       = uint32(0xe0000000)
	emulatorVirtualExportBase       = uint32(0xe8000000)
)

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"plugin": starlark.NewBuiltin("plugin", PluginBuiltin),
		"x86":    starlark.NewBuiltin("x86", Builtin),
	}
}

func PluginBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var install starlark.Callable
	name := "plugin"
	state := starlark.Value(starlark.None)
	var attrs *starlark.Dict
	if err := starlark.UnpackArgs("plugin", args, kwargs, "install", &install, "name?", &name, "state?", &state, "attrs?", &attrs); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("plugin: name must not be empty")
	}
	values := starlark.StringDict{
		"install": install,
		"name":    starlark.String(name),
		"state":   state,
	}
	if attrs != nil {
		for _, item := range attrs.Items() {
			attrName, ok := starlark.AsString(item[0])
			if !ok || attrName == "install" || attrName == "name" || attrName == "state" {
				return nil, fmt.Errorf("plugin: invalid or reserved attribute name %v", item[0])
			}
			values[attrName] = item[1]
		}
	}
	return newStarlarkRecord(values), nil
}

type emulatorMapping struct {
	name       string
	start      uint32
	data       []byte
	readable   bool
	writable   bool
	executable bool
}

type emulatorFreeRange struct {
	start uint32
	size  uint32
}

type emulatorImport struct {
	module  string
	name    string
	ordinal uint16
	iat     uint32
	target  uint32
}

type emulatorImportNameKey struct {
	module string
	name   string
}

type emulatorImportOrdinalKey struct {
	module  string
	ordinal uint16
}

func (i emulatorImport) displayName() string {
	if i.name != "" {
		return i.name
	}
	return fmt.Sprintf("#%d", i.ordinal)
}

type emulatorHook struct {
	module     string
	name       string
	address    uint32
	argc       int
	convention string
	callback   starlark.Callable
}

type emulatorHookRule struct {
	module     string
	name       string
	ordinal    uint16
	argc       int
	convention string
	callback   starlark.Callable
}

type emulatorModuleExport struct {
	address   uint32
	forwarder string
}

type emulatorModule struct {
	name     string
	base     uint32
	entry    uint32
	primary  bool
	exports  map[string]emulatorModuleExport
	ordinals map[uint32]emulatorModuleExport
}

type emulatorCRC32Loop struct {
	kind               emulatorCRC32LoopKind
	inputDisplacement  int8
	crcDisplacement    int8
	lengthDisplacement int8
	table              uint32
}

type emulatorLoopAcceleration struct {
	start               uint32
	end                 uint32
	maximumInstructions uint64
	instructionCount    uint64
	pattern             []byte
}

type emulatorRegionAcceleration struct {
	entry               uint32
	start               uint32
	end                 uint32
	reenter             bool
	maximumInstructions uint64
	digest              [sha256.Size]byte
}

type emulatorRewrite struct {
	start    uint32
	end      uint32
	name     string
	pattern  []byte
	callback starlark.Callable
	region   *emulatorRegionAcceleration
}

type emulatorTransformation struct {
	name                string
	anchor              []byte
	anchorMask          []byte
	size                uint32
	digest              [sha256.Size]byte
	normalizeRelative   bool
	callback            starlark.Callable
	runtimeRegion       bool
	entryOffset         uint32
	reenter             bool
	maximumInstructions uint64
}

type emulatorTransformationMatch struct {
	index     int
	ambiguous bool
}

type emulatorCRC32LoopKind uint8

const (
	emulatorCRC32LoopReflected emulatorCRC32LoopKind = iota
	emulatorCRC32LoopMSB
)

type emulatorAccelerator uint8

const (
	emulatorAcceleratorUnchecked emulatorAccelerator = iota
	emulatorAcceleratorNone
	emulatorAcceleratorZeroByteScan
	emulatorAcceleratorWideUnitScan
	emulatorAcceleratorBoundedWideScan
	emulatorAcceleratorBoundedWideCopy
	emulatorAcceleratorMixedASCIIFoldCompare
	emulatorAcceleratorASCIILower
	emulatorAcceleratorWideASCIIValidate
	emulatorAcceleratorWideASCIICompare
	emulatorAcceleratorCRC32
	emulatorAcceleratorI16DotProduct
	emulatorAcceleratorI16BitExtractDotProduct
	emulatorAcceleratorLinkedListReverse
	emulatorAcceleratorCRC16BitLoop
	emulatorAcceleratorI16LinkedListSearch
	emulatorAcceleratorU8LinkedListSearch
	emulatorAcceleratorRegisterCRC32
)

type emulatorRegisterFile [256]uint32
type emulatorDecodedPage struct {
	instructions [4096]*x86asm.Inst
	accelerators [4096]emulatorAccelerator
}

type emulatorDecodedEntry struct {
	address     uint32
	instruction *x86asm.Inst
}

type emulatorCPUContext struct {
	registers      emulatorRegisterFile
	eip            uint32
	callDepth      int
	callFrames     []emulatorCallFrame
	zero           bool
	carry          bool
	parity         bool
	sign           bool
	overflow       bool
	direction      bool
	x87ControlWord uint16
	x87StatusWord  uint16
	x87Stack       [8]float64
	x87Top         int
	x87Depth       int
	exceptionHead  uint32
}

type emulatorExecution struct {
	machine   *emulatorX86
	context   emulatorCPUContext
	stackSlot int
	done      bool
	closed    bool
	result    starlark.Value
	frozen    bool
}

type emulatorCheckpointDict struct {
	value *starlark.Dict
	items []starlark.Tuple
}

type emulatorCheckpointList struct {
	value *starlark.List
	items []starlark.Value
}

type emulatorCheckpointSet struct {
	value *starlark.Set
	items []starlark.Value
}

type emulatorCheckpointExecution struct {
	value    *emulatorExecution
	snapshot emulatorExecution
}

// emulatorCheckpoint retains the identities of mutable Starlark containers.
// Restoring them in place is important: installed hook callbacks close over
// those containers, so replacing them would leave the callbacks attached to
// state from after the checkpoint.
type emulatorCheckpoint struct {
	owner      *emulatorX86
	machine    *emulatorX86
	dicts      []emulatorCheckpointDict
	lists      []emulatorCheckpointList
	sets       []emulatorCheckpointSet
	executions []emulatorCheckpointExecution
}

func (c *emulatorCheckpoint) String() string {
	return fmt.Sprintf("<emulator.checkpoint mapped=%d states=%d>", c.machine.mappedBytes, len(c.dicts)+len(c.lists)+len(c.sets))
}
func (c *emulatorCheckpoint) Type() string          { return "emulator.checkpoint" }
func (c *emulatorCheckpoint) Freeze()               {}
func (c *emulatorCheckpoint) Truth() starlark.Bool  { return starlark.True }
func (c *emulatorCheckpoint) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", c.Type()) }

type emulatorCallFrame struct {
	site   uint32
	target uint32
}

type emulatorMemoryWrite struct {
	eip     uint32
	address uint32
	before  []byte
	after   []byte
}

type emulatorMemoryWatch struct {
	id      uint64
	start   uint32
	size    uint64
	limit   int
	entries []emulatorMemoryWrite
	cursor  int
	dropped uint64
}

type emulatorMemoryProtection struct {
	start      uint32
	size       uint64
	readable   bool
	writable   bool
	executable bool
}

type emulatorCodeEntry struct {
	address     uint32
	eax         uint32
	ebx         uint32
	ecx         uint32
	edx         uint32
	esi         uint32
	edi         uint32
	esp         uint32
	ebp         uint32
	eflags      uint32
	stack       []byte
	captures    map[string][]byte
	instruction string
}

type emulatorCodeCapture struct {
	name        string
	base        x86asm.Reg
	offset      int
	dereference int
	size        int
}

type emulatorCodeWatch struct {
	id         uint64
	start      uint32
	size       uint64
	limit      int
	stackBytes int
	captures   []emulatorCodeCapture
	entries    []emulatorCodeEntry
	cursor     int
	dropped    uint64
}

func callFrameSummary(frames []emulatorCallFrame, limit int) string {
	counts := make(map[emulatorCallFrame]int)
	for _, frame := range frames {
		counts[frame]++
	}
	type countedFrame struct {
		emulatorCallFrame
		count int
	}
	ordered := make([]countedFrame, 0, len(counts))
	for frame, count := range counts {
		ordered = append(ordered, countedFrame{emulatorCallFrame: frame, count: count})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].count != ordered[j].count {
			return ordered[i].count > ordered[j].count
		}
		if ordered[i].site != ordered[j].site {
			return ordered[i].site < ordered[j].site
		}
		return ordered[i].target < ordered[j].target
	})
	if limit > len(ordered) {
		limit = len(ordered)
	}
	output := make([]string, limit)
	for index, frame := range ordered[:limit] {
		output[index] = fmt.Sprintf("0x%08x->0x%08x:%d", frame.site, frame.target, frame.count)
	}
	return strings.Join(output, ",")
}

type emulatorX86 struct {
	mappings            []emulatorMapping
	mappingCache        [2]int
	registers           emulatorRegisterFile
	eip                 uint32
	entry               uint32
	exports             map[string]uint32
	imports             map[uint32]emulatorImport
	importsByName       map[emulatorImportNameKey][]uint32
	importsByOrdinal    map[emulatorImportOrdinalKey][]uint32
	indexedImports      int
	importValuesCache   *starlark.List
	hooks               map[uint32]emulatorHook
	hookRules           []emulatorHookRule
	modules             map[string]*emulatorModule
	moduleValuesCache   *starlark.List
	attrCache           starlark.StringDict
	decoded             map[uint32]*x86asm.Inst
	decodedEntries      []emulatorDecodedEntry
	decodedCursor       int
	decodedLimit        int
	decodedPages        map[uint32]*emulatorDecodedPage
	decodedPage         *emulatorDecodedPage
	decodedPageNumber   uint32
	cachedCodePages     map[uint32]bool
	crcLoops            map[uint32]*emulatorCRC32Loop
	crcLoopsChecked     map[uint32]bool
	loopAccelerations   map[uint32]emulatorLoopAcceleration
	regionAccelerations map[uint32]emulatorRegionAcceleration
	runtimeRegions      map[uint32]emulatorRegionAcceleration
	rewrites            map[uint32]emulatorRewrite
	transformations     []emulatorTransformation
	transformationCache map[uint32]emulatorTransformationMatch
	wideCompare         map[uint32]bool
	wideCompareChecked  map[uint32]bool
	asciiLower          map[uint32]bool
	asciiLowerChecked   map[uint32]bool
	mixedCompare        map[uint32]bool
	mixedCompareChecked map[uint32]bool
	zeroByteScan        map[uint32]bool
	zeroByteScanChecked map[uint32]bool
	instructionLimit    uint64
	callDepthLimit      int
	callDepth           int
	callFrames          []emulatorCallFrame
	callTrace           bool
	callTraceLimit      int
	callTraceEntries    []emulatorCallFrame
	callTraceCursor     int
	callTraceDropped    uint64
	callTraceStart      uint32
	callTraceSize       uint64
	memoryLimit         int64
	mappedBytes         int64
	nextAllocation      uint32
	allocations         map[uint32]bool
	freeAllocations     []emulatorFreeRange
	nextVirtualExport   uint32
	segmentBases        emulatorRegisterFile
	stackLow            uint32
	stackHigh           uint32
	zero                bool
	carry               bool
	parity              bool
	sign                bool
	overflow            bool
	direction           bool
	x87ControlWord      uint16
	x87StatusWord       uint16
	x87Stack            [8]float64
	x87Top              int
	x87Depth            int
	trace               bool
	traceLimit          int
	traceEntries        []starlark.Value
	traceCursor         int
	profile             bool
	profileInterval     uint64
	profileLimit        int
	profileOperations   uint64
	profileSamples      uint64
	profileDropped      uint64
	profileCounts       map[uint32]uint64
	timestampCounter    uint64
	recentEIPs          [64]uint32
	recentEIPCount      int
	recentEIPCursor     int
	currentInstruction  uint32
	memoryWatches       map[uint64]*emulatorMemoryWatch
	nextMemoryWatch     uint64
	protections         []emulatorMemoryProtection
	codeWatches         map[uint64]*emulatorCodeWatch
	nextCodeWatch       uint64
	pendingTransfer     bool
	pendingStop         string
	pendingStopDetail   string
	hookDepth           int
	invokeDepth         int
	stackSlots          map[int]bool
	invokeStackSlots    []int
	executions          map[*emulatorExecution]bool
	pluginStates        []starlark.Value
	exceptionHandler    starlark.Callable
	frozen              bool
}

type emulatorMemoryError struct {
	address    uint32
	permission byte
	detail     string
}

func (e *emulatorMemoryError) Error() string { return e.detail }

func Builtin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	imageValue := starlark.Value(starlark.None)
	codeValue := starlark.Value(starlark.None)
	entryValue := starlark.Value(starlark.None)
	base := 0x1000
	instructionLimit := defaultEmulatorInstructionLimit
	memoryLimit := defaultEmulatorMemoryLimit
	stackSize := defaultEmulatorStackSize
	callDepthLimit := defaultEmulatorCallDepthLimit
	trace := false
	traceLimit := 4096
	profile := false
	profileInterval := 256
	profileLimit := 16384
	imageName := "main"
	fsBase := 0
	segmentSize := 4096
	if err := starlark.UnpackArgs(
		"x86", args, kwargs,
		"image?", &imageValue,
		"code?", &codeValue,
		"base?", &base,
		"entry?", &entryValue,
		"instruction_limit?", &instructionLimit,
		"memory_limit?", &memoryLimit,
		"stack_size?", &stackSize,
		"call_depth_limit?", &callDepthLimit,
		"trace?", &trace,
		"trace_limit?", &traceLimit,
		"profile?", &profile,
		"profile_interval?", &profileInterval,
		"profile_limit?", &profileLimit,
		"image_name?", &imageName,
		"fs_base?", &fsBase,
		"segment_size?", &segmentSize,
	); err != nil {
		return nil, err
	}
	if (imageValue == starlark.None) == (codeValue == starlark.None) {
		return nil, fmt.Errorf("x86: provide exactly one of image or code")
	}
	if base < 0 || instructionLimit <= 0 || memoryLimit <= 0 || stackSize <= 0 || stackSize > memoryLimit || uint64(stackSize) >= uint64(emulatorStackTop) || callDepthLimit <= 0 || fsBase < 0 || segmentSize <= 0 || traceLimit <= 0 || traceLimit > 65536 || profileInterval <= 0 || profileInterval > 1<<20 || profileLimit <= 0 || profileLimit > 65536 {
		return nil, fmt.Errorf("x86: invalid base or resource budget")
	}
	machine := &emulatorX86{
		mappingCache:        [2]int{-1, -1},
		exports:             make(map[string]uint32),
		imports:             make(map[uint32]emulatorImport),
		importsByName:       make(map[emulatorImportNameKey][]uint32),
		importsByOrdinal:    make(map[emulatorImportOrdinalKey][]uint32),
		hooks:               make(map[uint32]emulatorHook),
		modules:             make(map[string]*emulatorModule),
		attrCache:           make(starlark.StringDict),
		decoded:             make(map[uint32]*x86asm.Inst),
		decodedLimit:        1 << 18,
		decodedPages:        make(map[uint32]*emulatorDecodedPage),
		cachedCodePages:     make(map[uint32]bool),
		crcLoops:            make(map[uint32]*emulatorCRC32Loop),
		crcLoopsChecked:     make(map[uint32]bool),
		loopAccelerations:   make(map[uint32]emulatorLoopAcceleration),
		regionAccelerations: make(map[uint32]emulatorRegionAcceleration),
		runtimeRegions:      make(map[uint32]emulatorRegionAcceleration),
		rewrites:            make(map[uint32]emulatorRewrite),
		transformationCache: make(map[uint32]emulatorTransformationMatch),
		wideCompare:         make(map[uint32]bool),
		wideCompareChecked:  make(map[uint32]bool),
		asciiLower:          make(map[uint32]bool),
		asciiLowerChecked:   make(map[uint32]bool),
		mixedCompare:        make(map[uint32]bool),
		mixedCompareChecked: make(map[uint32]bool),
		zeroByteScan:        make(map[uint32]bool),
		zeroByteScanChecked: make(map[uint32]bool),
		instructionLimit:    uint64(instructionLimit),
		callDepthLimit:      callDepthLimit,
		callTraceLimit:      4096,
		memoryLimit:         int64(memoryLimit),
		nextAllocation:      emulatorAllocationBase,
		allocations:         make(map[uint32]bool),
		nextVirtualExport:   emulatorVirtualExportBase,
		stackSlots:          make(map[int]bool),
		executions:          make(map[*emulatorExecution]bool),
		x87ControlWord:      0x037f,
		trace:               trace,
		traceLimit:          traceLimit,
		profile:             profile,
		profileInterval:     uint64(profileInterval),
		profileLimit:        profileLimit,
		profileCounts:       make(map[uint32]uint64),
		memoryWatches:       make(map[uint64]*emulatorMemoryWatch),
		nextMemoryWatch:     1,
		codeWatches:         make(map[uint64]*emulatorCodeWatch),
		nextCodeWatch:       1,
	}
	if imageValue != starlark.None {
		if _, err := machine.mapPE(imageValue, imageName, true); err != nil {
			return nil, fmt.Errorf("x86: %w", err)
		}
	} else {
		code, err := bytesForBinaryValue(codeValue)
		if err != nil {
			return nil, fmt.Errorf("x86: code: %w", err)
		}
		if err := machine.addMapping("code", uint32(base), bytes.Clone(code), true, false, true); err != nil {
			return nil, err
		}
		machine.entry = uint32(base)
	}
	if fsBase != 0 {
		if uint64(fsBase)+uint64(segmentSize) > uint64(math.MaxUint32)+1 {
			return nil, fmt.Errorf("x86: FS segment mapping overflows")
		}
		machine.segmentBases[x86asm.FS] = uint32(fsBase)
		if err := machine.addMapping("fs", uint32(fsBase), make([]byte, segmentSize), true, true, false); err != nil {
			return nil, err
		}
	}
	if entryValue != starlark.None {
		entry, err := starlark.AsInt32(entryValue)
		if err != nil || entry < 0 {
			return nil, fmt.Errorf("x86: entry must be a non-negative int")
		}
		machine.entry = uint32(entry)
	}
	stackTop := emulatorStackTop
	stackLength := uint32(stackSize)
	for {
		stackStart := stackTop - stackLength
		moved := false
		for _, mapping := range machine.mappings {
			mappingEnd := uint64(mapping.start) + uint64(len(mapping.data))
			if uint64(stackStart) < mappingEnd && uint64(mapping.start) < uint64(stackTop) {
				if mapping.start < stackLength {
					return nil, fmt.Errorf("x86: no address range available for stack")
				}
				stackTop = mapping.start &^ 0xfff
				moved = true
				break
			}
		}
		if !moved {
			break
		}
	}
	stackStart := stackTop - stackLength
	if err := machine.addMapping("stack", stackStart, make([]byte, stackSize), true, true, false); err != nil {
		return nil, err
	}
	machine.registers[x86asm.ESP] = stackTop
	machine.registers[x86asm.EBP] = stackTop
	machine.stackLow = stackStart
	machine.stackHigh = stackTop
	machine.eip = machine.entry
	return machine, nil
}

func (m *emulatorX86) mapPE(value starlark.Value, name string, primary bool) (*emulatorModule, error) {
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, fmt.Errorf("image: %w", err)
	}
	image, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("PE: %w", err)
	}
	defer image.Close()
	optional, ok := image.OptionalHeader.(*pe.OptionalHeader32)
	if !ok {
		return nil, fmt.Errorf("only PE32 images are supported")
	}
	if optional.SizeOfImage == 0 || int64(optional.SizeOfImage) > m.memoryLimit {
		return nil, fmt.Errorf("PE image size %d exceeds memory budget", optional.SizeOfImage)
	}
	mapped := make([]byte, optional.SizeOfImage)
	headerSize := min(int(optional.SizeOfHeaders), len(data), len(mapped))
	copy(mapped, data[:headerSize])
	for _, section := range image.Sections {
		sectionData, err := peSectionDataForMapping(data, section)
		if err != nil {
			return nil, fmt.Errorf("PE section %s: %w", section.Name, err)
		}
		start := int(section.VirtualAddress)
		if start < 0 || start > len(mapped) || len(sectionData) > len(mapped)-start {
			return nil, fmt.Errorf("PE section %s exceeds virtual image", section.Name)
		}
		copy(mapped[start:], sectionData)
	}
	base, err := m.peImageBase(optional.ImageBase, optional.SizeOfImage)
	if err != nil {
		return nil, err
	}
	if err := relocatePE32Image(mapped, optional, base); err != nil {
		return nil, fmt.Errorf("PE: %w", err)
	}
	canonicalName := canonicalEmulatorModuleName(name)
	if canonicalName == "" {
		return nil, fmt.Errorf("module name must not be empty")
	}
	if existing := m.modules[canonicalName]; existing != nil {
		return existing, nil
	}
	if err := m.addMapping("module:"+canonicalName, base, mapped, true, true, true); err != nil {
		return nil, err
	}
	module := &emulatorModule{name: canonicalName, base: base, entry: base + optional.AddressOfEntryPoint, primary: primary, exports: make(map[string]emulatorModuleExport), ordinals: make(map[uint32]emulatorModuleExport)}
	m.modules[canonicalName] = module
	m.moduleValuesCache = nil
	if primary {
		m.entry = base + optional.AddressOfEntryPoint
	}

	imports, err := windowsapi.PEImports(data)
	if err != nil {
		return nil, err
	}
	for _, item := range imports {
		target := emulatorImportBase + uint32(len(m.imports))*16
		entry := emulatorImport{module: canonicalEmulatorModuleName(item.DLL), name: item.Name, ordinal: item.Ordinal, iat: base + item.IATRVA, target: target}
		m.imports[target] = entry
		m.importValuesCache = nil
		m.indexImport(target, entry)
		m.applyHookRules(target, entry)
		if err := m.writeUint32(entry.iat, target); err != nil {
			return nil, fmt.Errorf("map import %s!%s: %w", item.DLL, item.Name, err)
		}
	}
	exports, err := windowsapi.PEExports(data)
	if err != nil {
		return nil, err
	}
	for _, item := range exports {
		export := emulatorModuleExport{address: base + item.RVA, forwarder: item.Forwarder}
		module.ordinals[item.Ordinal] = export
		if item.Name != "" {
			module.exports[strings.ToLower(item.Name)] = export
			if primary && item.Forwarder == "" {
				m.exports[strings.ToLower(item.Name)] = export.address
			}
		}
	}
	if err := m.relinkImports(); err != nil {
		return nil, err
	}
	return module, nil
}

// peSectionDataForMapping returns the bytes the Windows image loader maps for
// a section. Some signed legacy images omit the final file-alignment padding
// from the last section while retaining its aligned SizeOfRawData. The Go PE
// reader quite reasonably reports EOF for that layout, but Windows accepts it
// when every byte in VirtualSize is present and zero-fills the absent padding.
func peSectionDataForMapping(data []byte, section *pe.Section) ([]byte, error) {
	rawStart := uint64(section.Offset)
	rawSize := uint64(section.Size)
	if rawSize == 0 {
		return nil, nil
	}
	if rawStart > uint64(len(data)) {
		return nil, io.ErrUnexpectedEOF
	}
	available := min(rawSize, uint64(len(data))-rawStart)
	required := rawSize
	if virtualSize := uint64(section.VirtualSize); virtualSize != 0 {
		required = min(required, virtualSize)
	}
	if available < required {
		return nil, io.ErrUnexpectedEOF
	}
	return data[int(rawStart):int(rawStart+available)], nil
}

func (m *emulatorX86) peImageBase(preferred, size uint32) (uint32, error) {
	if m.mappingRangeAvailable(preferred, size) {
		return preferred, nil
	}
	const (
		first = uint64(0x10000000)
		limit = uint64(emulatorAllocationBase)
		align = uint64(0x10000)
	)
	for candidate := first; candidate+uint64(size) <= limit; {
		next := candidate
		for _, mapping := range m.mappings {
			mappingStart := uint64(mapping.start)
			mappingEnd := mappingStart + uint64(len(mapping.data))
			if candidate < mappingEnd && mappingStart < candidate+uint64(size) {
				next = (mappingEnd + align - 1) &^ (align - 1)
				break
			}
		}
		if next == candidate {
			return uint32(candidate), nil
		}
		candidate = next
	}
	return 0, fmt.Errorf("PE image size %d has no available address range", size)
}

func (m *emulatorX86) mappingRangeAvailable(start, size uint32) bool {
	end := uint64(start) + uint64(size)
	if size == 0 || end > uint64(math.MaxUint32)+1 {
		return false
	}
	for _, mapping := range m.mappings {
		mappingEnd := uint64(mapping.start) + uint64(len(mapping.data))
		if uint64(start) < mappingEnd && uint64(mapping.start) < end {
			return false
		}
	}
	return true
}

func relocatePE32Image(mapped []byte, optional *pe.OptionalHeader32, base uint32) error {
	if base == optional.ImageBase {
		return nil
	}
	directory := optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	if directory.VirtualAddress == 0 || directory.Size < 8 {
		return fmt.Errorf("image at preferred base 0x%08x cannot be relocated to 0x%08x", optional.ImageBase, base)
	}
	start := uint64(directory.VirtualAddress)
	end := start + uint64(directory.Size)
	if end > uint64(len(mapped)) {
		return fmt.Errorf("base relocation directory exceeds virtual image")
	}
	delta := base - optional.ImageBase
	for cursor := start; cursor < end; {
		if end-cursor < 8 {
			return fmt.Errorf("truncated base relocation block")
		}
		page := binary.LittleEndian.Uint32(mapped[cursor : cursor+4])
		blockSize := uint64(binary.LittleEndian.Uint32(mapped[cursor+4 : cursor+8]))
		if blockSize < 8 || blockSize > end-cursor || (blockSize-8)%2 != 0 {
			return fmt.Errorf("invalid base relocation block size %d", blockSize)
		}
		for entryOffset := cursor + 8; entryOffset < cursor+blockSize; entryOffset += 2 {
			entry := binary.LittleEndian.Uint16(mapped[entryOffset : entryOffset+2])
			typ := entry >> 12
			target := uint64(page) + uint64(entry&0x0fff)
			switch typ {
			case 0: // IMAGE_REL_BASED_ABSOLUTE padding.
				continue
			case 3: // IMAGE_REL_BASED_HIGHLOW for PE32.
				if target+4 > uint64(len(mapped)) {
					return fmt.Errorf("base relocation target 0x%x exceeds virtual image", target)
				}
				value := binary.LittleEndian.Uint32(mapped[target : target+4])
				binary.LittleEndian.PutUint32(mapped[target:target+4], value+delta)
			default:
				return fmt.Errorf("unsupported PE32 base relocation type %d", typ)
			}
		}
		cursor += blockSize
	}
	return nil
}

func (m *emulatorX86) relinkImports() error {
	for _, imported := range m.imports {
		address := m.resolveExport(imported.module, imported.name, uint32(imported.ordinal), 0)
		if address == 0 {
			continue
		}
		if err := m.writeUint32(imported.iat, address); err != nil {
			return fmt.Errorf("link import %s!%s: %w", imported.module, imported.name, err)
		}
	}
	return nil
}

func (m *emulatorX86) indexImport(target uint32, imported emulatorImport) {
	module := canonicalEmulatorModuleName(imported.module)
	if imported.name != "" {
		key := emulatorImportNameKey{module: module, name: strings.ToLower(imported.name)}
		m.importsByName[key] = append(m.importsByName[key], target)
	} else {
		key := emulatorImportOrdinalKey{module: module, ordinal: imported.ordinal}
		m.importsByOrdinal[key] = append(m.importsByOrdinal[key], target)
	}
	m.indexedImports++
}

func (m *emulatorX86) rebuildImportIndexes() {
	m.importsByName = make(map[emulatorImportNameKey][]uint32)
	m.importsByOrdinal = make(map[emulatorImportOrdinalKey][]uint32)
	m.indexedImports = 0
	for target, imported := range m.imports {
		m.indexImport(target, imported)
	}
}

func (m *emulatorX86) relinkProvidedExport(module, name string, ordinal uint32, address uint32) error {
	if m.indexedImports != len(m.imports) {
		m.rebuildImportIndexes()
	}
	module = canonicalEmulatorModuleName(module)
	var targets []uint32
	if name != "" {
		targets = m.importsByName[emulatorImportNameKey{module: module, name: strings.ToLower(name)}]
	} else if ordinal <= math.MaxUint16 {
		targets = m.importsByOrdinal[emulatorImportOrdinalKey{module: module, ordinal: uint16(ordinal)}]
	}
	for _, target := range targets {
		imported := m.imports[target]
		if err := m.writeUint32(imported.iat, address); err != nil {
			return fmt.Errorf("link import %s!%s: %w", imported.module, imported.displayName(), err)
		}
	}
	return nil
}

func canonicalEmulatorModuleName(name string) string {
	name = strings.ReplaceAll(strings.TrimSpace(name), `\`, "/")
	if slash := strings.LastIndexByte(name, '/'); slash >= 0 {
		name = name[slash+1:]
	}
	name = strings.ToLower(name)
	if name != "" && !strings.Contains(name, ".") {
		name += ".dll"
	}
	return name
}

func (m *emulatorX86) addMapping(name string, start uint32, data []byte, readable, writable, executable bool) error {
	if len(data) == 0 {
		return fmt.Errorf("emulator: mapping %q is empty", name)
	}
	end := uint64(start) + uint64(len(data))
	if end > uint64(math.MaxUint32)+1 {
		return fmt.Errorf("emulator: mapping %q overflows address space", name)
	}
	if int64(len(data)) > m.memoryLimit-m.mappedBytes {
		return fmt.Errorf("emulator: memory limit %d exceeded", m.memoryLimit)
	}
	for _, mapping := range m.mappings {
		mappingEnd := uint64(mapping.start) + uint64(len(mapping.data))
		if uint64(start) < mappingEnd && uint64(mapping.start) < end {
			return fmt.Errorf("emulator: mapping %q overlaps %q", name, mapping.name)
		}
	}
	m.mappings = append(m.mappings, emulatorMapping{name: name, start: start, data: data, readable: readable, writable: writable, executable: executable})
	m.mappedBytes += int64(len(data))
	sort.Slice(m.mappings, func(i, j int) bool { return m.mappings[i].start < m.mappings[j].start })
	m.mappingCache = [2]int{-1, -1}
	return nil
}

func (m *emulatorX86) mapping(address uint32, size int, permission byte) (*emulatorMapping, int, error) {
	if size >= 0 && uint64(address)+uint64(size) <= uint64(math.MaxUint32)+1 {
		index := m.mappingCache[0]
		if index >= 0 && index < len(m.mappings) {
			mapping := &m.mappings[index]
			if address >= mapping.start {
				offset := uint64(address - mapping.start)
				if offset+uint64(size) <= uint64(len(mapping.data)) && !m.protectionMayOverlap(address, size) &&
					(permission == 'r' && mapping.readable || permission == 'w' && mapping.writable || permission == 'x' && mapping.executable) {
					return mapping, int(offset), nil
				}
			}
		}
		index = m.mappingCache[1]
		if index >= 0 && index < len(m.mappings) {
			mapping := &m.mappings[index]
			if address >= mapping.start {
				offset := uint64(address - mapping.start)
				if offset+uint64(size) <= uint64(len(mapping.data)) && !m.protectionMayOverlap(address, size) &&
					(permission == 'r' && mapping.readable || permission == 'w' && mapping.writable || permission == 'x' && mapping.executable) {
					m.mappingCache[0], m.mappingCache[1] = m.mappingCache[1], m.mappingCache[0]
					return mapping, int(offset), nil
				}
			}
		}
	}
	return m.mappingSlow(address, size, permission)
}

func (m *emulatorX86) protectionMayOverlap(address uint32, size int) bool {
	if len(m.protections) == 0 || size <= 0 {
		return false
	}
	start := uint64(address)
	end := start + uint64(size)
	index := sort.Search(len(m.protections), func(index int) bool {
		protection := m.protections[index]
		return uint64(protection.start)+protection.size > start
	})
	return index < len(m.protections) && uint64(m.protections[index].start) < end
}

func (m *emulatorX86) mappingSlow(address uint32, size int, permission byte) (*emulatorMapping, int, error) {
	if size < 0 || uint64(address)+uint64(size) > uint64(math.MaxUint32)+1 {
		return nil, 0, &emulatorMemoryError{address: address, permission: permission, detail: "invalid memory range"}
	}
	// Mappings are sorted and cannot overlap. Locate the final mapping whose
	// start does not exceed the requested address, then validate its end.
	low, high := 0, len(m.mappings)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if m.mappings[middle].start <= address {
			low = middle + 1
		} else {
			high = middle
		}
	}
	if low != 0 {
		mapping := &m.mappings[low-1]
		offset := uint64(address - mapping.start)
		if offset+uint64(size) <= uint64(len(mapping.data)) {
			end := uint64(address) + uint64(size)
			cursor := uint64(address)
			for cursor < end {
				readable, writable, executable := mapping.readable, mapping.writable, mapping.executable
				next := end
				for _, protection := range m.protections {
					protectionStart := uint64(protection.start)
					protectionEnd := protectionStart + protection.size
					if protectionEnd <= cursor {
						continue
					}
					if protectionStart > cursor {
						next = min(next, protectionStart)
						break
					}
					readable, writable, executable = protection.readable, protection.writable, protection.executable
					next = min(next, protectionEnd)
					break
				}
				allowed := permission == 'r' && readable || permission == 'w' && writable || permission == 'x' && executable
				if !allowed {
					return nil, 0, &emulatorMemoryError{address: uint32(cursor), permission: permission, detail: fmt.Sprintf("memory at 0x%08x lacks %c permission", cursor, permission)}
				}
				cursor = next
			}
			m.mappingCache[1] = m.mappingCache[0]
			m.mappingCache[0] = low - 1
			return mapping, int(offset), nil
		}
	}
	return nil, 0, &emulatorMemoryError{address: address, permission: permission, detail: fmt.Sprintf("unmapped memory at 0x%08x", address)}
}

func (m *emulatorX86) readMemory(address uint32, size int, permission byte) ([]byte, error) {
	mapping, offset, err := m.mapping(address, size, permission)
	if err != nil {
		return nil, err
	}
	return mapping.data[offset : offset+size], nil
}

func invalidateOverlappingCache[T any](cache map[uint32]T, address uint32, size int, maximumWidth uint64) {
	if len(cache) == 0 || size <= 0 {
		return
	}
	end := uint64(address) + uint64(size)
	start := uint64(0)
	if uint64(address)+1 > maximumWidth {
		start = uint64(address) + 1 - maximumWidth
	}
	if end-start < uint64(len(cache)) {
		for candidate := start; candidate < end; candidate++ {
			key := uint32(candidate)
			if _, cached := cache[key]; cached {
				delete(cache, key)
			}
		}
		return
	}
	for candidate := range cache {
		candidateEnd := uint64(candidate) + maximumWidth
		if uint64(candidate) < end && uint64(address) < candidateEnd {
			delete(cache, candidate)
		}
	}
}

func (m *emulatorX86) writeMemory(address uint32, data []byte) error {
	mapping, offset, err := m.mapping(address, len(data), 'w')
	if err != nil {
		return err
	}
	m.recordMemoryWrites(address, mapping.data[offset:offset+len(data)], data)
	copy(mapping.data[offset:], data)
	if m.rangeMayExecute(address, len(data), mapping) {
		clear(m.transformationCache)
		clear(m.runtimeRegions)
		writeEnd := uint64(address) + uint64(len(data))
		for start, loop := range m.loopAccelerations {
			if uint64(start) < writeEnd && uint64(address) < uint64(loop.end) {
				delete(m.loopAccelerations, start)
			}
		}
		for entry, region := range m.regionAccelerations {
			if uint64(region.start) < writeEnd && uint64(address) < uint64(region.end) {
				delete(m.regionAccelerations, entry)
			}
		}
		for start, rewrite := range m.rewrites {
			if uint64(start) < writeEnd && uint64(address) < uint64(rewrite.end) {
				delete(m.rewrites, start)
			}
		}
		if m.cachedCodeMayOverlap(address, len(data)) {
			m.invalidateDecodedCache(address, len(data))
			invalidateOverlappingCache(m.crcLoopsChecked, address, len(data), 34)
			invalidateOverlappingCache(m.crcLoops, address, len(data), 34)
			m.invalidateAcceleratorCache(address, len(data))
			invalidateOverlappingCache(m.wideCompareChecked, address, len(data), 32)
			invalidateOverlappingCache(m.wideCompare, address, len(data), 32)
			invalidateOverlappingCache(m.asciiLowerChecked, address, len(data), 36)
			invalidateOverlappingCache(m.asciiLower, address, len(data), 36)
			invalidateOverlappingCache(m.mixedCompareChecked, address, len(data), 80)
			invalidateOverlappingCache(m.mixedCompare, address, len(data), 80)
			invalidateOverlappingCache(m.zeroByteScanChecked, address, len(data), 7)
			invalidateOverlappingCache(m.zeroByteScan, address, len(data), 7)
		}
	}
	return nil
}

func (m *emulatorX86) invalidateDecodedCache(address uint32, size int) {
	const maximumWidth = uint64(15)
	if len(m.decoded) == 0 || size <= 0 {
		return
	}
	end := uint64(address) + uint64(size)
	start := uint64(0)
	if uint64(address)+1 > maximumWidth {
		start = uint64(address) + 1 - maximumWidth
	}
	remove := func(candidate uint32) {
		if _, cached := m.decoded[candidate]; !cached {
			return
		}
		delete(m.decoded, candidate)
		pageNumber := candidate >> 12
		if page := m.decodedPages[pageNumber]; page != nil {
			page.instructions[candidate&0xfff] = nil
		}
	}
	if end-start < uint64(len(m.decoded)) {
		for candidate := start; candidate < end; candidate++ {
			remove(uint32(candidate))
		}
		return
	}
	for candidate := range m.decoded {
		candidateEnd := uint64(candidate) + maximumWidth
		if uint64(candidate) < end && uint64(address) < candidateEnd {
			remove(candidate)
		}
	}
}

func (m *emulatorX86) cacheDecodedInstruction(address uint32, instruction *x86asm.Inst) {
	if m.decodedLimit <= 0 {
		return
	}
	pageNumber := address >> 12
	page := m.decodedPages[pageNumber]
	if page == nil {
		page = new(emulatorDecodedPage)
		m.decodedPages[pageNumber] = page
	}
	if existing := m.decoded[address]; existing != nil {
		*existing = *instruction
		page.instructions[address&0xfff] = existing
		return
	}
	entry := emulatorDecodedEntry{address: address, instruction: instruction}
	if len(m.decodedEntries) < m.decodedLimit {
		m.decodedEntries = append(m.decodedEntries, entry)
	} else {
		slot := m.decodedCursor
		for scanned := 0; scanned < len(m.decodedEntries); scanned++ {
			slot = m.decodedCursor
			evicted := m.decodedEntries[slot]
			m.decodedCursor = (m.decodedCursor + 1) % len(m.decodedEntries)
			if len(m.decoded) < m.decodedLimit || m.decoded[evicted.address] == evicted.instruction {
				if m.decoded[evicted.address] == evicted.instruction {
					delete(m.decoded, evicted.address)
					if evictedPage := m.decodedPages[evicted.address>>12]; evictedPage != nil && evictedPage.instructions[evicted.address&0xfff] == evicted.instruction {
						evictedPage.instructions[evicted.address&0xfff] = nil
					}
				}
				break
			}
		}
		m.decodedEntries[slot] = entry
	}
	m.decoded[address] = instruction
	page.instructions[address&0xfff] = instruction
}

func (m *emulatorX86) invalidateAcceleratorCache(address uint32, size int) {
	const maximumWidth = uint64(80)
	if len(m.decodedPages) == 0 || size <= 0 {
		return
	}
	end := uint64(address) + uint64(size)
	start := uint64(0)
	if uint64(address)+1 > maximumWidth {
		start = uint64(address) + 1 - maximumWidth
	}
	if end-start < uint64(len(m.decodedPages))*4096 {
		for candidate := start; candidate < end; candidate++ {
			if page := m.decodedPages[uint32(candidate)>>12]; page != nil {
				page.accelerators[uint32(candidate)&0xfff] = emulatorAcceleratorUnchecked
			}
		}
		return
	}
	for pageNumber, page := range m.decodedPages {
		pageStart := uint64(pageNumber) << 12
		for offset, kind := range page.accelerators {
			if kind == emulatorAcceleratorUnchecked {
				continue
			}
			candidate := pageStart + uint64(offset)
			if candidate < end && uint64(address) < candidate+maximumWidth {
				page.accelerators[offset] = emulatorAcceleratorUnchecked
			}
		}
	}
}

func (m *emulatorX86) cachedCodeMayOverlap(address uint32, size int) bool {
	const maximumCachedWidth = uint64(80)
	if len(m.cachedCodePages) == 0 || size <= 0 {
		return false
	}
	start := uint64(0)
	if uint64(address)+1 > maximumCachedWidth {
		start = uint64(address) + 1 - maximumCachedWidth
	}
	end := uint64(address) + uint64(size)
	for page := start >> 12; page <= (end-1)>>12; page++ {
		if m.cachedCodePages[uint32(page)] {
			return true
		}
	}
	return false
}

func (m *emulatorX86) rangeMayExecute(address uint32, size int, mapping *emulatorMapping) bool {
	if mapping.executable {
		return true
	}
	start, end := uint64(address), uint64(address)+uint64(size)
	for _, protection := range m.protections {
		protectionStart := uint64(protection.start)
		if protection.executable && start < protectionStart+protection.size && protectionStart < end {
			return true
		}
	}
	return false
}

func (m *emulatorX86) recordMemoryWrites(address uint32, before, after []byte) {
	writeStart := uint64(address)
	writeEnd := writeStart + uint64(len(after))
	for _, watch := range m.memoryWatches {
		watchStart := uint64(watch.start)
		watchEnd := watchStart + uint64(watch.size)
		start := max(writeStart, watchStart)
		end := min(writeEnd, watchEnd)
		if start >= end {
			continue
		}
		offset := int(start - writeStart)
		size := int(end - start)
		entry := emulatorMemoryWrite{
			eip:     m.currentInstruction,
			address: uint32(start),
			before:  bytes.Clone(before[offset : offset+size]),
			after:   bytes.Clone(after[offset : offset+size]),
		}
		if len(watch.entries) < watch.limit {
			watch.entries = append(watch.entries, entry)
			continue
		}
		watch.entries[watch.cursor] = entry
		watch.cursor = (watch.cursor + 1) % len(watch.entries)
		watch.dropped++
	}
}

func (m *emulatorX86) codeWatchAt(address uint32) bool {
	for _, watch := range m.codeWatches {
		start := uint64(watch.start)
		if uint64(address) >= start && uint64(address) < start+watch.size {
			return true
		}
	}
	return false
}

func (m *emulatorX86) recordCodeTrace(address uint32, instruction string) {
	for _, watch := range m.codeWatches {
		start := uint64(watch.start)
		if uint64(address) < start || uint64(address) >= start+watch.size {
			continue
		}
		entry := emulatorCodeEntry{
			address:     address,
			eax:         m.registers[x86asm.EAX],
			ebx:         m.registers[x86asm.EBX],
			ecx:         m.registers[x86asm.ECX],
			edx:         m.registers[x86asm.EDX],
			esi:         m.registers[x86asm.ESI],
			edi:         m.registers[x86asm.EDI],
			esp:         m.registers[x86asm.ESP],
			ebp:         m.registers[x86asm.EBP],
			eflags:      m.flagsValue(),
			instruction: instruction,
		}
		if watch.stackBytes != 0 {
			if stack, err := m.readMemory(entry.esp, watch.stackBytes, 'r'); err == nil {
				entry.stack = bytes.Clone(stack)
			}
		}
		if len(watch.captures) != 0 {
			entry.captures = make(map[string][]byte, len(watch.captures))
			for _, capture := range watch.captures {
				base := m.registerValue(capture.base)
				if capture.base == x86asm.EIP {
					base = address
				}
				captureAddress := int64(base) + int64(capture.offset)
				valid := captureAddress >= 0 && captureAddress <= math.MaxUint32
				for depth := 0; valid && depth < capture.dereference; depth++ {
					pointer, err := m.readUint32(uint32(captureAddress))
					if err != nil || pointer == 0 {
						valid = false
						break
					}
					captureAddress = int64(pointer)
				}
				if valid {
					if data, err := m.readMemory(uint32(captureAddress), capture.size, 'r'); err == nil {
						entry.captures[capture.name] = bytes.Clone(data)
						continue
					}
				}
				entry.captures[capture.name] = nil
			}
		}
		if len(watch.entries) < watch.limit {
			watch.entries = append(watch.entries, entry)
			continue
		}
		watch.entries[watch.cursor] = entry
		watch.cursor = (watch.cursor + 1) % len(watch.entries)
		watch.dropped++
	}
}

func (m *emulatorX86) readUint32(address uint32) (uint32, error) {
	data, err := m.readMemory(address, 4, 'r')
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (m *emulatorX86) readUint16(address uint32) (uint16, error) {
	data, err := m.readMemory(address, 2, 'r')
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(data), nil
}
func (m *emulatorX86) writeUint32(address, value uint32) error {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	return m.writeMemory(address, data[:])
}

func (m *emulatorX86) u32MultiplyAccumulateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var destination, source, count, scalar, carry uint64
	subtract := false
	if err := starlark.UnpackArgs("u32_multiply_accumulate", args, kwargs,
		"destination", &destination,
		"source", &source,
		"count", &count,
		"scalar", &scalar,
		"carry?", &carry,
		"subtract?", &subtract,
	); err != nil {
		return nil, err
	}
	const maximumWords = uint64(1 << 20)
	width := count * 4
	if m.frozen || count > maximumWords || scalar > math.MaxUint32 || carry > math.MaxUint32 ||
		destination > math.MaxUint32 || source > math.MaxUint32 ||
		width > uint64(math.MaxUint32)+1-destination || width > uint64(math.MaxUint32)+1-source {
		return nil, fmt.Errorf("u32_multiply_accumulate: invalid address range, scalar, carry, count, or frozen machine")
	}
	if count == 0 {
		return starlark.MakeUint64(carry), nil
	}

	destinationAddress, sourceAddress := uint32(destination), uint32(source)
	byteCount := int(width)
	sourceData, err := m.readMemory(sourceAddress, byteCount, 'r')
	if err != nil {
		return nil, fmt.Errorf("u32_multiply_accumulate: source: %w", err)
	}
	destinationData, err := m.readMemory(destinationAddress, byteCount, 'r')
	if err != nil {
		return nil, fmt.Errorf("u32_multiply_accumulate: destination: %w", err)
	}
	if _, _, err := m.mapping(destinationAddress, byteCount, 'w'); err != nil {
		return nil, fmt.Errorf("u32_multiply_accumulate: destination: %w", err)
	}

	endDestination := destination + width
	endSource := source + width
	overlaps := destination < endSource && source < endDestination && destination != source
	if overlaps {
		for index := uint64(0); index < count; index++ {
			sourceWord, err := m.readUint32(sourceAddress + uint32(index*4))
			if err != nil {
				return nil, fmt.Errorf("u32_multiply_accumulate: source word %d: %w", index, err)
			}
			destinationWord, err := m.readUint32(destinationAddress + uint32(index*4))
			if err != nil {
				return nil, fmt.Errorf("u32_multiply_accumulate: destination word %d: %w", index, err)
			}
			product := uint64(sourceWord)*scalar + carry
			low := uint32(product)
			carry = product >> 32
			var output uint32
			if subtract {
				output = destinationWord - low
				if destinationWord < low {
					carry++
				}
			} else {
				sum := uint64(destinationWord) + uint64(low)
				output = uint32(sum)
				carry += sum >> 32
			}
			carry &= math.MaxUint32
			if err := m.writeUint32(destinationAddress+uint32(index*4), output); err != nil {
				return nil, fmt.Errorf("u32_multiply_accumulate: destination word %d: %w", index, err)
			}
		}
		return starlark.MakeUint64(carry), nil
	}

	output := make([]byte, byteCount)
	for index := uint64(0); index < count; index++ {
		offset := index * 4
		sourceWord := binary.LittleEndian.Uint32(sourceData[offset : offset+4])
		destinationWord := binary.LittleEndian.Uint32(destinationData[offset : offset+4])
		product := uint64(sourceWord)*scalar + carry
		low := uint32(product)
		carry = product >> 32
		var result uint32
		if subtract {
			result = destinationWord - low
			if destinationWord < low {
				carry++
			}
		} else {
			sum := uint64(destinationWord) + uint64(low)
			result = uint32(sum)
			carry += sum >> 32
		}
		carry &= math.MaxUint32
		binary.LittleEndian.PutUint32(output[offset:offset+4], result)
	}
	if err := m.writeMemory(destinationAddress, output); err != nil {
		return nil, fmt.Errorf("u32_multiply_accumulate: destination: %w", err)
	}
	return starlark.MakeUint64(carry), nil
}
func (m *emulatorX86) push(value uint32) error {
	esp := m.registers[x86asm.ESP] - 4
	if err := m.writeUint32(esp, value); err != nil {
		return err
	}
	m.registers[x86asm.ESP] = esp
	return nil
}
func (m *emulatorX86) pop() (uint32, error) {
	esp := m.registers[x86asm.ESP]
	value, err := m.readUint32(esp)
	if err != nil {
		return 0, err
	}
	m.registers[x86asm.ESP] = esp + 4
	return value, nil
}

func (m *emulatorX86) String() string {
	return fmt.Sprintf("<emulator.x86 eip=0x%08x mapped=%d>", m.eip, m.mappedBytes)
}
func (m *emulatorX86) Type() string          { return "emulator.x86" }
func (m *emulatorX86) Freeze()               { m.frozen = true }
func (m *emulatorX86) Truth() starlark.Bool  { return starlark.True }
func (m *emulatorX86) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", m.Type()) }
func (m *emulatorX86) AttrNames() []string {
	names := []string{"accelerate_loop", "accelerate_region", "accelerate_runtime_region", "allocate", "call", "call_export", "call_trace", "checkpoint", "code_trace", "configure_call_trace", "configure_trace", "entry", "free", "get_register", "hook", "imports", "invoke", "load_module", "mappings", "memory_writes", "modules", "on_exception", "profile", "protect", "provide_export", "read", "read_cbytes", "read_cstring", "resolve_export", "restore", "rewrite", "run", "segment_base", "set_register", "snapshot", "spawn", "stack", "stop", "transform", "transfer", "u32_multiply_accumulate", "use", "watch_code", "watch_memory", "write"}
	for _, codec := range binaryScalarCodecs {
		names = append(names, "read_"+codec.Name, "write_"+codec.Name)
	}
	sort.Strings(names)
	return names
}
func (m *emulatorX86) Attr(name string) (starlark.Value, error) {
	if name == "entry" {
		return starlark.MakeUint64(uint64(m.entry)), nil
	}
	if name == "imports" {
		return m.importValues(), nil
	}
	if name == "modules" {
		return m.moduleValues(), nil
	}
	if name == "mappings" {
		return m.mappingValues(), nil
	}
	if name == "stack" {
		return newStarlarkRecord(map[string]starlark.Value{"low": starlark.MakeUint64(uint64(m.stackLow)), "high": starlark.MakeUint64(uint64(m.stackHigh))}), nil
	}
	if value, ok := m.attrCache[name]; ok {
		return value, nil
	}
	var method func(*starlark.Thread, *starlark.Builtin, starlark.Tuple, []starlark.Tuple) (starlark.Value, error)
	switch name {
	case "accelerate_loop":
		method = m.accelerateLoopBuiltin
	case "accelerate_region":
		method = m.accelerateRegionBuiltin
	case "accelerate_runtime_region":
		method = m.accelerateRuntimeRegionBuiltin
	case "allocate":
		method = m.allocateBuiltin
	case "call":
		method = m.callBuiltin
	case "call_export":
		method = m.callExportBuiltin
	case "call_trace":
		method = m.callTraceBuiltin
	case "checkpoint":
		method = m.checkpointBuiltin
	case "code_trace":
		method = m.codeTraceBuiltin
	case "configure_call_trace":
		method = m.configureCallTraceBuiltin
	case "configure_trace":
		method = m.configureTraceBuiltin
	case "free":
		method = m.freeBuiltin
	case "get_register":
		method = m.getRegisterBuiltin
	case "hook":
		method = m.hookBuiltin
	case "invoke":
		method = m.invokeBuiltin
	case "load_module":
		method = m.loadModuleBuiltin
	case "memory_writes":
		method = m.memoryWritesBuiltin
	case "on_exception":
		method = m.onExceptionBuiltin
	case "profile":
		method = m.profileBuiltin
	case "protect":
		method = m.protectBuiltin
	case "provide_export":
		method = m.provideExportBuiltin
	case "read":
		method = m.readBuiltin
	case "read_cbytes":
		method = m.readCBytesBuiltin
	case "read_cstring":
		method = m.readCStringBuiltin
	case "resolve_export":
		method = m.resolveExportBuiltin
	case "restore":
		method = m.restoreBuiltin
	case "rewrite":
		method = m.rewriteBuiltin
	case "run":
		method = m.runBuiltin
	case "segment_base":
		method = m.segmentBaseBuiltin
	case "set_register":
		method = m.setRegisterBuiltin
	case "snapshot":
		method = m.snapshotBuiltin
	case "spawn":
		method = m.spawnBuiltin
	case "stop":
		method = m.stopBuiltin
	case "transform":
		method = m.transformBuiltin
	case "transfer":
		method = m.transferBuiltin
	case "u32_multiply_accumulate":
		method = m.u32MultiplyAccumulateBuiltin
	case "use":
		method = m.useBuiltin
	case "watch_code":
		method = m.watchCodeBuiltin
	case "watch_memory":
		method = m.watchMemoryBuiltin
	case "write":
		method = m.writeBuiltin
	}
	if method != nil {
		value := starlark.NewBuiltin(name, method)
		m.attrCache[name] = value
		return value, nil
	}
	if strings.HasPrefix(name, "read_") {
		if codec, ok := binaryScalarCodecNamed(strings.TrimPrefix(name, "read_")); ok {
			value := starlark.NewBuiltin("emulator.x86."+name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var addressValue starlark.Int
				if err := starlark.UnpackArgs(name, args, kwargs, "address", &addressValue); err != nil {
					return nil, err
				}
				address, ok := addressValue.Uint64()
				if !ok || address > math.MaxUint32-uint64(codec.Width-1) {
					return nil, fmt.Errorf("%s: address range does not fit in 32-bit guest memory", name)
				}
				data, err := m.readMemory(uint32(address), codec.Width, 'r')
				if err != nil {
					return nil, fmt.Errorf("%s: %w", name, err)
				}
				return codec.Decode(data), nil
			})
			m.attrCache[name] = value
			return value, nil
		}
	}
	if strings.HasPrefix(name, "write_") {
		if codec, ok := binaryScalarCodecNamed(strings.TrimPrefix(name, "write_")); ok {
			value := starlark.NewBuiltin("emulator.x86."+name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var addressValue starlark.Int
				var value starlark.Value
				if err := starlark.UnpackArgs(name, args, kwargs, "address", &addressValue, "value", &value); err != nil {
					return nil, err
				}
				address, ok := addressValue.Uint64()
				if m.frozen || !ok || address > math.MaxUint32-uint64(codec.Width-1) {
					return nil, fmt.Errorf("%s: invalid 32-bit guest address range or frozen machine", name)
				}
				data, err := codec.Encode(value)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", name, err)
				}
				if err := m.writeMemory(uint32(address), data); err != nil {
					return nil, fmt.Errorf("%s: %w", name, err)
				}
				return starlark.None, nil
			})
			m.attrCache[name] = value
			return value, nil
		}
	}
	return nil, nil
}

func (m *emulatorX86) mappingValues() *starlark.List {
	values := make([]starlark.Value, len(m.mappings))
	for index, mapping := range m.mappings {
		values[index] = newStarlarkRecord(map[string]starlark.Value{
			"name":       starlark.String(mapping.name),
			"start":      starlark.MakeUint64(uint64(mapping.start)),
			"size":       starlark.MakeInt(len(mapping.data)),
			"readable":   starlark.Bool(mapping.readable),
			"writable":   starlark.Bool(mapping.writable),
			"executable": starlark.Bool(mapping.executable),
		})
	}
	return starlark.NewList(values)
}

func (m *emulatorX86) segmentBaseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("segment_base", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	segments := map[string]x86asm.Reg{"cs": x86asm.CS, "ds": x86asm.DS, "es": x86asm.ES, "fs": x86asm.FS, "gs": x86asm.GS, "ss": x86asm.SS}
	segment, ok := segments[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("segment_base: unknown segment %q", name)
	}
	return starlark.MakeUint64(uint64(m.segmentBases[segment])), nil
}

func (m *emulatorX86) moduleValues() *starlark.List {
	if m.moduleValuesCache != nil {
		return m.moduleValuesCache
	}
	names := make([]string, 0, len(m.modules))
	for name := range m.modules {
		names = append(names, name)
	}
	sort.Strings(names)
	values := make([]starlark.Value, len(names))
	for index, name := range names {
		module := m.modules[name]
		values[index] = newStarlarkRecord(map[string]starlark.Value{"name": starlark.String(module.name), "base": starlark.MakeUint64(uint64(module.base)), "entry": starlark.MakeUint64(uint64(module.entry)), "primary": starlark.Bool(module.primary)})
	}
	result := starlark.NewList(values)
	result.Freeze()
	m.moduleValuesCache = result
	return result
}

func (m *emulatorX86) loadModuleBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var image starlark.Value
	var name string
	if err := starlark.UnpackArgs("load_module", args, kwargs, "image", &image, "name", &name); err != nil {
		return nil, err
	}
	if m.frozen {
		return nil, fmt.Errorf("load_module: machine is frozen")
	}
	module, err := m.mapPE(image, name, false)
	if err != nil {
		return nil, fmt.Errorf("load_module: %w", err)
	}
	return newStarlarkRecord(map[string]starlark.Value{"name": starlark.String(module.name), "base": starlark.MakeUint64(uint64(module.base)), "entry": starlark.MakeUint64(uint64(module.entry)), "primary": starlark.Bool(module.primary)}), nil
}

func (m *emulatorX86) provideExportBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	callbackValue := starlark.Value(starlark.None)
	value := starlark.Value(starlark.None)
	var moduleName, name string
	ordinal, argc := 0, 0
	convention := "stdcall"
	writable := true
	if err := starlark.UnpackArgs("provide_export", args, kwargs,
		"callback?", &callbackValue, "module", &moduleName, "name?", &name, "ordinal?", &ordinal,
		"argc?", &argc, "convention?", &convention, "value?", &value, "writable?", &writable,
	); err != nil {
		return nil, err
	}
	hasCallback := callbackValue != starlark.None
	hasValue := value != starlark.None
	if m.frozen || hasCallback == hasValue || (name == "") == (ordinal == 0) || ordinal < 0 || argc < 0 || (convention != "stdcall" && convention != "cdecl") {
		return nil, fmt.Errorf("provide_export: invalid symbol, arguments, convention, or frozen machine")
	}
	var callback starlark.Callable
	if hasCallback {
		var ok bool
		callback, ok = callbackValue.(starlark.Callable)
		if !ok {
			return nil, fmt.Errorf("provide_export: callback is not callable")
		}
	} else if argc != 0 || convention != "stdcall" {
		return nil, fmt.Errorf("provide_export: argc and convention apply only to callable exports")
	}
	canonicalName := canonicalEmulatorModuleName(moduleName)
	if canonicalName == "" {
		return nil, fmt.Errorf("provide_export: module name must not be empty")
	}
	module := m.modules[canonicalName]
	if module == nil {
		base := emulatorVirtualModuleBase
		for {
			used := false
			for _, existing := range m.modules {
				used = used || existing.base == base
			}
			if !used {
				break
			}
			base += 0x10000
		}
		module = &emulatorModule{name: canonicalName, base: base, exports: make(map[string]emulatorModuleExport), ordinals: make(map[uint32]emulatorModuleExport)}
		m.modules[canonicalName] = module
		m.moduleValuesCache = nil
	}
	target := m.nextVirtualExport
	if hasValue {
		data, err := bytesForBinaryValue(value)
		if err != nil {
			return nil, fmt.Errorf("provide_export: value: %w", err)
		}
		if len(data) == 0 || len(data) > 1<<20 {
			return nil, fmt.Errorf("provide_export: data export must contain 1 byte through 1 MiB")
		}
		size := (len(data) + 15) &^ 15
		if uint64(target)+uint64(size) > math.MaxUint32 {
			return nil, fmt.Errorf("provide_export: virtual export address space exhausted")
		}
		mapped := make([]byte, size)
		copy(mapped, data)
		symbol := name
		if symbol == "" {
			symbol = fmt.Sprintf("#%d", ordinal)
		}
		if err := m.addMapping(canonicalName+"!"+symbol, target, mapped, true, writable, false); err != nil {
			return nil, fmt.Errorf("provide_export: %w", err)
		}
		m.nextVirtualExport += uint32(size)
	} else {
		m.nextVirtualExport += 16
	}
	export := emulatorModuleExport{address: target}
	hookName := name
	if name != "" {
		module.exports[strings.ToLower(name)] = export
	} else {
		module.ordinals[uint32(ordinal)] = export
		hookName = fmt.Sprintf("#%d", ordinal)
	}
	if hasCallback {
		m.hooks[target] = emulatorHook{module: canonicalName, name: hookName, address: target, argc: argc, convention: convention, callback: callback}
	}
	if err := m.relinkProvidedExport(canonicalName, name, uint32(ordinal), target); err != nil {
		return nil, fmt.Errorf("provide_export: %w", err)
	}
	return starlark.MakeUint64(uint64(target)), nil
}

func (m *emulatorX86) resolveExportBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var module, name string
	ordinal := 0
	if err := starlark.UnpackArgs("resolve_export", args, kwargs, "module", &module, "name?", &name, "ordinal?", &ordinal); err != nil {
		return nil, err
	}
	if (name == "") == (ordinal == 0) || ordinal < 0 {
		return nil, fmt.Errorf("resolve_export: provide exactly one of name or ordinal")
	}
	address := m.resolveExport(module, name, uint32(ordinal), 0)
	return starlark.MakeUint64(uint64(address)), nil
}

func (m *emulatorX86) resolveExport(moduleName, name string, ordinal uint32, depth int) uint32 {
	if depth >= 16 {
		return 0
	}
	module := m.modules[canonicalEmulatorModuleName(moduleName)]
	if module == nil {
		return 0
	}
	var export emulatorModuleExport
	var ok bool
	if name != "" {
		export, ok = module.exports[strings.ToLower(name)]
	} else {
		export, ok = module.ordinals[ordinal]
	}
	if !ok {
		return 0
	}
	if export.forwarder == "" {
		return export.address
	}
	separator := strings.LastIndexByte(export.forwarder, '.')
	if separator <= 0 || separator == len(export.forwarder)-1 {
		return 0
	}
	forwardModule, symbol := export.forwarder[:separator], export.forwarder[separator+1:]
	if !strings.Contains(forwardModule, ".") {
		forwardModule += ".dll"
	}
	if strings.HasPrefix(symbol, "#") {
		var forwardedOrdinal uint32
		if _, err := fmt.Sscanf(symbol, "#%d", &forwardedOrdinal); err != nil {
			return 0
		}
		return m.resolveExport(forwardModule, "", forwardedOrdinal, depth+1)
	}
	return m.resolveExport(forwardModule, symbol, 0, depth+1)
}

func (m *emulatorX86) importValues() *starlark.List {
	if m.importValuesCache != nil {
		return m.importValuesCache
	}
	targets := make([]int, 0, len(m.imports))
	for target := range m.imports {
		targets = append(targets, int(target))
	}
	sort.Ints(targets)
	values := make([]starlark.Value, 0, len(targets))
	for _, raw := range targets {
		item := m.imports[uint32(raw)]
		values = append(values, newStarlarkRecord(map[string]starlark.Value{"module": starlark.String(item.module), "name": starlark.String(item.name), "ordinal": starlark.MakeUint(uint(item.ordinal)), "iat": starlark.MakeUint64(uint64(item.iat)), "address": starlark.MakeUint64(uint64(item.target))}))
	}
	result := starlark.NewList(values)
	result.Freeze()
	m.importValuesCache = result
	return result
}

func (m *emulatorX86) runBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	entryValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("run", args, kwargs, "entry?", &entryValue); err != nil {
		return nil, err
	}
	if entryValue != starlark.None {
		entry, err := starlark.AsInt32(entryValue)
		if err != nil || entry < 0 {
			return nil, fmt.Errorf("run: entry must be a non-negative int")
		}
		m.eip = uint32(entry)
	}
	// A saved or externally interrupted context can resume immediately after
	// CALL or a tail JMP has transferred control to a hooked address. Resume the
	// pending semantic call instead of interpreting its physical thunk.
	// Explicit entry overrides retain their debugging meaning and execute from
	// the requested instruction verbatim.
	if entryValue == starlark.None {
		if hook, ok := m.hooks[m.eip]; ok {
			stop, detail, err := m.invokeTailHook(thread, hook)
			if err != nil {
				return nil, err
			}
			if stop != "" {
				return m.result(stop, 0, detail), nil
			}
		}
	}
	return m.run(thread)
}
func (m *emulatorX86) callExportBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	arguments := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("call_export", args, kwargs, "name", &name, "args?", &arguments); err != nil {
		return nil, err
	}
	entry, ok := m.exports[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("call_export: export %q not found", name)
	}
	values, err := starlarkUint32Values("call_export", arguments)
	if err != nil {
		return nil, err
	}
	return m.callAddress(thread, entry, values)
}

func (m *emulatorX86) callBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return m.callBuiltinNamed(thread, "call", args, kwargs, false)
}

func (m *emulatorX86) invokeBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return m.callBuiltinNamed(thread, "invoke", args, kwargs, true)
}

func (m *emulatorX86) stackSlot() (int, uint32, error) {
	const slotSize = uint32(64 << 10)
	maximum := int((m.stackHigh - m.stackLow) / 2 / slotSize)
	for slot := 1; slot <= maximum; slot++ {
		if m.stackSlots[slot] {
			continue
		}
		used := false
		for _, active := range m.invokeStackSlots {
			if active == slot {
				used = true
				break
			}
		}
		if !used {
			return slot, m.stackLow + uint32(slot)*slotSize, nil
		}
	}
	return 0, 0, fmt.Errorf("emulator: no reserved execution stack remains")
}

func (m *emulatorX86) captureContext() (emulatorCPUContext, error) {
	context := emulatorCPUContext{
		registers:      m.registers,
		eip:            m.eip,
		callDepth:      m.callDepth,
		callFrames:     append([]emulatorCallFrame(nil), m.callFrames...),
		zero:           m.zero,
		carry:          m.carry,
		parity:         m.parity,
		sign:           m.sign,
		overflow:       m.overflow,
		direction:      m.direction,
		x87ControlWord: m.x87ControlWord,
		x87StatusWord:  m.x87StatusWord,
		x87Stack:       m.x87Stack,
		x87Top:         m.x87Top,
		x87Depth:       m.x87Depth,
		exceptionHead:  math.MaxUint32,
	}
	if fsBase := m.segmentBases[x86asm.FS]; fsBase != 0 {
		head, err := m.readUint32(fsBase)
		if err != nil {
			return emulatorCPUContext{}, err
		}
		context.exceptionHead = head
	}
	return context, nil
}

func (m *emulatorX86) restoreContext(context emulatorCPUContext) error {
	m.registers = context.registers
	m.eip = context.eip
	m.callDepth = context.callDepth
	m.callFrames = append(m.callFrames[:0], context.callFrames...)
	m.zero, m.carry, m.parity = context.zero, context.carry, context.parity
	m.sign, m.overflow, m.direction = context.sign, context.overflow, context.direction
	m.x87ControlWord, m.x87StatusWord = context.x87ControlWord, context.x87StatusWord
	m.x87Stack, m.x87Top, m.x87Depth = context.x87Stack, context.x87Top, context.x87Depth
	if fsBase := m.segmentBases[x86asm.FS]; fsBase != 0 {
		if err := m.writeUint32(fsBase, context.exceptionHead); err != nil {
			return err
		}
	}
	return nil
}

func (m *emulatorX86) spawnBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address int
	arguments := starlark.Value(starlark.None)
	registerValues := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("spawn", args, kwargs, "address", &address, "args?", &arguments, "registers?", &registerValues); err != nil {
		return nil, err
	}
	if m.frozen || address < 0 || uint64(address) > math.MaxUint32 {
		return nil, fmt.Errorf("spawn: address must fit uint32 on a mutable machine")
	}
	values, err := starlarkUint32Values("spawn", arguments)
	if err != nil {
		return nil, err
	}
	initial, err := starlarkRegisterValues("spawn", registerValues)
	if err != nil {
		return nil, err
	}
	slot, stackTop, err := m.stackSlot()
	if err != nil {
		return nil, err
	}
	m.stackSlots[slot] = true
	registers := emulatorRegisterFile{}
	for register, value := range initial {
		registers[register] = value
	}
	registers[x86asm.ESP] = stackTop - uint32((len(values)+1)*4)
	registers[x86asm.EBP] = stackTop
	for index, value := range values {
		if err := m.writeUint32(registers[x86asm.ESP]+4+uint32(index*4), value); err != nil {
			delete(m.stackSlots, slot)
			return nil, err
		}
	}
	if err := m.writeUint32(registers[x86asm.ESP], 0); err != nil {
		delete(m.stackSlots, slot)
		return nil, err
	}
	execution := &emulatorExecution{
		machine:   m,
		stackSlot: slot,
		context: emulatorCPUContext{
			registers: registers, eip: uint32(address), x87ControlWord: 0x037f,
			exceptionHead: math.MaxUint32,
		},
	}
	m.executions[execution] = true
	return execution, nil
}

func (m *emulatorX86) callBuiltinNamed(thread *starlark.Thread, builtinName string, args starlark.Tuple, kwargs []starlark.Tuple, preserve bool) (starlark.Value, error) {
	var address int
	arguments := starlark.Value(starlark.None)
	registerValues := starlark.Value(starlark.None)
	inheritExceptions := false
	if err := starlark.UnpackArgs(builtinName, args, kwargs, "address", &address, "args?", &arguments, "registers?", &registerValues, "inherit_exceptions?", &inheritExceptions); err != nil {
		return nil, err
	}
	if inheritExceptions && !preserve {
		return nil, fmt.Errorf("%s: inherit_exceptions is only supported by invoke", builtinName)
	}
	if address < 0 || uint64(address) > math.MaxUint32 {
		return nil, fmt.Errorf("%s: address must fit uint32", builtinName)
	}
	values, err := starlarkUint32Values(builtinName, arguments)
	if err != nil {
		return nil, err
	}
	initialRegisters, err := starlarkRegisterValues(builtinName, registerValues)
	if err != nil {
		return nil, err
	}
	if preserve {
		registers := m.registers
		eip, callDepth, callFrames := m.eip, m.callDepth, m.callFrames
		zero, carry, parity, sign, overflow, direction := m.zero, m.carry, m.parity, m.sign, m.overflow, m.direction
		x87ControlWord, x87StatusWord, x87Stack, x87Top, x87Depth := m.x87ControlWord, m.x87StatusWord, m.x87Stack, m.x87Top, m.x87Depth
		traceEntries, traceCursor := m.traceEntries, m.traceCursor
		var exceptionHead uint32
		fsBase := m.segmentBases[x86asm.FS]
		if fsBase != 0 {
			exceptionHead, err = m.readUint32(fsBase)
			if err != nil {
				return nil, fmt.Errorf("invoke: read exception list: %w", err)
			}
			if !inheritExceptions {
				if err := m.writeUint32(fsBase, math.MaxUint32); err != nil {
					return nil, fmt.Errorf("invoke: isolate exception list: %w", err)
				}
			}
		}
		m.invokeDepth++
		slot, nestedStackTop, stackErr := m.stackSlot()
		if stackErr != nil {
			m.invokeDepth--
			if fsBase != 0 {
				_ = m.writeUint32(fsBase, exceptionHead)
			}
			return nil, fmt.Errorf("invoke: %w", stackErr)
		}
		m.invokeStackSlots = append(m.invokeStackSlots, slot)
		m.registers = emulatorRegisterFile{}
		result, err := m.callAddressWithRegistersAt(thread, uint32(address), values, initialRegisters, nestedStackTop)
		m.invokeStackSlots = m.invokeStackSlots[:len(m.invokeStackSlots)-1]
		m.invokeDepth--
		if fsBase != 0 {
			if restoreErr := m.writeUint32(fsBase, exceptionHead); restoreErr != nil && err == nil {
				err = fmt.Errorf("invoke: restore exception list: %w", restoreErr)
			}
		}
		m.registers = registers
		m.eip, m.callDepth, m.callFrames = eip, callDepth, callFrames
		m.zero, m.carry, m.parity, m.sign, m.overflow, m.direction = zero, carry, parity, sign, overflow, direction
		m.x87ControlWord, m.x87StatusWord, m.x87Stack, m.x87Top, m.x87Depth = x87ControlWord, x87StatusWord, x87Stack, x87Top, x87Depth
		m.traceEntries = traceEntries
		m.traceCursor = traceCursor
		return result, err
	}
	return m.callAddressWithRegisters(thread, uint32(address), values, initialRegisters)
}

func (m *emulatorX86) callAddress(thread *starlark.Thread, address uint32, values []uint32) (starlark.Value, error) {
	return m.callAddressWithRegisters(thread, address, values, nil)
}

func (m *emulatorX86) callAddressWithRegisters(thread *starlark.Thread, address uint32, values []uint32, initial map[x86asm.Reg]uint32) (starlark.Value, error) {
	return m.callAddressWithRegistersAt(thread, address, values, initial, m.stackHigh)
}

func (m *emulatorX86) callAddressWithRegistersAt(thread *starlark.Thread, address uint32, values []uint32, initial map[x86asm.Reg]uint32, stackTop uint32) (starlark.Value, error) {
	m.registers = emulatorRegisterFile{}
	m.zero, m.carry, m.sign, m.overflow, m.direction = false, false, false, false, false
	m.registers[x86asm.ESP] = stackTop
	m.registers[x86asm.EBP] = stackTop
	for register, value := range initial {
		m.registers[register] = value
	}
	m.callDepth = 0
	m.callFrames = nil
	for index := len(values) - 1; index >= 0; index-- {
		if err := m.push(values[index]); err != nil {
			return nil, err
		}
	}
	if err := m.push(0); err != nil {
		return nil, err
	}
	m.eip = address
	if hook, ok := m.hooks[address]; ok {
		stop, detail, err := m.invokeTailHook(thread, hook)
		if err != nil {
			return nil, err
		}
		if stop != "" {
			return m.result(stop, 0, detail), nil
		}
	}
	return m.run(thread)
}

func (m *emulatorX86) crc32Loop(address uint32) *emulatorCRC32Loop {
	if m.crcLoopsChecked[address] {
		return m.crcLoops[address]
	}
	m.cachedCodePages[address>>12] = true
	m.crcLoopsChecked[address] = true
	code, err := m.readMemory(address, 34, 'x')
	if err != nil {
		return nil
	}
	reflected := map[int]byte{
		0: 0x8b, 1: 0x45, 3: 0x0f, 4: 0xb6, 5: 0x14, 6: 0x01,
		7: 0x8b, 8: 0x45, 10: 0x0f, 11: 0xb6, 12: 0xf0,
		13: 0x33, 14: 0xd6, 15: 0xc1, 16: 0xe8, 17: 0x08,
		18: 0x33, 19: 0x04, 20: 0x95, 25: 0x41, 26: 0x3b,
		27: 0x4d, 29: 0x89, 30: 0x45, 32: 0x72, 33: 0xde,
	}
	matches := func(fixed map[int]byte) bool {
		for offset, expected := range fixed {
			if code[offset] != expected {
				return false
			}
		}
		return true
	}
	if matches(reflected) && code[9] == code[31] {
		loop := &emulatorCRC32Loop{
			kind:               emulatorCRC32LoopReflected,
			inputDisplacement:  int8(code[2]),
			crcDisplacement:    int8(code[9]),
			lengthDisplacement: int8(code[28]),
			table:              binary.LittleEndian.Uint32(code[21:25]),
		}
		m.crcLoops[address] = loop
		return loop
	}

	code, err = m.readMemory(address, 40, 'x')
	if err != nil {
		return nil
	}
	msb := map[int]byte{
		0: 0x8b, 1: 0x01, 2: 0x8b, 3: 0x55,
		5: 0x0f, 6: 0xb6, 7: 0x14,
		9: 0x8b, 10: 0xf8, 11: 0xc1, 12: 0xef, 13: 0x18,
		14: 0x33, 15: 0xd7, 16: 0x81, 17: 0xe2,
		18: 0xff, 19: 0x00, 20: 0x00, 21: 0x00,
		22: 0xc1, 23: 0xe0, 24: 0x08,
		25: 0x33, 26: 0x04, 27: 0x95,
		32: 0x46, 33: 0x3b, 34: 0x75,
		36: 0x89, 37: 0x01, 38: 0x7c, 39: 0xd8,
	}
	// [esi+edx] has two equivalent SIB encodings depending on which
	// commutative operand the compiler selects as the index register.
	if !matches(msb) || (code[8] != 0x16 && code[8] != 0x32) {
		return nil
	}
	loop := &emulatorCRC32Loop{
		kind:               emulatorCRC32LoopMSB,
		inputDisplacement:  int8(code[4]),
		lengthDisplacement: int8(code[35]),
		table:              binary.LittleEndian.Uint32(code[28:32]),
	}
	m.crcLoops[address] = loop
	return loop
}

func (m *emulatorX86) accelerateCRC32(address uint32, remaining uint64) (uint64, bool, error) {
	loop := m.crc32Loop(address)
	if loop == nil || remaining == 0 {
		return 0, false, nil
	}
	ebp := m.registers[x86asm.EBP]
	stackAddress := func(displacement int8) uint32 { return uint32(int64(ebp) + int64(displacement)) }
	input, err := m.readUint32(stackAddress(loop.inputDisplacement))
	if err != nil {
		return 0, true, err
	}
	limit, err := m.readUint32(stackAddress(loop.lengthDisplacement))
	if err != nil {
		return 0, true, err
	}
	index := m.registers[x86asm.ECX]
	if loop.kind == emulatorCRC32LoopMSB {
		index = m.registers[x86asm.ESI]
	}
	if index >= limit {
		return 0, false, nil
	}
	count := uint64(limit - index)
	maximum := remaining * emulatorAcceleratedWorkUnit
	if maximum/remaining != emulatorAcceleratedWorkUnit {
		maximum = math.MaxUint64
	}
	if maximum > emulatorAcceleratedChunkSize {
		maximum = emulatorAcceleratedChunkSize
	}
	if count > maximum {
		count = maximum
	}
	data, err := m.readMemory(input+index, int(count), 'r')
	if err != nil {
		return 0, true, err
	}
	table, err := m.readMemory(loop.table, 256*4, 'r')
	if err != nil {
		return 0, true, err
	}
	crcAddress := stackAddress(loop.crcDisplacement)
	if loop.kind == emulatorCRC32LoopMSB {
		crcAddress = m.registers[x86asm.ECX]
	}
	crc, err := m.readUint32(crcAddress)
	if err != nil {
		return 0, true, err
	}
	lastTableIndex, previousLow := uint32(0), uint32(0)
	if loop.kind == emulatorCRC32LoopReflected {
		for _, value := range data {
			previousLow = crc & 0xff
			lastTableIndex = uint32(value) ^ previousLow
			crc = crc>>8 ^ binary.LittleEndian.Uint32(table[lastTableIndex*4:lastTableIndex*4+4])
		}
	} else {
		for _, value := range data {
			previousLow = crc >> 24
			lastTableIndex = uint32(value) ^ previousLow
			crc = crc<<8 ^ binary.LittleEndian.Uint32(table[lastTableIndex*4:lastTableIndex*4+4])
		}
	}
	index += uint32(count)
	m.registers[x86asm.EAX] = crc
	m.registers[x86asm.EDX] = lastTableIndex
	if loop.kind == emulatorCRC32LoopReflected {
		m.registers[x86asm.ECX] = index
		m.registers[x86asm.ESI] = previousLow
	} else {
		m.registers[x86asm.EDI] = previousLow
		m.registers[x86asm.ESI] = index
	}
	if err := m.writeUint32(crcAddress, crc); err != nil {
		return 0, true, err
	}
	m.subFlags(index, limit, 4)
	if index == limit {
		if loop.kind == emulatorCRC32LoopReflected {
			m.eip = address + 34
		} else {
			m.eip = address + 40
		}
	}
	// The recognized loop is finite and all memory accesses above are bounded.
	// Charge bulk work rather than every interpreted instruction so checksums
	// over normal image-sized buffers do not exhaust the control-flow budget.
	return (count + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit, true, nil
}

func (m *emulatorX86) isWideASCIICompare(address uint32) bool {
	if m.wideCompareChecked[address] {
		return m.wideCompare[address]
	}
	m.cachedCodePages[address>>12] = true
	m.wideCompareChecked[address] = true
	code, err := m.readMemory(address, 32, 'x')
	if err != nil {
		return false
	}
	fixed := map[int]byte{
		0: 0x8b, 1: 0xff, 2: 0x55, 3: 0x8b, 4: 0xec,
		5: 0x83, 6: 0xec, 7: 0x0c, 8: 0x53, 9: 0x8b,
		10: 0x5d, 11: 0x0c, 12: 0x56, 13: 0x57, 14: 0x8b,
		15: 0x3d, 20: 0x8b, 21: 0x45, 22: 0x08, 23: 0x66,
		24: 0x8b, 25: 0x00, 26: 0x66, 27: 0x85, 28: 0xc0,
	}
	for offset, expected := range fixed {
		if code[offset] != expected {
			return false
		}
	}
	m.wideCompare[address] = true
	return true
}

func (m *emulatorX86) accelerateWideASCIICompare(address uint32) (bool, error) {
	if !m.isWideASCIICompare(address) {
		return false, nil
	}
	esp := m.registers[x86asm.ESP]
	left, err := m.readUint32(esp + 4)
	if err != nil {
		return true, err
	}
	right, err := m.readUint32(esp + 8)
	if err != nil {
		return true, err
	}
	const maximumUnits = 1 << 20
	for index := uint32(0); index < maximumUnits; index++ {
		leftUnit, err := m.readUint16(left + index*2)
		if err != nil {
			return true, err
		}
		rightUnit, err := m.readUint16(right + index*2)
		if err != nil {
			return true, err
		}
		if leftUnit > 0x7f || rightUnit > 0x7f {
			return false, nil
		}
		if leftUnit >= 'A' && leftUnit <= 'Z' {
			leftUnit += 'a' - 'A'
		}
		if rightUnit >= 'A' && rightUnit <= 'Z' {
			rightUnit += 'a' - 'A'
		}
		if leftUnit != rightUnit || leftUnit == 0 {
			m.registers[x86asm.EAX] = uint32(int32(leftUnit) - int32(rightUnit))
			returnAddress, err := m.readUint32(esp)
			if err != nil {
				return true, err
			}
			m.registers[x86asm.ESP] = esp + 12
			m.eip = returnAddress
			if m.callDepth > 0 {
				m.callDepth--
			}
			if len(m.callFrames) > 0 {
				m.callFrames = m.callFrames[:len(m.callFrames)-1]
			}
			return true, nil
		}
	}
	return true, fmt.Errorf("wide string comparison exceeds %d code units", maximumUnits)
}

func (m *emulatorX86) isASCIILower(address uint32) bool {
	if m.asciiLowerChecked[address] {
		return m.asciiLower[address]
	}
	m.cachedCodePages[address>>12] = true
	m.asciiLowerChecked[address] = true
	code, err := m.readMemory(address, 36, 'x')
	if err != nil {
		return false
	}
	fixed := map[int]byte{
		0: 0x8b, 1: 0xff, 2: 0x55, 3: 0x8b, 4: 0xec, 5: 0x51,
		6: 0x8b, 7: 0x45, 8: 0x08, 9: 0x66, 10: 0x3d, 11: 0x7f,
		12: 0x00, 13: 0x77, 15: 0x66, 16: 0x3d, 17: 0x41, 18: 0x00,
		19: 0x72, 21: 0x66, 22: 0x3d, 23: 0x5a, 24: 0x00, 25: 0x77,
		27: 0x83, 28: 0xc0, 29: 0x20, 30: 0x8b, 31: 0xe5, 32: 0x5d,
		33: 0xc2, 34: 0x04, 35: 0x00,
	}
	for offset, expected := range fixed {
		if code[offset] != expected {
			return false
		}
	}
	m.asciiLower[address] = true
	return true
}

func (m *emulatorX86) accelerateASCIILower(address uint32) (bool, error) {
	if !m.isASCIILower(address) {
		return false, nil
	}
	esp := m.registers[x86asm.ESP]
	value, err := m.readUint32(esp + 4)
	if err != nil {
		return true, err
	}
	unit := uint16(value)
	if unit > 0x7f {
		return false, nil
	}
	if unit >= 'A' && unit <= 'Z' {
		value += 'a' - 'A'
	}
	returnAddress, err := m.readUint32(esp)
	if err != nil {
		return true, err
	}
	m.registers[x86asm.EAX] = value
	m.registers[x86asm.ESP] = esp + 8
	m.eip = returnAddress
	if m.callDepth > 0 {
		m.callDepth--
	}
	if len(m.callFrames) > 0 {
		m.callFrames = m.callFrames[:len(m.callFrames)-1]
	}
	return true, nil
}

func (m *emulatorX86) isWideASCIIValidate(address uint32) bool {
	code, err := m.readMemory(address, 40, 'x')
	if err != nil {
		return false
	}
	return bytes.Equal(code, []byte{
		0x8b, 0xff, 0x55, 0x8b, 0xec, 0x8b, 0x45, 0x08,
		0x8b, 0xc8, 0x0f, 0xb7, 0x00, 0xeb, 0x09, 0x84,
		0xe4, 0x75, 0x11, 0x41, 0x41, 0x66, 0x8b, 0x01,
		0x66, 0x85, 0xc0, 0x75, 0xf2, 0x33, 0xc0, 0x40,
		0x5d, 0xc2, 0x04, 0x00, 0x33, 0xc0, 0xeb, 0xf8,
	})
}

func (m *emulatorX86) accelerateWideASCIIValidate(address uint32) (bool, error) {
	if !m.isWideASCIIValidate(address) {
		return false, nil
	}
	esp := m.registers[x86asm.ESP]
	source, err := m.readUint32(esp + 4)
	if err != nil {
		return true, err
	}
	result := uint32(0)
	const maximumUnits = 1 << 20
	for index := uint32(0); index < maximumUnits; index++ {
		unit, err := m.readUint16(source + index*2)
		if err != nil {
			return true, err
		}
		if unit == 0 {
			result = 1
			break
		}
		if unit > 0xff {
			break
		}
		if index == maximumUnits-1 {
			return true, fmt.Errorf("wide ASCII validation exceeds %d code units", maximumUnits)
		}
	}
	returnAddress, err := m.readUint32(esp)
	if err != nil {
		return true, err
	}
	m.registers[x86asm.EAX] = result
	m.registers[x86asm.ESP] = esp + 8
	m.eip = returnAddress
	if m.callDepth > 0 {
		m.callDepth--
	}
	if len(m.callFrames) > 0 {
		m.callFrames = m.callFrames[:len(m.callFrames)-1]
	}
	return true, nil
}

func (m *emulatorX86) isMixedASCIIFoldCompare(address uint32) bool {
	if m.mixedCompareChecked[address] {
		return m.mixedCompare[address]
	}
	m.cachedCodePages[address>>12] = true
	m.mixedCompareChecked[address] = true
	code, err := m.readMemory(address, 80, 'x')
	if err != nil {
		return false
	}
	fixed := map[int]byte{
		0: 0x8b, 1: 0xff, 2: 0x55, 3: 0x8b, 4: 0xec, 5: 0x53,
		6: 0x56, 7: 0x8b, 8: 0x75, 9: 0x08, 10: 0x57, 11: 0x8b,
		12: 0x7d, 13: 0x0c, 14: 0xeb, 15: 0x31, 16: 0x8a, 17: 0x07,
		18: 0xff, 19: 0x4d, 20: 0x10, 21: 0x84, 22: 0xc0, 23: 0x75,
		24: 0x06, 25: 0x66, 26: 0x83, 27: 0x3e, 28: 0x00, 29: 0x74,
		30: 0x28, 31: 0x66, 32: 0x0f, 33: 0xb6, 34: 0xc0, 35: 0x50,
		36: 0xe8, 41: 0x0f, 42: 0xb7, 43: 0xd8, 44: 0x33, 45: 0xc0,
		46: 0x66, 47: 0x8b, 48: 0x06, 49: 0x50, 50: 0xe8, 55: 0x0f,
		56: 0xb7, 57: 0xc0, 58: 0x2b, 59: 0xc3, 60: 0x75, 61: 0x0b,
		62: 0x47, 63: 0x46, 64: 0x46, 65: 0x83, 66: 0x7d, 67: 0x10,
		68: 0x00, 69: 0x75, 70: 0xc9, 71: 0x33, 72: 0xc0, 73: 0x5f,
		74: 0x5e, 75: 0x5b, 76: 0x5d, 77: 0xc2, 78: 0x0c, 79: 0x00,
	}
	for offset, expected := range fixed {
		if code[offset] != expected {
			return false
		}
	}
	firstTarget := uint32(int64(address) + 41 + int64(int32(binary.LittleEndian.Uint32(code[37:41]))))
	secondTarget := uint32(int64(address) + 55 + int64(int32(binary.LittleEndian.Uint32(code[51:55]))))
	if firstTarget != secondTarget {
		return false
	}
	m.mixedCompare[address] = true
	return true
}

func (m *emulatorX86) accelerateMixedASCIIFoldCompare(address uint32) (bool, error) {
	if !m.isMixedASCIIFoldCompare(address) {
		return false, nil
	}
	esp := m.registers[x86asm.ESP]
	wide, err := m.readUint32(esp + 4)
	if err != nil {
		return true, err
	}
	narrow, err := m.readUint32(esp + 8)
	if err != nil {
		return true, err
	}
	remaining, err := m.readUint32(esp + 12)
	if err != nil {
		return true, err
	}
	const maximumUnits = 1 << 20
	result := int32(0)
	completed := false
	for index := uint32(0); index < maximumUnits; index++ {
		narrowUnit, err := m.readMemory(narrow+index, 1, 'r')
		if err != nil {
			return true, err
		}
		wideUnit, err := m.readUint16(wide + index*2)
		if err != nil {
			return true, err
		}
		if wideUnit > 0x7f {
			return false, nil
		}
		remaining--
		if narrowUnit[0] == 0 && wideUnit == 0 {
			completed = true
			break
		}
		lowerNarrow := uint16(narrowUnit[0])
		if lowerNarrow >= 'A' && lowerNarrow <= 'Z' {
			lowerNarrow += 'a' - 'A'
		}
		if wideUnit >= 'A' && wideUnit <= 'Z' {
			wideUnit += 'a' - 'A'
		}
		result = int32(wideUnit) - int32(lowerNarrow)
		if result != 0 || remaining == 0 {
			completed = true
			break
		}
	}
	if !completed {
		return false, nil
	}
	returnAddress, err := m.readUint32(esp)
	if err != nil {
		return true, err
	}
	m.registers[x86asm.EAX] = uint32(result)
	m.registers[x86asm.ESP] = esp + 16
	m.eip = returnAddress
	if m.callDepth > 0 {
		m.callDepth--
	}
	if len(m.callFrames) > 0 {
		m.callFrames = m.callFrames[:len(m.callFrames)-1]
	}
	return true, nil
}

func (m *emulatorX86) isZeroByteScan(address uint32) bool {
	if m.zeroByteScanChecked[address] {
		return m.zeroByteScan[address]
	}
	m.cachedCodePages[address>>12] = true
	m.zeroByteScanChecked[address] = true
	code, err := m.readMemory(address, 7, 'x')
	if err != nil || code[0] != 0x8a || code[2] != 0x40 || code[3] != 0x84 || code[5] != 0x75 || code[6] != 0xf9 {
		return false
	}
	if !((code[1] == 0x08 && code[4] == 0xc9) || (code[1] == 0x10 && code[4] == 0xd2)) {
		return false
	}
	m.zeroByteScan[address] = true
	return true
}

func (m *emulatorX86) accelerateZeroByteScan(address uint32, remaining uint64) (uint64, bool, error) {
	if !m.isZeroByteScan(address) || remaining == 0 {
		return 0, false, nil
	}
	const maximumBytes = 1 << 20
	start := m.registers[x86asm.EAX]
	consumed := 0
	for consumed < maximumBytes {
		mapping, offset, err := m.mapping(start+uint32(consumed), 1, 'r')
		if err != nil {
			return 0, true, err
		}
		count := min(maximumBytes-consumed, len(mapping.data)-offset, emulatorAcceleratedChunkSize)
		index := bytes.IndexByte(mapping.data[offset:offset+count], 0)
		if index < 0 {
			consumed += count
			continue
		}
		consumed += index + 1
		m.registers[x86asm.EAX] = start + uint32(consumed)
		code, err := m.readMemory(address, 2, 'x')
		if err != nil {
			return 0, true, err
		}
		if code[1] == 0x08 {
			m.setRegisterValue(x86asm.CL, 0)
		} else {
			m.setRegisterValue(x86asm.DL, 0)
		}
		m.logicalFlags(0, 1)
		m.eip = address + 7
		work := (uint64(consumed) + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
		if work > remaining {
			work = remaining
		}
		return work, true, nil
	}
	return 0, false, nil
}

var emulatorI16DotProductLoop = []byte{
	0x0f, 0xbf, 0x10, 0x0f, 0xbf, 0x39, 0x0f, 0xaf, 0xd7,
	0x01, 0xd3, 0x83, 0xc0, 0x02, 0x01, 0xe9, 0x39, 0x04,
	0x24, 0x75, 0xeb,
}

var emulatorI16BitExtractDotProductLoop = []byte{
	0x0f, 0xbf, 0x11, 0x0f, 0xbf, 0x3b, 0x0f, 0xaf, 0xd7,
	0x89, 0xd7, 0xc1, 0xff, 0x02, 0x83, 0xe7, 0x0f, 0xc1,
	0xfa, 0x05, 0x83, 0xe2, 0x7f, 0x0f, 0xaf, 0xfa, 0x01,
	0xfe, 0x83, 0xc1, 0x02, 0x01, 0xeb, 0x39, 0x0c, 0x24,
	0x75, 0xda,
}

var emulatorLinkedListReverseLoop = []byte{
	0x89, 0xd3, 0x8b, 0x13, 0x89, 0x0b, 0x89, 0xd9, 0x85, 0xd2, 0x75, 0xf4,
}

var emulatorCRC16BitLoop = []byte{
	0x88, 0xca, 0x31, 0xc2, 0xd0, 0xe9, 0x66, 0xd1, 0xe8,
	0x83, 0xe2, 0x01, 0xf7, 0xda, 0x81, 0xe2, 0x01, 0xa0,
	0xff, 0xff, 0x31, 0xd0, 0xfe, 0xcb, 0x75, 0xe6,
}

var emulatorI16LinkedListSearchLoop = []byte{
	0x8b, 0x00, 0x85, 0xc0, 0x0f, 0x84, 0x9e, 0x00, 0x00, 0x00,
	0x8b, 0x48, 0x04, 0x66, 0x8b, 0x71, 0x02, 0x66, 0x39, 0xd6,
	0x75, 0xea,
}

var emulatorU8LinkedListSearchLoop = []byte{
	0x8b, 0x00, 0x85, 0xc0, 0x74, 0x36, 0x8b, 0x48, 0x04,
	0x0f, 0xb6, 0x39, 0x66, 0x39, 0xd7, 0x75, 0xef,
}

func (m *emulatorX86) isI16DotProduct(address uint32) bool {
	code, err := m.readMemory(address, len(emulatorI16DotProductLoop), 'x')
	return err == nil && bytes.Equal(code, emulatorI16DotProductLoop)
}

func (m *emulatorX86) isI16BitExtractDotProduct(address uint32) bool {
	code, err := m.readMemory(address, len(emulatorI16BitExtractDotProductLoop), 'x')
	return err == nil && bytes.Equal(code, emulatorI16BitExtractDotProductLoop)
}

func (m *emulatorX86) isLinkedListReverse(address uint32) bool {
	code, err := m.readMemory(address, len(emulatorLinkedListReverseLoop), 'x')
	return err == nil && bytes.Equal(code, emulatorLinkedListReverseLoop)
}

func (m *emulatorX86) isCRC16BitLoop(address uint32) bool {
	code, err := m.readMemory(address, len(emulatorCRC16BitLoop), 'x')
	return err == nil && bytes.Equal(code, emulatorCRC16BitLoop)
}

func (m *emulatorX86) isI16LinkedListSearch(address uint32) bool {
	code, err := m.readMemory(address, len(emulatorI16LinkedListSearchLoop), 'x')
	return err == nil && bytes.Equal(code, emulatorI16LinkedListSearchLoop)
}

func (m *emulatorX86) isU8LinkedListSearch(address uint32) bool {
	code, err := m.readMemory(address, len(emulatorU8LinkedListSearchLoop), 'x')
	return err == nil && bytes.Equal(code, emulatorU8LinkedListSearchLoop)
}

func (m *emulatorX86) dotProductIterations(start, limit uint32, remaining, instructionsPerIteration uint64) (uint64, bool) {
	if limit <= start || (limit-start)&1 != 0 {
		return 0, false
	}
	iterations := uint64((limit - start) / 2)
	if iterations > emulatorAcceleratedChunkSize || iterations > remaining/instructionsPerIteration {
		return 0, false
	}
	return iterations, true
}

func (m *emulatorX86) wideUnitScan(address uint32) (x86asm.Reg, uint16, bool) {
	code, err := m.readMemory(address, 11, 'x')
	if err != nil {
		return 0, 0, false
	}
	// mov ax,[cursor]; add cursor,2; test/cmp ax,terminator; jne loop
	switch {
	case bytes.Equal(code, []byte{0x66, 0x8b, 0x06, 0x83, 0xc6, 0x02, 0x66, 0x85, 0xc0, 0x75, 0xf5}):
		return x86asm.ESI, 0, true
	case bytes.Equal(code, []byte{0x66, 0x8b, 0x01, 0x83, 0xc1, 0x02, 0x66, 0x85, 0xc0, 0x75, 0xf5}):
		return x86asm.ECX, 0, true
	case bytes.Equal(code, []byte{0x66, 0x8b, 0x01, 0x83, 0xc1, 0x02, 0x66, 0x3b, 0xc6, 0x75, 0xf5}):
		return x86asm.ECX, uint16(m.registers[x86asm.ESI]), true
	case bytes.Equal(code, []byte{0x66, 0x8b, 0x01, 0x83, 0xc1, 0x02, 0x66, 0x3b, 0xc7, 0x75, 0xf5}):
		return x86asm.ECX, uint16(m.registers[x86asm.EDI]), true
	case bytes.Equal(code, []byte{0x66, 0x8b, 0x07, 0x83, 0xc7, 0x02, 0x66, 0x3b, 0xc6, 0x75, 0xf5}):
		return x86asm.EDI, uint16(m.registers[x86asm.ESI]), true
	default:
		return 0, 0, false
	}
}

func (m *emulatorX86) accelerateWideUnitScan(address uint32, remaining uint64) (uint64, bool, error) {
	cursorRegister, terminator, recognized := m.wideUnitScan(address)
	if !recognized || remaining == 0 {
		return 0, false, nil
	}
	const maximumUnits = 1 << 20
	cursor := m.registers[cursorRegister]
	for index := uint32(0); index < maximumUnits; index++ {
		unit, err := m.readUint16(cursor + index*2)
		if err != nil {
			return 0, true, err
		}
		if unit != terminator {
			continue
		}
		consumed := uint64(index + 1)
		m.registers[cursorRegister] = cursor + uint32(consumed*2)
		m.setRegisterValue(x86asm.AX, uint32(unit))
		m.subFlags(uint32(unit), uint32(terminator), 2)
		m.eip = address + 11
		work := (consumed + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
		return min(work, remaining), true, nil
	}
	return 0, true, fmt.Errorf("wide-unit scan exceeds %d code units", maximumUnits)
}

func (m *emulatorX86) isBoundedWideScan(address uint32) bool {
	code, err := m.readMemory(address, 11, 'x')
	return err == nil && bytes.Equal(code, []byte{0x66, 0x39, 0x19, 0x74, 0x06, 0x83, 0xc1, 0x02, 0x4a, 0x75, 0xf5})
}

func (m *emulatorX86) accelerateBoundedWideScan(address uint32, remaining uint64) (uint64, bool, error) {
	if !m.isBoundedWideScan(address) || remaining == 0 || m.registers[x86asm.EDX] == 0 {
		return 0, false, nil
	}
	const maximumUnits = 1 << 20
	units := uint64(0)
	terminator := uint16(m.registers[x86asm.EBX])
	for units < maximumUnits {
		unit, err := m.readUint16(m.registers[x86asm.ECX])
		if err != nil {
			return 0, true, err
		}
		m.subFlags(uint32(unit), uint32(terminator), 2)
		if unit == terminator {
			m.eip = address + 11
			work := (units + 1 + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
			return min(work, remaining), true, nil
		}
		cursor := m.registers[x86asm.ECX]
		m.registers[x86asm.ECX] = m.addFlags(cursor, 2, 4)
		carry := m.carry
		oldCount := m.registers[x86asm.EDX]
		m.registers[x86asm.EDX] = m.subFlags(oldCount, 1, 4)
		m.carry = carry
		units++
		if m.registers[x86asm.EDX] == 0 {
			m.eip = address + 11
			work := (units + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
			return min(work, remaining), true, nil
		}
	}
	return 0, true, fmt.Errorf("bounded wide scan exceeds %d code units", maximumUnits)
}

func (m *emulatorX86) isBoundedWideCopy(address uint32) bool {
	code, err := m.readMemory(address, 23, 'x')
	if err != nil {
		return false
	}
	// test esi,esi; jz done; movzx ebx,word ptr [eax+ecx]; test bx,bx;
	// jz done; mov word ptr [ecx],bx; add ecx,2; dec esi; dec edx; jnz loop
	return bytes.Equal(code, []byte{
		0x85, 0xf6, 0x74, 0x13, 0x0f, 0xb7, 0x1c, 0x08,
		0x66, 0x85, 0xdb, 0x74, 0x0a, 0x66, 0x89, 0x19,
		0x83, 0xc1, 0x02, 0x4e, 0x4a, 0x75, 0xe9,
	})
}

func (m *emulatorX86) accelerateBoundedWideCopy(address uint32, remaining uint64) (uint64, bool, error) {
	if !m.isBoundedWideCopy(address) || remaining == 0 {
		return 0, false, nil
	}
	const maximumUnits = 1 << 20
	units := uint64(0)
	for units < maximumUnits {
		if m.registers[x86asm.ESI] == 0 {
			m.logicalFlags(0, 4)
			m.eip = address + 23
			work := (units + 1 + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
			return min(work, remaining), true, nil
		}
		source := m.registers[x86asm.EAX] + m.registers[x86asm.ECX]
		unit, err := m.readUint16(source)
		if err != nil {
			return 0, true, err
		}
		m.setRegisterValue(x86asm.BX, uint32(unit))
		if unit == 0 {
			m.logicalFlags(0, 2)
			m.eip = address + 23
			work := (units + 1 + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
			return min(work, remaining), true, nil
		}
		encoded := [2]byte{}
		binary.LittleEndian.PutUint16(encoded[:], unit)
		if err := m.writeMemory(m.registers[x86asm.ECX], encoded[:]); err != nil {
			return 0, true, err
		}
		cursor := m.registers[x86asm.ECX]
		m.registers[x86asm.ECX] = m.addFlags(cursor, 2, 4)
		carry := m.carry
		m.registers[x86asm.ESI] = m.subFlags(m.registers[x86asm.ESI], 1, 4)
		m.carry = carry
		oldCount := m.registers[x86asm.EDX]
		m.registers[x86asm.EDX] = m.subFlags(oldCount, 1, 4)
		m.carry = carry
		units++
		if m.registers[x86asm.EDX] == 0 {
			m.eip = address + 23
			return min((units+emulatorAcceleratedWorkUnit-1)/emulatorAcceleratedWorkUnit, remaining), true, nil
		}
	}
	return 0, true, fmt.Errorf("bounded wide copy exceeds %d code units", maximumUnits)
}

func (m *emulatorX86) registerCRC32Table(address uint32) (uint32, bool) {
	code, err := m.readMemory(address, 30, 'x')
	if err != nil {
		return 0, false
	}
	fixed := map[int]byte{
		0: 0x0f, 1: 0xb6, 2: 0x02, 3: 0x8b, 4: 0xce,
		5: 0xc1, 6: 0xe9, 7: 0x18, 8: 0x33, 9: 0xc8,
		10: 0xc1, 11: 0xe6, 12: 0x08, 13: 0x81, 14: 0xe1,
		15: 0xff, 16: 0x00, 17: 0x00, 18: 0x00, 19: 0x33,
		20: 0x34, 21: 0x8d, 26: 0x42, 27: 0x4f, 28: 0x75, 29: 0xe2,
	}
	for offset, expected := range fixed {
		if code[offset] != expected {
			return 0, false
		}
	}
	return binary.LittleEndian.Uint32(code[22:26]), true
}

func (m *emulatorX86) accelerateRegisterCRC32(address uint32, remaining uint64) (uint64, bool, error) {
	tableAddress, recognized := m.registerCRC32Table(address)
	if !recognized || remaining == 0 || m.registers[x86asm.EDI] == 0 {
		return 0, false, nil
	}
	count := uint64(m.registers[x86asm.EDI])
	maximum := remaining * emulatorAcceleratedWorkUnit
	if maximum/remaining != emulatorAcceleratedWorkUnit {
		maximum = math.MaxUint64
	}
	count = min(count, maximum, uint64(emulatorAcceleratedChunkSize))
	data, err := m.readMemory(m.registers[x86asm.EDX], int(count), 'r')
	if err != nil {
		return 0, true, err
	}
	table, err := m.readMemory(tableAddress, 256*4, 'r')
	if err != nil {
		return 0, true, err
	}
	crc := m.registers[x86asm.ESI]
	index := uint32(0)
	for _, value := range data {
		index = crc>>24 ^ uint32(value)
		crc = crc<<8 ^ binary.LittleEndian.Uint32(table[index*4:index*4+4])
	}
	m.registers[x86asm.EAX] = uint32(data[len(data)-1])
	m.registers[x86asm.ECX] = index
	m.registers[x86asm.ESI] = crc
	m.registers[x86asm.EDX] += uint32(count)
	m.registers[x86asm.EDI] -= uint32(count)
	m.subFlags(m.registers[x86asm.EDI]+1, 1, 4)
	m.carry = false
	if m.registers[x86asm.EDI] == 0 {
		m.eip = address + 30
	}
	return (count + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit, true, nil
}

func (m *emulatorX86) accelerateI16DotProduct(address uint32, remaining uint64) (uint64, bool, error) {
	limit, err := m.readUint32(m.registers[x86asm.ESP])
	if err != nil {
		return 0, true, err
	}
	iterations, ok := m.dotProductIterations(m.registers[x86asm.EAX], limit, remaining, 8)
	if !ok {
		return 0, false, nil
	}
	left, right := m.registers[x86asm.EAX], m.registers[x86asm.ECX]
	stride := m.registers[x86asm.EBP]
	accumulator := m.registers[x86asm.EBX]
	var product int32
	var lastRight int16
	for index := uint64(0); index < iterations; index++ {
		leftValue, readErr := m.readUint16(left)
		if readErr != nil {
			return 0, true, readErr
		}
		rightValue, readErr := m.readUint16(right)
		if readErr != nil {
			return 0, true, readErr
		}
		product = int32(int16(leftValue)) * int32(int16(rightValue))
		lastRight = int16(rightValue)
		accumulator += uint32(product)
		left += 2
		right += stride
	}
	m.registers[x86asm.EAX] = left
	m.registers[x86asm.ECX] = right
	m.registers[x86asm.EDX] = uint32(product)
	m.registers[x86asm.EDI] = uint32(int32(lastRight))
	m.registers[x86asm.EBX] = accumulator
	m.subFlags(limit, left, 4)
	m.eip = address + uint32(len(emulatorI16DotProductLoop))
	return iterations * 8, true, nil
}

func (m *emulatorX86) accelerateI16BitExtractDotProduct(address uint32, remaining uint64) (uint64, bool, error) {
	limit, err := m.readUint32(m.registers[x86asm.ESP])
	if err != nil {
		return 0, true, err
	}
	iterations, ok := m.dotProductIterations(m.registers[x86asm.ECX], limit, remaining, 14)
	if !ok {
		return 0, false, nil
	}
	left, right := m.registers[x86asm.ECX], m.registers[x86asm.EBX]
	stride := m.registers[x86asm.EBP]
	accumulator := m.registers[x86asm.ESI]
	var extracted, product uint32
	for index := uint64(0); index < iterations; index++ {
		leftValue, readErr := m.readUint16(left)
		if readErr != nil {
			return 0, true, readErr
		}
		rightValue, readErr := m.readUint16(right)
		if readErr != nil {
			return 0, true, readErr
		}
		product = uint32(int32(int16(leftValue)) * int32(int16(rightValue)))
		extracted = uint32(int32(product)>>2) & 0x0f
		product = uint32(int32(product)>>5) & 0x7f
		extracted *= product
		accumulator += extracted
		left += 2
		right += stride
	}
	m.registers[x86asm.ECX] = left
	m.registers[x86asm.EBX] = right
	m.registers[x86asm.EDX] = product
	m.registers[x86asm.EDI] = extracted
	m.registers[x86asm.ESI] = accumulator
	m.subFlags(limit, left, 4)
	m.eip = address + uint32(len(emulatorI16BitExtractDotProductLoop))
	return iterations * 14, true, nil
}

func (m *emulatorX86) accelerateLinkedListReverse(address uint32, remaining uint64) (uint64, bool, error) {
	const maximumNodes = 65536
	nodeCount := 0
	for node := m.registers[x86asm.EDX]; node != 0; {
		if nodeCount == maximumNodes {
			return 0, false, nil
		}
		if _, _, err := m.mapping(node, 4, 'w'); err != nil {
			return 0, false, nil
		}
		next, err := m.readUint32(node)
		if err != nil {
			return 0, true, err
		}
		nodeCount++
		node = next
	}
	consumed := uint64(nodeCount) * 6
	if nodeCount == 0 || consumed > remaining {
		return 0, false, nil
	}
	previous := m.registers[x86asm.ECX]
	node := m.registers[x86asm.EDX]
	for node != 0 {
		next, err := m.readUint32(node)
		if err != nil {
			return 0, true, err
		}
		if err := m.writeUint32(node, previous); err != nil {
			return 0, true, err
		}
		previous = node
		m.registers[x86asm.EBX] = node
		node = next
	}
	m.registers[x86asm.EDX] = 0
	m.registers[x86asm.ECX] = previous
	m.logicalFlags(0, 4)
	m.eip = address + uint32(len(emulatorLinkedListReverseLoop))
	return consumed, true, nil
}

func (m *emulatorX86) accelerateCRC16BitLoop(address uint32, remaining uint64) (uint64, bool, error) {
	eax := m.registers[x86asm.EAX]
	ebx := m.registers[x86asm.EBX]
	ecx := m.registers[x86asm.ECX]
	edx := m.registers[x86asm.EDX]
	iterations := uint64(uint8(ebx))
	consumed := iterations * 10
	if iterations == 0 || consumed > remaining {
		return 0, false, nil
	}
	for index := uint64(0); index < iterations; index++ {
		edx = edx&^0xff | ecx&0xff
		edx ^= eax
		ecx = ecx&^0xff | (ecx&0xff)>>1
		eax = eax&^0xffff | (eax&0xffff)>>1
		edx &= 1
		edx = -edx
		edx &= 0xffffa001
		eax ^= edx
		ebx = ebx&^0xff | uint32(uint8(ebx)-1)
	}
	m.registers[x86asm.EAX] = eax
	m.registers[x86asm.EBX] = ebx
	m.registers[x86asm.ECX] = ecx
	m.registers[x86asm.EDX] = edx
	m.logicalFlags(uint32(uint8(ebx)), 1)
	m.eip = address + uint32(len(emulatorCRC16BitLoop))
	return consumed, true, nil
}

func (m *emulatorX86) accelerateI16LinkedListSearch(address uint32, remaining uint64) (uint64, bool, error) {
	const maximumNodes = 65536
	node := m.registers[x86asm.EAX]
	comparison := uint16(m.registers[x86asm.EDX])
	consumed := uint64(0)
	for range maximumNodes {
		next, err := m.readUint32(node)
		if err != nil {
			return 0, true, err
		}
		if next == 0 {
			consumed += 3
			if consumed > remaining {
				return 0, false, nil
			}
			m.registers[x86asm.EAX] = 0
			m.logicalFlags(0, 4)
			m.eip = address + 0xa8
			return consumed, true, nil
		}
		info, err := m.readUint32(next + 4)
		if err != nil {
			return 0, true, err
		}
		value, err := m.readUint16(info + 2)
		if err != nil {
			return 0, true, err
		}
		consumed += 7
		if consumed > remaining {
			return 0, false, nil
		}
		if value == comparison {
			m.registers[x86asm.EAX] = next
			m.registers[x86asm.ECX] = info
			m.setRegisterValue(x86asm.SI, uint32(value))
			m.subFlags(uint32(value), uint32(comparison), 2)
			m.eip = address + uint32(len(emulatorI16LinkedListSearchLoop))
			return consumed, true, nil
		}
		node = next
	}
	return 0, false, nil
}

func (m *emulatorX86) accelerateU8LinkedListSearch(address uint32, remaining uint64) (uint64, bool, error) {
	const maximumNodes = 65536
	node := m.registers[x86asm.EAX]
	comparison := uint16(m.registers[x86asm.EDX])
	consumed := uint64(0)
	for range maximumNodes {
		next, err := m.readUint32(node)
		if err != nil {
			return 0, true, err
		}
		if next == 0 {
			consumed += 3
			if consumed > remaining {
				return 0, false, nil
			}
			m.registers[x86asm.EAX] = 0
			m.logicalFlags(0, 4)
			m.eip = address + 0x3c
			return consumed, true, nil
		}
		info, err := m.readUint32(next + 4)
		if err != nil {
			return 0, true, err
		}
		data, err := m.readMemory(info, 1, 'r')
		if err != nil {
			return 0, true, err
		}
		value := uint16(data[0])
		consumed += 7
		if consumed > remaining {
			return 0, false, nil
		}
		if value == comparison {
			m.registers[x86asm.EAX] = next
			m.registers[x86asm.ECX] = info
			m.registers[x86asm.EDI] = uint32(value)
			m.subFlags(uint32(value), uint32(comparison), 2)
			m.eip = address + uint32(len(emulatorU8LinkedListSearchLoop))
			return consumed, true, nil
		}
		node = next
	}
	return 0, false, nil
}

func (m *emulatorX86) accelerator(address uint32) emulatorAccelerator {
	pageNumber := address >> 12
	page := m.decodedPage
	if page == nil || m.decodedPageNumber != pageNumber {
		page = m.decodedPages[pageNumber]
		if page == nil {
			page = new(emulatorDecodedPage)
			m.decodedPages[pageNumber] = page
		}
		m.decodedPage = page
		m.decodedPageNumber = pageNumber
	}
	offset := address & 0xfff
	if kind := page.accelerators[offset]; kind != emulatorAcceleratorUnchecked {
		return kind
	}
	return m.detectAccelerator(address, page, offset)
}

func (m *emulatorX86) detectAccelerator(address uint32, page *emulatorDecodedPage, offset uint32) emulatorAccelerator {
	m.cachedCodePages[address>>12] = true
	kind := emulatorAcceleratorNone
	switch {
	case m.isZeroByteScan(address):
		kind = emulatorAcceleratorZeroByteScan
	case func() bool { _, _, ok := m.wideUnitScan(address); return ok }():
		kind = emulatorAcceleratorWideUnitScan
	case m.isBoundedWideScan(address):
		kind = emulatorAcceleratorBoundedWideScan
	case m.isBoundedWideCopy(address):
		kind = emulatorAcceleratorBoundedWideCopy
	case m.isMixedASCIIFoldCompare(address):
		kind = emulatorAcceleratorMixedASCIIFoldCompare
	case m.isASCIILower(address):
		kind = emulatorAcceleratorASCIILower
	case m.isWideASCIIValidate(address):
		kind = emulatorAcceleratorWideASCIIValidate
	case m.isWideASCIICompare(address):
		kind = emulatorAcceleratorWideASCIICompare
	case m.crc32Loop(address) != nil:
		kind = emulatorAcceleratorCRC32
	case m.isI16DotProduct(address):
		kind = emulatorAcceleratorI16DotProduct
	case m.isI16BitExtractDotProduct(address):
		kind = emulatorAcceleratorI16BitExtractDotProduct
	case m.isLinkedListReverse(address):
		kind = emulatorAcceleratorLinkedListReverse
	case m.isCRC16BitLoop(address):
		kind = emulatorAcceleratorCRC16BitLoop
	case m.isI16LinkedListSearch(address):
		kind = emulatorAcceleratorI16LinkedListSearch
	case m.isU8LinkedListSearch(address):
		kind = emulatorAcceleratorU8LinkedListSearch
	case func() bool { _, ok := m.registerCRC32Table(address); return ok }():
		kind = emulatorAcceleratorRegisterCRC32
	}
	page.accelerators[offset] = kind
	return kind
}

func emulatorConditionalJump(operation x86asm.Op) bool {
	switch operation {
	case x86asm.JECXZ, x86asm.JE, x86asm.JNE, x86asm.JB, x86asm.JAE,
		x86asm.JBE, x86asm.JA, x86asm.JL, x86asm.JGE, x86asm.JLE,
		x86asm.JG, x86asm.JS, x86asm.JNS, x86asm.JP, x86asm.JNP:
		return true
	default:
		return false
	}
}

func (m *emulatorX86) accelerateLoopBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	patternValue := starlark.Value(starlark.None)
	digestValue := starlark.Value(starlark.None)
	size := 0
	normalizeRelative := false
	maximumInstructions := 1 << 20
	if err := starlark.UnpackArgs("accelerate_loop", args, kwargs,
		"address", &address,
		"pattern?", &patternValue,
		"size?", &size,
		"digest?", &digestValue,
		"normalize_relative?", &normalizeRelative,
		"maximum_instructions?", &maximumInstructions,
	); err != nil {
		return nil, err
	}
	pattern, hasPattern := patternValue.(starlark.Bytes)
	digest, hasDigest := digestValue.(starlark.Bytes)
	if hasPattern {
		size = len(pattern)
	}
	if m.frozen || address > math.MaxUint32 || hasPattern == hasDigest || size < 2 || size > 1<<20 || uint64(size) > uint64(math.MaxUint32)+1-address || (hasDigest && len(digest) != sha256.Size) || maximumInstructions <= 0 || maximumInstructions > 1<<26 {
		return nil, fmt.Errorf("accelerate_loop: invalid address, pattern, instruction limit, or frozen machine")
	}
	start := uint32(address)
	end := start + uint32(size)
	code, err := m.readMemory(start, size, 'x')
	if err != nil {
		return nil, fmt.Errorf("accelerate_loop: %w", err)
	}
	if hasPattern && !bytes.Equal(code, []byte(pattern)) {
		return nil, fmt.Errorf("accelerate_loop: pattern does not match executable memory at 0x%08x", start)
	}
	if hasDigest {
		actual, digestErr := emulatorCodeDigest(code, normalizeRelative)
		if digestErr != nil {
			return nil, fmt.Errorf("accelerate_loop: %w", digestErr)
		}
		if !bytes.Equal(actual[:], []byte(digest)) {
			return nil, fmt.Errorf("accelerate_loop: digest does not match executable memory at 0x%08x", start)
		}
	}

	offset := 0
	instructionCount := uint64(0)
	hasConditionalExit := false
	for offset < len(code) {
		instruction, decodeErr := x86asm.Decode(code[offset:], 32)
		if decodeErr != nil || instruction.Len == 0 || offset+instruction.Len > len(code) {
			return nil, fmt.Errorf("accelerate_loop: invalid instruction at pattern offset %#x: %v", offset, decodeErr)
		}
		instructionAddress := start + uint32(offset)
		next := instructionAddress + uint32(instruction.Len)
		last := offset+instruction.Len == len(code)
		if instruction.Op == x86asm.CALL || instruction.Op == x86asm.RET || instruction.Op == x86asm.RDTSC {
			return nil, fmt.Errorf("accelerate_loop: unsafe %s at pattern offset %#x", instruction.Op, offset)
		}
		if instruction.Op == x86asm.JMP || emulatorConditionalJump(instruction.Op) {
			relative, ok := instruction.Args[0].(x86asm.Rel)
			if !ok {
				return nil, fmt.Errorf("accelerate_loop: indirect %s at pattern offset %#x", instruction.Op, offset)
			}
			target := uint32(int64(next) + int64(relative))
			if last {
				if target != start || (instruction.Op == x86asm.JMP && !hasConditionalExit) {
					return nil, fmt.Errorf("accelerate_loop: final instruction must be a bounded back edge to 0x%08x", start)
				}
			} else if target < start || target >= end {
				// Conditional exits are valid. An unconditional jump outside the
				// region would make the final back edge unreachable.
				if instruction.Op == x86asm.JMP {
					return nil, fmt.Errorf("accelerate_loop: unconditional exit at pattern offset %#x", offset)
				}
				hasConditionalExit = true
			}
		} else if last {
			return nil, fmt.Errorf("accelerate_loop: pattern has no final conditional back edge")
		}
		offset += instruction.Len
		instructionCount++
	}

	m.loopAccelerations[start] = emulatorLoopAcceleration{
		start:               start,
		end:                 end,
		maximumInstructions: uint64(maximumInstructions),
		instructionCount:    instructionCount,
		pattern:             bytes.Clone(code),
	}
	return newStarlarkRecord(map[string]starlark.Value{
		"address":      starlark.MakeUint64(address),
		"size":         starlark.MakeInt(size),
		"instructions": starlark.MakeUint64(instructionCount),
	}), nil
}

func (m *emulatorX86) accelerateRegionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var entry, start uint64
	var digest starlark.Bytes
	size := 0
	reenter := false
	maximumInstructions := 1 << 20
	if err := starlark.UnpackArgs("accelerate_region", args, kwargs,
		"entry", &entry,
		"start", &start,
		"size", &size,
		"digest", &digest,
		"reenter?", &reenter,
		"maximum_instructions?", &maximumInstructions,
	); err != nil {
		return nil, err
	}
	end := start + uint64(size)
	if m.frozen || start > math.MaxUint32 || size <= 0 || size > 1<<20 || end > uint64(math.MaxUint32) || entry < start || entry >= end || len(digest) != sha256.Size || maximumInstructions <= 0 || maximumInstructions > 1<<26 {
		return nil, fmt.Errorf("accelerate_region: invalid executable region, digest, instruction limit, or frozen machine")
	}
	code, err := m.readMemory(uint32(start), size, 'x')
	if err != nil {
		return nil, fmt.Errorf("accelerate_region: %w", err)
	}
	actual := sha256.Sum256(code)
	if !bytes.Equal(actual[:], []byte(digest)) {
		return nil, fmt.Errorf("accelerate_region: digest does not match executable memory at 0x%08x", start)
	}
	var expected [sha256.Size]byte
	copy(expected[:], digest)
	for _, existing := range m.regionAccelerations {
		if (reenter || existing.reenter) && start < uint64(existing.end) && end > uint64(existing.start) {
			return nil, fmt.Errorf("accelerate_region: re-entering executable regions must not overlap")
		}
	}
	m.regionAccelerations[uint32(entry)] = emulatorRegionAcceleration{
		entry:               uint32(entry),
		start:               uint32(start),
		end:                 uint32(end),
		reenter:             reenter,
		maximumInstructions: uint64(maximumInstructions),
		digest:              expected,
	}
	return newStarlarkRecord(map[string]starlark.Value{
		"entry":   starlark.MakeUint64(entry),
		"start":   starlark.MakeUint64(start),
		"size":    starlark.MakeInt(size),
		"reenter": starlark.Bool(reenter),
	}), nil
}

func (m *emulatorX86) rewriteBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	patternValue := starlark.Value(starlark.None)
	digestValue := starlark.Value(starlark.None)
	var callback starlark.Callable
	size := 0
	name := "inline rewrite"
	normalizeRelative := false
	if err := starlark.UnpackArgs("rewrite", args, kwargs,
		"address", &address,
		"pattern?", &patternValue,
		"size?", &size,
		"digest?", &digestValue,
		"callback", &callback,
		"name?", &name,
		"normalize_relative?", &normalizeRelative,
	); err != nil {
		return nil, err
	}
	pattern, hasPattern := patternValue.(starlark.Bytes)
	digest, hasDigest := digestValue.(starlark.Bytes)
	if hasPattern {
		size = len(pattern)
	}
	if m.frozen || address > math.MaxUint32 || hasPattern == hasDigest || size <= 0 || size > 1<<20 || uint64(size) > uint64(math.MaxUint32)+1-address || (hasDigest && len(digest) != sha256.Size) || name == "" {
		return nil, fmt.Errorf("rewrite: invalid address, pattern, name, or frozen machine")
	}
	start := uint32(address)
	code, err := m.readMemory(start, size, 'x')
	if err != nil {
		return nil, fmt.Errorf("rewrite: %w", err)
	}
	if hasPattern && !bytes.Equal(code, []byte(pattern)) {
		return nil, fmt.Errorf("rewrite: pattern does not match executable memory at 0x%08x", start)
	}
	if hasDigest {
		actual, digestErr := emulatorCodeDigest(code, normalizeRelative)
		if digestErr != nil {
			return nil, fmt.Errorf("rewrite: %w", digestErr)
		}
		if !bytes.Equal(actual[:], []byte(digest)) {
			return nil, fmt.Errorf("rewrite: digest does not match executable memory at 0x%08x", start)
		}
	}
	m.rewrites[start] = emulatorRewrite{
		start:    start,
		end:      start + uint32(size),
		name:     name,
		pattern:  bytes.Clone(code),
		callback: callback,
	}
	return newStarlarkRecord(map[string]starlark.Value{
		"address": starlark.MakeUint64(address),
		"size":    starlark.MakeInt(size),
		"name":    starlark.String(name),
	}), nil
}

func emulatorCodeDigest(code []byte, normalizeRelative bool) ([sha256.Size]byte, error) {
	normalized := bytes.Clone(code)
	for offset := 0; offset < len(normalized); {
		instruction, err := x86asm.Decode(normalized[offset:], 32)
		if err != nil || instruction.Len == 0 || offset+instruction.Len > len(normalized) {
			return [sha256.Size]byte{}, fmt.Errorf("decode at offset %#x: %v", offset, err)
		}
		if normalizeRelative && instruction.PCRel > 0 {
			start := offset + instruction.PCRelOff
			end := start + instruction.PCRel
			if start < offset || end > offset+instruction.Len {
				return [sha256.Size]byte{}, fmt.Errorf("invalid relative operand at offset %#x", offset)
			}
			clear(normalized[start:end])
		}
		offset += instruction.Len
	}
	return sha256.Sum256(normalized), nil
}

func (m *emulatorX86) transformBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var anchor starlark.Bytes
	anchorMaskValue := starlark.Value(starlark.None)
	var digest starlark.Bytes
	var callback starlark.Callable
	size := 0
	name := "runtime transformation"
	normalizeRelative := true
	if err := starlark.UnpackArgs("transform", args, kwargs,
		"anchor", &anchor,
		"anchor_mask?", &anchorMaskValue,
		"size", &size,
		"digest", &digest,
		"callback", &callback,
		"name?", &name,
		"normalize_relative?", &normalizeRelative,
	); err != nil {
		return nil, err
	}
	anchorMask := bytes.Repeat([]byte{0xff}, len(anchor))
	if anchorMaskValue != starlark.None {
		value, ok := anchorMaskValue.(starlark.Bytes)
		if !ok || len(value) != len(anchor) {
			return nil, fmt.Errorf("transform: anchor_mask must be bytes matching anchor length")
		}
		copy(anchorMask, value)
	}
	fixedBits := 0
	for _, value := range anchorMask {
		fixedBits += bits.OnesCount8(value)
	}
	if m.frozen || len(m.transformations) >= 256 || len(anchor) == 0 || len(anchor) > 64 || fixedBits < 32 || size < len(anchor) || size > 1<<20 || len(digest) != sha256.Size || name == "" {
		return nil, fmt.Errorf("transform: invalid anchor, size, digest, name, transformation limit, or frozen machine")
	}
	var expected [sha256.Size]byte
	copy(expected[:], digest)
	for _, transformation := range m.transformations {
		if transformation.size == uint32(size) && transformation.normalizeRelative == normalizeRelative && bytes.Equal(transformation.anchor, []byte(anchor)) && bytes.Equal(transformation.anchorMask, anchorMask) && transformation.digest == expected {
			return nil, fmt.Errorf("transform: duplicate signature for %q", transformation.name)
		}
	}
	m.transformations = append(m.transformations, emulatorTransformation{
		name:              name,
		anchor:            bytes.Clone([]byte(anchor)),
		anchorMask:        bytes.Clone(anchorMask),
		size:              uint32(size),
		digest:            expected,
		normalizeRelative: normalizeRelative,
		callback:          callback,
	})
	clear(m.transformationCache)
	clear(m.runtimeRegions)
	return newStarlarkRecord(map[string]starlark.Value{
		"id":                 starlark.MakeInt(len(m.transformations) - 1),
		"name":               starlark.String(name),
		"size":               starlark.MakeInt(size),
		"normalize_relative": starlark.Bool(normalizeRelative),
	}), nil
}

func (m *emulatorX86) accelerateRuntimeRegionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var anchor starlark.Bytes
	anchorMaskValue := starlark.Value(starlark.None)
	var digest starlark.Bytes
	size := 0
	entryOffset := 0
	name := "runtime executable region"
	normalizeRelative := true
	reenter := false
	maximumInstructions := 1 << 20
	if err := starlark.UnpackArgs("accelerate_runtime_region", args, kwargs,
		"anchor", &anchor,
		"anchor_mask?", &anchorMaskValue,
		"size", &size,
		"digest", &digest,
		"entry_offset?", &entryOffset,
		"name?", &name,
		"normalize_relative?", &normalizeRelative,
		"reenter?", &reenter,
		"maximum_instructions?", &maximumInstructions,
	); err != nil {
		return nil, err
	}
	anchorMask := bytes.Repeat([]byte{0xff}, len(anchor))
	if anchorMaskValue != starlark.None {
		value, ok := anchorMaskValue.(starlark.Bytes)
		if !ok || len(value) != len(anchor) {
			return nil, fmt.Errorf("accelerate_runtime_region: anchor_mask must be bytes matching anchor length")
		}
		copy(anchorMask, value)
	}
	fixedBits := 0
	for _, value := range anchorMask {
		fixedBits += bits.OnesCount8(value)
	}
	if m.frozen || len(m.transformations) >= 256 || len(anchor) == 0 || len(anchor) > 64 || fixedBits < 32 || size < len(anchor) || size > 1<<20 || entryOffset < 0 || entryOffset >= size || len(digest) != sha256.Size || name == "" || maximumInstructions <= 0 || maximumInstructions > 1<<26 {
		return nil, fmt.Errorf("accelerate_runtime_region: invalid signature, region, instruction limit, name, transformation limit, or frozen machine")
	}
	var expected [sha256.Size]byte
	copy(expected[:], digest)
	for _, transformation := range m.transformations {
		if transformation.size == uint32(size) && transformation.normalizeRelative == normalizeRelative && bytes.Equal(transformation.anchor, []byte(anchor)) && bytes.Equal(transformation.anchorMask, anchorMask) && transformation.digest == expected {
			return nil, fmt.Errorf("accelerate_runtime_region: duplicate signature for %q", transformation.name)
		}
	}
	m.transformations = append(m.transformations, emulatorTransformation{
		name:                name,
		anchor:              bytes.Clone([]byte(anchor)),
		anchorMask:          bytes.Clone(anchorMask),
		size:                uint32(size),
		digest:              expected,
		normalizeRelative:   normalizeRelative,
		runtimeRegion:       true,
		entryOffset:         uint32(entryOffset),
		reenter:             reenter,
		maximumInstructions: uint64(maximumInstructions),
	})
	clear(m.transformationCache)
	clear(m.runtimeRegions)
	return newStarlarkRecord(map[string]starlark.Value{
		"id":                 starlark.MakeInt(len(m.transformations) - 1),
		"name":               starlark.String(name),
		"size":               starlark.MakeInt(size),
		"entry_offset":       starlark.MakeInt(entryOffset),
		"normalize_relative": starlark.Bool(normalizeRelative),
		"reenter":            starlark.Bool(reenter),
	}), nil
}

func (m *emulatorX86) transformationAt(address uint32) (emulatorRewrite, bool, error) {
	if match, ok := m.transformationCache[address]; ok {
		if match.ambiguous {
			return emulatorRewrite{}, false, fmt.Errorf("ambiguous runtime transformation at 0x%08x", address)
		}
		if match.index < 0 {
			return emulatorRewrite{}, false, nil
		}
		transformation := m.transformations[match.index]
		code, err := m.readMemory(address, int(transformation.size), 'x')
		if err != nil {
			delete(m.transformationCache, address)
			return emulatorRewrite{}, false, nil
		}
		resolved := emulatorRewrite{start: address, end: address + transformation.size, name: transformation.name, pattern: bytes.Clone(code), callback: transformation.callback}
		if transformation.runtimeRegion {
			region := emulatorRegionAcceleration{
				entry: address + transformation.entryOffset, start: address, end: address + transformation.size,
				reenter: transformation.reenter, maximumInstructions: transformation.maximumInstructions, digest: transformation.digest,
			}
			resolved.region = &region
		}
		return resolved, true, nil
	}

	matched := -1
	var matchedCode []byte
	for index, transformation := range m.transformations {
		if uint64(address)+uint64(transformation.size) > uint64(math.MaxUint32)+1 {
			continue
		}
		anchor, err := m.readMemory(address, len(transformation.anchor), 'x')
		if err != nil {
			continue
		}
		anchorMatches := true
		for offset := range anchor {
			if anchor[offset]&transformation.anchorMask[offset] != transformation.anchor[offset]&transformation.anchorMask[offset] {
				anchorMatches = false
				break
			}
		}
		if !anchorMatches {
			continue
		}
		code, err := m.readMemory(address, int(transformation.size), 'x')
		if err != nil {
			continue
		}
		digest, err := emulatorCodeDigest(code, transformation.normalizeRelative)
		if err != nil || digest != transformation.digest {
			continue
		}
		if matched >= 0 {
			m.transformationCache[address] = emulatorTransformationMatch{ambiguous: true}
			return emulatorRewrite{}, false, fmt.Errorf("ambiguous runtime transformation at 0x%08x", address)
		}
		matched = index
		matchedCode = code
	}
	if matched < 0 {
		m.transformationCache[address] = emulatorTransformationMatch{index: -1}
		return emulatorRewrite{}, false, nil
	}
	m.transformationCache[address] = emulatorTransformationMatch{index: matched}
	transformation := m.transformations[matched]
	resolved := emulatorRewrite{start: address, end: address + transformation.size, name: transformation.name, pattern: bytes.Clone(matchedCode), callback: transformation.callback}
	if transformation.runtimeRegion {
		region := emulatorRegionAcceleration{
			entry: address + transformation.entryOffset, start: address, end: address + transformation.size,
			reenter: transformation.reenter, maximumInstructions: transformation.maximumInstructions, digest: transformation.digest,
		}
		resolved.region = &region
	}
	return resolved, true, nil
}

func (m *emulatorX86) invokeRewrite(thread *starlark.Thread, rewrite emulatorRewrite) (string, string) {
	event := newStarlarkRecord(map[string]starlark.Value{
		"machine": m,
		"name":    starlark.String(rewrite.name),
		"address": starlark.MakeUint64(uint64(rewrite.start)),
		"end":     starlark.MakeUint64(uint64(rewrite.end)),
		"code":    starlark.Bytes(bytes.Clone(rewrite.pattern)),
	})
	m.hookDepth++
	result, err := starlark.Call(thread, rewrite.callback, starlark.Tuple{event}, nil)
	m.hookDepth--
	if err != nil {
		m.pendingTransfer = false
		return "plugin", fmt.Sprintf("rewrite %s: %v", rewrite.name, err)
	}
	if result != starlark.None {
		value, ok := emulatorHookResult(result)
		if !ok {
			m.pendingTransfer = false
			return "plugin", fmt.Sprintf("rewrite %s returned %s, want int or None", rewrite.name, result.Type())
		}
		m.registers[x86asm.EAX] = value
	}
	if m.pendingStop != "" {
		stop, detail := m.pendingStop, m.pendingStopDetail
		m.pendingStop, m.pendingStopDetail = "", ""
		m.pendingTransfer = false
		return stop, detail
	}
	if !m.pendingTransfer {
		return "plugin", fmt.Sprintf("rewrite %s did not transfer control", rewrite.name)
	}
	m.pendingTransfer = false
	if m.eip >= rewrite.start && m.eip < rewrite.end {
		return "plugin", fmt.Sprintf("rewrite %s transferred into its own matched region", rewrite.name)
	}
	return "", ""
}

func (m *emulatorX86) codeWatchOverlaps(start, end uint32) bool {
	for _, watch := range m.codeWatches {
		watchEnd := uint64(watch.start) + watch.size
		if uint64(start) < watchEnd && uint64(watch.start) < uint64(end) {
			return true
		}
	}
	return false
}

func (m *emulatorX86) accelerateRegisteredLoop(thread *starlark.Thread, loop emulatorLoopAcceleration, remaining uint64) (uint64, bool, string, string, error) {
	if remaining == 0 || m.eip != loop.start {
		return 0, false, "", "", nil
	}
	maximum := remaining * emulatorAcceleratedWorkUnit
	if maximum/remaining != emulatorAcceleratedWorkUnit {
		maximum = math.MaxUint64
	}
	maximum = min(maximum, loop.maximumInstructions)
	// Complete the current iteration after reaching the chunk boundary. This
	// guarantees the next dispatch is either outside the region or at its
	// registered entry, while exceeding the bound by at most one loop body.
	hardMaximum := maximum + loop.instructionCount
	if hardMaximum < maximum {
		hardMaximum = math.MaxUint64
	}
	executed := uint64(0)
	for executed < hardMaximum {
		if m.eip < loop.start || m.eip >= loop.end {
			break
		}
		if executed >= maximum && m.eip == loop.start {
			break
		}
		address := m.eip
		instruction, cached := m.decoded[address]
		if !cached {
			code, err := m.readMemory(address, min(15, int(loop.end-address)), 'x')
			if err != nil {
				return 0, true, "", "", err
			}
			decoded, decodeErr := x86asm.Decode(code, 32)
			if decodeErr != nil || decoded.Len == 0 {
				return 0, true, "", "", fmt.Errorf("accelerated loop decode at 0x%08x: %v", address, decodeErr)
			}
			instruction = &decoded
			m.cacheDecodedInstruction(address, instruction)
			m.cachedCodePages[address>>12] = true
		}
		m.currentInstruction = address
		if m.codeWatchAt(address) {
			m.recordCodeTrace(address, x86asm.IntelSyntax(*instruction, uint64(address), nil))
		}
		m.recentEIPs[m.recentEIPCursor] = address
		m.recentEIPCursor = (m.recentEIPCursor + 1) % len(m.recentEIPs)
		if m.recentEIPCount < len(m.recentEIPs) {
			m.recentEIPCount++
		}
		stop, detail, err := m.execute(thread, instruction, address+uint32(instruction.Len))
		executed++
		if err != nil {
			return 0, true, "", "", err
		}
		if stop != "" {
			work := (executed + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
			return min(work, remaining), true, stop, detail, nil
		}
	}
	if executed == 0 {
		return 0, false, "", "", nil
	}
	work := (executed + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
	return min(work, remaining), true, "", "", nil
}

func (m *emulatorX86) accelerateRegisteredRegion(thread *starlark.Thread, region emulatorRegionAcceleration, remaining uint64) (uint64, bool, string, string, error) {
	if remaining == 0 || (m.eip != region.entry && !region.reenter) || m.eip < region.start || m.eip >= region.end {
		return 0, false, "", "", nil
	}
	maximum := remaining * emulatorAcceleratedWorkUnit
	if maximum/remaining != emulatorAcceleratedWorkUnit {
		maximum = math.MaxUint64
	}
	maximum = min(maximum, region.maximumInstructions)
	executed := uint64(0)
	for executed < maximum && m.eip >= region.start && m.eip < region.end {
		address := m.eip
		instruction, cached := m.decoded[address]
		if !cached {
			code, err := m.readMemory(address, 15, 'x')
			if err != nil {
				mapping, offset, mapErr := m.mapping(address, 1, 'x')
				if mapErr != nil {
					return 0, true, "", "", err
				}
				code = mapping.data[offset:]
			}
			decoded, decodeErr := x86asm.Decode(code, 32)
			if decodeErr != nil || decoded.Len == 0 {
				return 0, true, "", "", fmt.Errorf("accelerated region decode at 0x%08x: %v", address, decodeErr)
			}
			instruction = &decoded
			m.cacheDecodedInstruction(address, instruction)
			m.cachedCodePages[address>>12] = true
		}
		m.currentInstruction = address
		if m.codeWatchAt(address) {
			m.recordCodeTrace(address, x86asm.IntelSyntax(*instruction, uint64(address), nil))
		}
		m.recentEIPs[m.recentEIPCursor] = address
		m.recentEIPCursor = (m.recentEIPCursor + 1) % len(m.recentEIPs)
		if m.recentEIPCount < len(m.recentEIPs) {
			m.recentEIPCount++
		}
		stop, detail, err := m.execute(thread, instruction, address+uint32(instruction.Len))
		executed++
		if err != nil {
			return 0, true, "", "", err
		}
		if stop != "" {
			work := (executed + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
			return min(work, remaining), true, stop, detail, nil
		}
	}
	if executed == 0 {
		return 0, false, "", "", nil
	}
	work := (executed + emulatorAcceleratedWorkUnit - 1) / emulatorAcceleratedWorkUnit
	return min(work, remaining), true, "", "", nil
}

func (m *emulatorX86) regionAccelerationAt(address uint32) (emulatorRegionAcceleration, bool) {
	if region, ok := m.regionAccelerations[address]; ok {
		return region, true
	}
	for _, region := range m.regionAccelerations {
		if region.reenter && address >= region.start && address < region.end {
			return region, true
		}
	}
	if region, ok := m.runtimeRegions[address]; ok {
		return region, true
	}
	for _, region := range m.runtimeRegions {
		if region.reenter && address >= region.start && address < region.end {
			return region, true
		}
	}
	return emulatorRegionAcceleration{}, false
}

func (m *emulatorX86) sampleProfile(address uint32) {
	if !m.profile {
		return
	}
	m.profileOperations++
	if m.profileOperations%m.profileInterval != 0 {
		return
	}
	m.profileSamples++
	if _, tracked := m.profileCounts[address]; tracked || len(m.profileCounts) < m.profileLimit {
		m.profileCounts[address]++
		return
	}
	// Keep a bounded Misra-Gries table so sustained later hot spots can
	// displace one-time startup instructions. Counts are lower bounds when
	// dropped is nonzero, but their ordering remains useful for profiling.
	m.profileDropped++
	for candidate, count := range m.profileCounts {
		if count == 1 {
			delete(m.profileCounts, candidate)
		} else {
			m.profileCounts[candidate] = count - 1
		}
	}
}

func (m *emulatorX86) run(thread *starlark.Thread) (starlark.Value, error) {
	if m.frozen {
		return nil, fmt.Errorf("run: machine is frozen")
	}
	previousInstruction := m.currentInstruction
	defer func() { m.currentInstruction = previousInstruction }()
	m.traceEntries = nil
	m.traceCursor = 0
	steps := uint64(0)
	for steps < m.instructionLimit {
		if m.eip == 0 {
			return m.result("return", steps, ""), nil
		}
		address := m.eip
		m.currentInstruction = address
		m.sampleProfile(address)
		pageNumber := address >> 12
		page := m.decodedPage
		if page == nil || m.decodedPageNumber != pageNumber {
			page = m.decodedPages[pageNumber]
			if page == nil {
				page = new(emulatorDecodedPage)
				m.decodedPages[pageNumber] = page
			}
			m.decodedPage = page
			m.decodedPageNumber = pageNumber
		}
		offset := address & 0xfff
		watchCode := m.codeWatchAt(address)
		if rewrite, ok := m.rewrites[address]; ok && !m.trace && !m.codeWatchOverlaps(rewrite.start, rewrite.end) {
			stop, detail := m.invokeRewrite(thread, rewrite)
			steps++
			m.timestampCounter++
			if stop != "" {
				return m.result(stop, steps, detail), nil
			}
			continue
		}
		if !m.trace && len(m.transformations) != 0 {
			transformation, matched, err := m.transformationAt(address)
			if err != nil {
				return m.result("plugin", steps, err.Error()), nil
			}
			if matched {
				if transformation.region != nil {
					m.runtimeRegions[transformation.region.entry] = *transformation.region
				} else if !m.codeWatchOverlaps(transformation.start, transformation.end) {
					stop, detail := m.invokeRewrite(thread, transformation)
					steps++
					m.timestampCounter++
					if stop != "" {
						return m.result(stop, steps, detail), nil
					}
					continue
				}
			}
		}
		if !m.trace {
			consumed := uint64(1)
			accelerated := false
			acceleratedStop := ""
			acceleratedDetail := ""
			var err error
			if region, ok := m.regionAccelerationAt(address); ok {
				consumed, accelerated, acceleratedStop, acceleratedDetail, err = m.accelerateRegisteredRegion(thread, region, m.instructionLimit-steps)
			}
			if !accelerated {
				if loop, ok := m.loopAccelerations[address]; ok {
					consumed, accelerated, acceleratedStop, acceleratedDetail, err = m.accelerateRegisteredLoop(thread, loop, m.instructionLimit-steps)
				}
			}
			kind := emulatorAcceleratorNone
			if !accelerated && !watchCode {
				kind = page.accelerators[offset]
				if kind == emulatorAcceleratorUnchecked {
					kind = m.detectAccelerator(address, page, offset)
				}
			}
			switch kind {
			case emulatorAcceleratorZeroByteScan:
				consumed, accelerated, err = m.accelerateZeroByteScan(address, m.instructionLimit-steps)
			case emulatorAcceleratorWideUnitScan:
				consumed, accelerated, err = m.accelerateWideUnitScan(address, m.instructionLimit-steps)
			case emulatorAcceleratorBoundedWideScan:
				consumed, accelerated, err = m.accelerateBoundedWideScan(address, m.instructionLimit-steps)
			case emulatorAcceleratorBoundedWideCopy:
				consumed, accelerated, err = m.accelerateBoundedWideCopy(address, m.instructionLimit-steps)
			case emulatorAcceleratorMixedASCIIFoldCompare:
				accelerated, err = m.accelerateMixedASCIIFoldCompare(address)
			case emulatorAcceleratorASCIILower:
				accelerated, err = m.accelerateASCIILower(address)
			case emulatorAcceleratorWideASCIIValidate:
				accelerated, err = m.accelerateWideASCIIValidate(address)
			case emulatorAcceleratorWideASCIICompare:
				accelerated, err = m.accelerateWideASCIICompare(address)
			case emulatorAcceleratorCRC32:
				consumed, accelerated, err = m.accelerateCRC32(address, m.instructionLimit-steps)
			case emulatorAcceleratorI16DotProduct:
				consumed, accelerated, err = m.accelerateI16DotProduct(address, m.instructionLimit-steps)
			case emulatorAcceleratorI16BitExtractDotProduct:
				consumed, accelerated, err = m.accelerateI16BitExtractDotProduct(address, m.instructionLimit-steps)
			case emulatorAcceleratorLinkedListReverse:
				consumed, accelerated, err = m.accelerateLinkedListReverse(address, m.instructionLimit-steps)
			case emulatorAcceleratorCRC16BitLoop:
				consumed, accelerated, err = m.accelerateCRC16BitLoop(address, m.instructionLimit-steps)
			case emulatorAcceleratorI16LinkedListSearch:
				consumed, accelerated, err = m.accelerateI16LinkedListSearch(address, m.instructionLimit-steps)
			case emulatorAcceleratorU8LinkedListSearch:
				consumed, accelerated, err = m.accelerateU8LinkedListSearch(address, m.instructionLimit-steps)
			case emulatorAcceleratorRegisterCRC32:
				consumed, accelerated, err = m.accelerateRegisterCRC32(address, m.instructionLimit-steps)
			}
			if err != nil {
				return m.result("exception", steps, err.Error()), nil
			}
			if accelerated {
				steps += consumed
				m.timestampCounter += consumed
				if acceleratedStop != "" {
					return m.result(acceleratedStop, steps, acceleratedDetail), nil
				}
				continue
			}
		}
		instruction := page.instructions[offset]
		if instruction == nil {
			code, err := m.readMemory(address, 15, 'x')
			if err != nil {
				// Instructions near the end of a mapping may have fewer than 15 bytes.
				mapping, offset, mapErr := m.mapping(address, 1, 'x')
				if mapErr != nil {
					return m.result("exception", steps, err.Error()), nil
				}
				code = mapping.data[offset:]
			}
			decoded, decodeErr := x86asm.Decode(code, 32)
			if decodeErr != nil || decoded.Len == 0 {
				return m.result("unsupported", steps, fmt.Sprintf("decode at 0x%08x: %v", address, decodeErr)), nil
			}
			instruction = &decoded
			m.cacheDecodedInstruction(address, instruction)
			m.cachedCodePages[address>>12] = true
		}
		next := m.eip + uint32(instruction.Len)
		if m.trace || watchCode {
			syntax := x86asm.IntelSyntax(*instruction, uint64(address), nil)
			if watchCode {
				m.recordCodeTrace(address, syntax)
			}
			if m.trace {
				entry := newStarlarkRecord(map[string]starlark.Value{
					"address":     starlark.MakeUint64(uint64(address)),
					"esp":         starlark.MakeUint64(uint64(m.registers[x86asm.ESP])),
					"instruction": starlark.String(syntax),
				})
				if len(m.traceEntries) < m.traceLimit {
					m.traceEntries = append(m.traceEntries, entry)
				} else {
					m.traceEntries[m.traceCursor] = entry
					m.traceCursor = (m.traceCursor + 1) % len(m.traceEntries)
				}
			}
		}
		m.recentEIPs[m.recentEIPCursor] = address
		m.recentEIPCursor = (m.recentEIPCursor + 1) % len(m.recentEIPs)
		if m.recentEIPCount < len(m.recentEIPs) {
			m.recentEIPCount++
		}
		m.timestampCounter++
		stop, detail, err := m.execute(thread, instruction, next)
		steps++
		if err != nil {
			var memoryErr *emulatorMemoryError
			if errors.As(err, &memoryErr) && m.exceptionHandler != nil {
				m.eip = address
				handled, pluginDetail := m.dispatchException(thread, 0xc0000005, address, []uint32{
					map[byte]uint32{'r': 0, 'w': 1, 'x': 8}[memoryErr.permission],
					memoryErr.address,
				})
				if pluginDetail != "" {
					return m.result("plugin", steps, pluginDetail), nil
				}
				if handled {
					continue
				}
			}
			return m.result("exception", steps, err.Error()), nil
		}
		if stop != "" {
			return m.result(stop, steps, detail), nil
		}
	}
	first := len(m.callFrames) - 12
	if first < 0 {
		first = 0
	}
	chain := make([]string, 0, len(m.callFrames)-first)
	for _, frame := range m.callFrames[first:] {
		chain = append(chain, fmt.Sprintf("0x%08x->0x%08x", frame.site, frame.target))
	}
	detail := fmt.Sprintf("instruction limit reached at 0x%08x (esp 0x%08x; chain %s; frequent %s)", m.eip, m.registers[x86asm.ESP], strings.Join(chain, ","), callFrameSummary(m.callFrames, 12))
	return m.result("budget", m.instructionLimit, detail), nil
}

func (m *emulatorX86) execute(thread *starlark.Thread, instruction *x86asm.Inst, next uint32) (string, string, error) {
	m.eip = next
	switch instruction.Op {
	case x86asm.NOP, x86asm.FWAIT, x86asm.FNCLEX:
	case x86asm.RDTSC:
		m.registers[x86asm.EAX] = uint32(m.timestampCounter)
		m.registers[x86asm.EDX] = uint32(m.timestampCounter >> 32)
	case x86asm.FNSTCW:
		if err := m.setOperand(instruction.Args[0], 2, uint32(m.x87ControlWord)); err != nil {
			return "", "", err
		}
	case x86asm.FLDCW:
		control, err := m.operandValueWidth(instruction.Args[0], next, 2)
		if err != nil {
			return "", "", err
		}
		m.x87ControlWord = uint16(control)
	case x86asm.FNSTSW:
		status := (m.x87StatusWord &^ 0x3800) | uint16(m.x87Top<<11)
		if err := m.setOperand(instruction.Args[0], 2, uint32(status)); err != nil {
			return "", "", err
		}
	case x86asm.FILD:
		value, err := m.x87IntegerOperand(instruction.Args[0], instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if err := m.x87Push(float64(value)); err != nil {
			return "", "", err
		}
	case x86asm.FLD:
		value, err := m.x87FloatOperand(instruction.Args[0], instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if err := m.x87Push(value); err != nil {
			return "", "", err
		}
	case x86asm.FLDZ, x86asm.FLD1:
		value := 0.0
		if instruction.Op == x86asm.FLD1 {
			value = 1
		}
		if err := m.x87Push(value); err != nil {
			return "", "", err
		}
	case x86asm.FADD, x86asm.FMUL, x86asm.FSUB, x86asm.FSUBR:
		destination := 0
		source := instruction.Args[0]
		if instruction.Args[1] != nil {
			var err error
			destination, err = x87RegisterIndex(instruction.Args[0])
			if err != nil {
				return "", "", err
			}
			source = instruction.Args[1]
		}
		value, err := m.x87FloatOperand(source, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		current, err := m.x87Value(destination)
		if err != nil {
			return "", "", err
		}
		index := (m.x87Top + destination) % len(m.x87Stack)
		switch instruction.Op {
		case x86asm.FADD:
			m.x87Stack[index] = current + value
		case x86asm.FMUL:
			m.x87Stack[index] = current * value
		case x86asm.FSUB:
			m.x87Stack[index] = current - value
		case x86asm.FSUBR:
			m.x87Stack[index] = value - current
		}
	case x86asm.FDIV, x86asm.FDIVR:
		destination := 0
		source := instruction.Args[0]
		if instruction.Args[1] != nil {
			var err error
			destination, err = x87RegisterIndex(instruction.Args[0])
			if err != nil {
				return "", "", err
			}
			source = instruction.Args[1]
		}
		value, err := m.x87FloatOperand(source, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		current, err := m.x87Value(destination)
		if err != nil {
			return "", "", err
		}
		index := (m.x87Top + destination) % len(m.x87Stack)
		if instruction.Op == x86asm.FDIV {
			m.x87Stack[index] = current / value
		} else {
			m.x87Stack[index] = value / current
		}
	case x86asm.FADDP, x86asm.FMULP, x86asm.FSUBP, x86asm.FSUBRP, x86asm.FDIVP, x86asm.FDIVRP:
		leftIndex, err := x87RegisterIndex(instruction.Args[0])
		if err != nil {
			return "", "", err
		}
		left, err := m.x87Value(leftIndex)
		if err != nil {
			return "", "", err
		}
		right, err := m.x87Value(0)
		if err != nil {
			return "", "", err
		}
		result := 0.0
		switch instruction.Op {
		case x86asm.FADDP:
			result = left + right
		case x86asm.FMULP:
			result = left * right
		case x86asm.FSUBP:
			result = left - right
		case x86asm.FSUBRP:
			result = right - left
		case x86asm.FDIVP:
			result = left / right
		case x86asm.FDIVRP:
			result = right / left
		}
		m.x87Stack[(m.x87Top+leftIndex)%len(m.x87Stack)] = result
		m.x87Pop()
	case x86asm.FCOM, x86asm.FCOMP, x86asm.FCOMPP, x86asm.FUCOM, x86asm.FUCOMP, x86asm.FUCOMPP:
		left, err := m.x87Value(0)
		if err != nil {
			return "", "", err
		}
		rightIndex := 1
		if instruction.Op != x86asm.FCOMPP && instruction.Op != x86asm.FUCOMPP {
			rightIndex = 0
			if instruction.Args[0] != nil {
				if register, ok := instruction.Args[0].(x86asm.Reg); ok && register >= x86asm.F0 && register <= x86asm.F7 {
					rightIndex = int(register - x86asm.F0)
				} else {
					right, err := m.x87FloatOperand(instruction.Args[0], instruction.MemBytes)
					if err != nil {
						return "", "", err
					}
					m.x87Compare(left, right)
					if instruction.Op == x86asm.FCOMP || instruction.Op == x86asm.FUCOMP {
						m.x87Pop()
					}
					break
				}
			}
		}
		right, err := m.x87Value(rightIndex)
		if err != nil {
			return "", "", err
		}
		m.x87Compare(left, right)
		if instruction.Op == x86asm.FCOMPP || instruction.Op == x86asm.FUCOMPP {
			m.x87Pop()
			m.x87Pop()
		} else if instruction.Op == x86asm.FCOMP || instruction.Op == x86asm.FUCOMP {
			m.x87Pop()
		}
	case x86asm.FST:
		value, err := m.x87Value(0)
		if err != nil {
			return "", "", err
		}
		if err := m.setX87FloatOperand(instruction.Args[0], instruction.MemBytes, value); err != nil {
			return "", "", err
		}
	case x86asm.FSTP:
		value, err := m.x87Value(0)
		if err != nil {
			return "", "", err
		}
		if err := m.setX87FloatOperand(instruction.Args[0], instruction.MemBytes, value); err != nil {
			return "", "", err
		}
		m.x87Pop()
	case x86asm.FISTP:
		value, err := m.x87Value(0)
		if err != nil {
			return "", "", err
		}
		if err := m.setX87IntegerOperand(instruction.Args[0], instruction.MemBytes, m.x87Round(value)); err != nil {
			return "", "", err
		}
		m.x87Pop()
	case x86asm.MOV:
		v, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if err := m.setOperand(instruction.Args[0], instruction.MemBytes, v); err != nil {
			return "", "", err
		}
	case x86asm.BSWAP:
		if _, ok := instruction.Args[0].(x86asm.Reg); !ok || m.operandWidth(instruction.Args[0], instruction.MemBytes) != 4 {
			return "unsupported", "BSWAP requires a 32-bit register", nil
		}
		v, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if err := m.setOperand(instruction.Args[0], 4, bits.ReverseBytes32(v)); err != nil {
			return "", "", err
		}
	case x86asm.SAHF:
		value := m.registerValue(x86asm.AH)
		m.carry = value&(1<<0) != 0
		m.parity = value&(1<<2) != 0
		m.zero = value&(1<<6) != 0
		m.sign = value&(1<<7) != 0
	case x86asm.BSF, x86asm.BSR:
		width := m.operandWidth(instruction.Args[1], instruction.MemBytes)
		if width != 2 && width != 4 {
			return "unsupported", fmt.Sprintf("unsupported %s width %d at 0x%08x", instruction.Op, width, next-uint32(instruction.Len)), nil
		}
		source, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		source &= uint32(arithmeticMask(width))
		m.zero = source == 0
		if !m.zero {
			index := bits.TrailingZeros32(source)
			if instruction.Op == x86asm.BSR {
				index = bits.Len32(source) - 1
			}
			if err := m.setOperand(instruction.Args[0], width, uint32(index)); err != nil {
				return "", "", err
			}
		}
	case x86asm.XCHG:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		if _, ok := instruction.Args[1].(x86asm.Mem); ok {
			width = m.operandWidth(instruction.Args[1], instruction.MemBytes)
		}
		left, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		right, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		// Write a memory operand before changing a register that may contribute
		// to its effective address.
		if _, ok := instruction.Args[0].(x86asm.Mem); ok {
			if err := m.setOperand(instruction.Args[0], width, right); err != nil {
				return "", "", err
			}
			if err := m.setOperand(instruction.Args[1], width, left); err != nil {
				return "", "", err
			}
		} else {
			if err := m.setOperand(instruction.Args[1], width, left); err != nil {
				return "", "", err
			}
			if err := m.setOperand(instruction.Args[0], width, right); err != nil {
				return "", "", err
			}
		}
	case x86asm.XADD:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		destination, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		source, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		result := m.addFlags(destination, source, width)
		// Preserve the effective address when the source register also
		// contributes to a memory destination.
		if _, ok := instruction.Args[0].(x86asm.Mem); ok {
			if err := m.setOperand(instruction.Args[0], width, result); err != nil {
				return "", "", err
			}
			if err := m.setOperand(instruction.Args[1], width, destination); err != nil {
				return "", "", err
			}
		} else {
			if err := m.setOperand(instruction.Args[1], width, destination); err != nil {
				return "", "", err
			}
			if err := m.setOperand(instruction.Args[0], width, result); err != nil {
				return "", "", err
			}
		}
	case x86asm.CMPXCHG:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		destination, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		source, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		accumulator := m.registerValue(map[int]x86asm.Reg{1: x86asm.AL, 2: x86asm.AX, 4: x86asm.EAX}[width])
		m.subFlags(accumulator, destination, width)
		if m.zero {
			if err := m.setOperand(instruction.Args[0], width, source); err != nil {
				return "", "", err
			}
		} else {
			m.setRegisterValue(map[int]x86asm.Reg{1: x86asm.AL, 2: x86asm.AX, 4: x86asm.EAX}[width], destination)
		}
	case x86asm.MOVZX, x86asm.MOVSX:
		v, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if instruction.Op == x86asm.MOVSX {
			if instruction.MemBytes == 1 {
				v = uint32(int32(int8(v)))
			} else if instruction.MemBytes == 2 {
				v = uint32(int32(int16(v)))
			}
		}
		if err := m.setOperand(instruction.Args[0], 4, v); err != nil {
			return "", "", err
		}
	case x86asm.LEA:
		memory, ok := instruction.Args[1].(x86asm.Mem)
		if !ok {
			return "unsupported", "LEA source is not memory", nil
		}
		address, err := m.effectiveAddress(memory)
		if err != nil {
			return "", "", err
		}
		if err := m.setOperand(instruction.Args[0], 4, address); err != nil {
			return "", "", err
		}
	case x86asm.PUSH:
		v, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if err := m.push(v); err != nil {
			return "", "", err
		}
	case x86asm.PUSHFD:
		if err := m.push(m.flagsValue()); err != nil {
			return "", "", err
		}
	case x86asm.PUSHAD:
		originalESP := m.registers[x86asm.ESP]
		for _, value := range []uint32{
			m.registers[x86asm.EAX], m.registers[x86asm.ECX], m.registers[x86asm.EDX], m.registers[x86asm.EBX],
			originalESP, m.registers[x86asm.EBP], m.registers[x86asm.ESI], m.registers[x86asm.EDI],
		} {
			if err := m.push(value); err != nil {
				return "", "", err
			}
		}
	case x86asm.POP:
		v, err := m.pop()
		if err != nil {
			return "", "", err
		}
		if err := m.setOperand(instruction.Args[0], 4, v); err != nil {
			return "", "", err
		}
	case x86asm.POPFD:
		flags, err := m.pop()
		if err != nil {
			return "", "", err
		}
		m.setFlagsValue(flags)
	case x86asm.POPAD:
		for index, register := range []x86asm.Reg{
			x86asm.EDI, x86asm.ESI, x86asm.EBP, 0, x86asm.EBX, x86asm.EDX, x86asm.ECX, x86asm.EAX,
		} {
			value, err := m.pop()
			if err != nil {
				return "", "", err
			}
			if index != 3 {
				m.registers[register] = value
			}
		}
	case x86asm.ADD, x86asm.ADC, x86asm.SUB, x86asm.SBB, x86asm.AND, x86asm.OR, x86asm.XOR:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		left, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		right, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		result := left
		switch instruction.Op {
		case x86asm.ADD:
			result = m.addFlags(left, right, width)
		case x86asm.ADC:
			result = m.addCarryFlags(left, right, m.carry, width)
		case x86asm.SUB:
			result = m.subFlags(left, right, width)
		case x86asm.SBB:
			result = m.subBorrowFlags(left, right, m.carry, width)
		case x86asm.AND:
			result = left & right
			m.logicalFlags(result, width)
		case x86asm.OR:
			result = left | right
			m.logicalFlags(result, width)
		case x86asm.XOR:
			result = left ^ right
			m.logicalFlags(result, width)
		}
		if err := m.setOperand(instruction.Args[0], instruction.MemBytes, result); err != nil {
			return "", "", err
		}
	case x86asm.SHL, x86asm.SHR, x86asm.SAR, x86asm.ROL, x86asm.ROR, x86asm.RCL, x86asm.RCR:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		left, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		right, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		count := right & 31
		bits := uint32(width * 8)
		mask := uint32(arithmeticMask(width))
		left &= mask
		result := left
		if instruction.Op == x86asm.ROL || instruction.Op == x86asm.ROR {
			effective := count % bits
			if effective != 0 {
				if instruction.Op == x86asm.ROL {
					result = (left<<effective | left>>(bits-effective)) & mask
					m.carry = result&1 != 0
					if effective == 1 {
						m.overflow = (result&(1<<(bits-1)) != 0) != m.carry
					}
				} else {
					result = (left>>effective | left<<(bits-effective)) & mask
					m.carry = result&(1<<(bits-1)) != 0
					if effective == 1 {
						m.overflow = (result&(1<<(bits-1)) != 0) != (result&(1<<(bits-2)) != 0)
					}
				}
			}
		} else if instruction.Op == x86asm.RCL || instruction.Op == x86asm.RCR {
			effective := count % (bits + 1)
			if effective != 0 {
				for range effective {
					previousCarry := m.carry
					if instruction.Op == x86asm.RCL {
						m.carry = result&(1<<(bits-1)) != 0
						result = result << 1 & mask
						if previousCarry {
							result |= 1
						}
					} else {
						m.carry = result&1 != 0
						result >>= 1
						if previousCarry {
							result |= 1 << (bits - 1)
						}
					}
				}
				if effective == 1 {
					mostSignificant := result&(1<<(bits-1)) != 0
					if instruction.Op == x86asm.RCL {
						m.overflow = mostSignificant != m.carry
					} else {
						nextMostSignificant := result&(1<<(bits-2)) != 0
						m.overflow = mostSignificant != nextMostSignificant
					}
				}
			}
		} else if count != 0 {
			switch instruction.Op {
			case x86asm.SHL:
				m.carry = count <= bits && left&(1<<(bits-count)) != 0
				result = left << count & mask
				if count == 1 {
					m.overflow = (result&(1<<(bits-1)) != 0) != m.carry
				}
			case x86asm.SHR:
				m.carry = count <= bits && left&(1<<(count-1)) != 0
				result = left >> count
				if count == 1 {
					m.overflow = left&(1<<(bits-1)) != 0
				}
			case x86asm.SAR:
				m.carry = left&(1<<(min(count, bits)-1)) != 0
				shift := min(count, bits-1)
				result = uint32(signedOperand(left, width)>>shift) & mask
				if count == 1 {
					m.overflow = false
				}
			}
			m.resultFlags(result, width)
		}
		if err := m.setOperand(instruction.Args[0], instruction.MemBytes, result); err != nil {
			return "", "", err
		}
	case x86asm.SHLD, x86asm.SHRD:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		left, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		right, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		countValue, err := m.operandValueWidth(instruction.Args[2], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		count := countValue & 31
		bits := uint32(width * 8)
		if count > bits {
			return "unsupported", fmt.Sprintf("undefined %s count %d at 0x%08x", instruction.Op, count, next-uint32(instruction.Len)), nil
		}
		mask := uint32(arithmeticMask(width))
		left &= mask
		right &= mask
		result := left
		if count != 0 {
			if instruction.Op == x86asm.SHLD {
				m.carry = left&(1<<(bits-count)) != 0
				result = (left<<count | right>>(bits-count)) & mask
				if count == 1 {
					m.overflow = (result&(1<<(bits-1)) != 0) != m.carry
				}
			} else {
				m.carry = left&(1<<(count-1)) != 0
				result = (left>>count | right<<(bits-count)) & mask
				if count == 1 {
					m.overflow = (left&(1<<(bits-1)) != 0) != (result&(1<<(bits-1)) != 0)
				}
			}
			m.resultFlags(result, width)
		}
		if err := m.setOperand(instruction.Args[0], instruction.MemBytes, result); err != nil {
			return "", "", err
		}
	case x86asm.INC, x86asm.DEC:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		v, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if instruction.Op == x86asm.INC {
			carry := m.carry
			v = m.addFlags(v, 1, width)
			m.carry = carry
		} else {
			carry := m.carry
			v = m.subFlags(v, 1, width)
			m.carry = carry
		}
		if err := m.setOperand(instruction.Args[0], instruction.MemBytes, v); err != nil {
			return "", "", err
		}
	case x86asm.IMUL:
		if instruction.Args[1] == nil {
			width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
			multiplier, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
			if err != nil {
				return "", "", err
			}
			var product int64
			switch width {
			case 1:
				product = signedOperand(m.registerValue(x86asm.AL), 1) * signedOperand(multiplier, 1)
				m.setRegisterValue(x86asm.AX, uint32(uint16(int16(product))))
			case 2:
				product = signedOperand(m.registerValue(x86asm.AX), 2) * signedOperand(multiplier, 2)
				m.setRegisterValue(x86asm.AX, uint32(uint16(product)))
				m.setRegisterValue(x86asm.DX, uint32(uint16(uint32(product)>>16)))
			case 4:
				product = int64(int32(m.registerValue(x86asm.EAX))) * int64(int32(multiplier))
				m.registers[x86asm.EAX] = uint32(product)
				m.registers[x86asm.EDX] = uint32(uint64(product) >> 32)
			default:
				return "unsupported", fmt.Sprintf("unsupported IMUL width %d at 0x%08x", width, next-uint32(instruction.Len)), nil
			}
			bits := width * 8
			minimum, maximum := -(int64(1) << (bits - 1)), int64(1)<<(bits-1)-1
			m.carry = product < minimum || product > maximum
			m.overflow = m.carry
			break
		}
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		leftArgument, rightArgument := instruction.Args[0], instruction.Args[1]
		if instruction.Args[2] != nil {
			leftArgument, rightArgument = instruction.Args[1], instruction.Args[2]
		}
		left, err := m.operandValueWidth(leftArgument, next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		right, err := m.operandValueWidth(rightArgument, next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		product := signedOperand(left, width) * signedOperand(right, width)
		bits := width * 8
		minimum, maximum := -(int64(1) << (bits - 1)), int64(1)<<(bits-1)-1
		m.carry = product < minimum || product > maximum
		m.overflow = m.carry
		result := uint32(uint64(product) & arithmeticMask(width))
		m.resultFlags(result, width)
		if err := m.setOperand(instruction.Args[0], instruction.MemBytes, result); err != nil {
			return "", "", err
		}
	case x86asm.CDQ:
		m.registers[x86asm.EDX] = uint32(int32(m.registers[x86asm.EAX]) >> 31)
	case x86asm.CWDE:
		m.registers[x86asm.EAX] = uint32(int32(int16(m.registerValue(x86asm.AX))))
	case x86asm.MUL:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		if width != 4 {
			return "unsupported", fmt.Sprintf("unsupported MUL width %d at 0x%08x", width, next-uint32(instruction.Len)), nil
		}
		multiplier, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		product := uint64(m.registers[x86asm.EAX]) * uint64(multiplier)
		m.registers[x86asm.EAX] = uint32(product)
		m.registers[x86asm.EDX] = uint32(product >> 32)
		m.carry = m.registers[x86asm.EDX] != 0
		m.overflow = m.carry
	case x86asm.IDIV, x86asm.DIV:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		if width != 4 {
			return "unsupported", fmt.Sprintf("unsupported %s width %d at 0x%08x", instruction.Op, width, next-uint32(instruction.Len)), nil
		}
		divisor, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if divisor == 0 {
			return "exception", "integer division by zero", nil
		}
		if instruction.Op == x86asm.IDIV {
			dividend := int64(uint64(m.registers[x86asm.EDX])<<32 | uint64(m.registers[x86asm.EAX]))
			quotient := dividend / int64(int32(divisor))
			if quotient < math.MinInt32 || quotient > math.MaxInt32 {
				return "exception", "signed integer quotient overflow", nil
			}
			m.registers[x86asm.EAX] = uint32(int32(quotient))
			m.registers[x86asm.EDX] = uint32(int32(dividend % int64(int32(divisor))))
		} else {
			dividend := uint64(m.registers[x86asm.EDX])<<32 | uint64(m.registers[x86asm.EAX])
			quotient := dividend / uint64(divisor)
			if quotient > math.MaxUint32 {
				return "exception", "unsigned integer quotient overflow", nil
			}
			m.registers[x86asm.EAX] = uint32(quotient)
			m.registers[x86asm.EDX] = uint32(dividend % uint64(divisor))
		}
	case x86asm.NOT, x86asm.NEG:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		v, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		if instruction.Op == x86asm.NOT {
			v = ^v
		} else {
			v = m.subFlags(0, v, width)
		}
		if err := m.setOperand(instruction.Args[0], instruction.MemBytes, v); err != nil {
			return "", "", err
		}
	case x86asm.CMP, x86asm.TEST:
		width := m.operandWidth(instruction.Args[0], instruction.MemBytes)
		left, err := m.operandValueWidth(instruction.Args[0], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		right, err := m.operandValueWidth(instruction.Args[1], next, instruction.MemBytes)
		if err != nil {
			return "", "", err
		}
		result := left & right
		if instruction.Op == x86asm.CMP {
			m.subFlags(left, right, width)
		} else {
			m.logicalFlags(result, width)
		}
	case x86asm.SETE, x86asm.SETNE, x86asm.SETB, x86asm.SETAE, x86asm.SETBE, x86asm.SETA,
		x86asm.SETL, x86asm.SETGE, x86asm.SETLE, x86asm.SETG, x86asm.SETS, x86asm.SETNS,
		x86asm.SETP, x86asm.SETNP, x86asm.SETO, x86asm.SETNO:
		condition := false
		switch instruction.Op {
		case x86asm.SETE:
			condition = m.zero
		case x86asm.SETNE:
			condition = !m.zero
		case x86asm.SETB:
			condition = m.carry
		case x86asm.SETAE:
			condition = !m.carry
		case x86asm.SETBE:
			condition = m.carry || m.zero
		case x86asm.SETA:
			condition = !m.carry && !m.zero
		case x86asm.SETL:
			condition = m.sign != m.overflow
		case x86asm.SETGE:
			condition = m.sign == m.overflow
		case x86asm.SETLE:
			condition = m.zero || m.sign != m.overflow
		case x86asm.SETG:
			condition = !m.zero && m.sign == m.overflow
		case x86asm.SETS:
			condition = m.sign
		case x86asm.SETNS:
			condition = !m.sign
		case x86asm.SETP:
			condition = m.parity
		case x86asm.SETNP:
			condition = !m.parity
		case x86asm.SETO:
			condition = m.overflow
		case x86asm.SETNO:
			condition = !m.overflow
		}
		if err := m.setOperand(instruction.Args[0], 1, boolUint32(condition)); err != nil {
			return "", "", err
		}
	case x86asm.JMP:
		target, err := m.branchTarget(instruction.Args[0], next)
		if err != nil {
			return "", "", err
		}
		if hook, ok := m.hooks[target]; ok {
			return m.invokeTailHook(thread, hook)
		}
		if imported, ok := m.imports[target]; ok {
			return "plugin", fmt.Sprintf("unhandled import %s!%s at 0x%08x", imported.module, imported.displayName(), target), nil
		}
		m.eip = target
	case x86asm.JECXZ:
		if m.registers[x86asm.ECX] == 0 {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JE:
		if m.zero {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JNE:
		if !m.zero {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JB:
		if m.carry {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JAE:
		if !m.carry {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JBE:
		if m.carry || m.zero {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JA:
		if !m.carry && !m.zero {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JL:
		if m.sign != m.overflow {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JGE:
		if m.sign == m.overflow {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JLE:
		if m.zero || m.sign != m.overflow {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JG:
		if !m.zero && m.sign == m.overflow {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JS:
		if m.sign {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JNS:
		if !m.sign {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.JP, x86asm.JNP:
		if m.parity == (instruction.Op == x86asm.JP) {
			target, err := m.branchTarget(instruction.Args[0], next)
			if err != nil {
				return "", "", err
			}
			m.eip = target
		}
	case x86asm.CALL:
		target, err := m.branchTarget(instruction.Args[0], next)
		if err != nil {
			return "", "", err
		}
		m.recordCallTrace(next-uint32(instruction.Len), target)
		if hook, ok := m.hooks[target]; ok {
			stop, detail, err := m.invokeHook(thread, hook)
			if stop != "" {
				// A stopped API call has not returned. Re-execute the call when
				// this context resumes so the hook can observe the wake condition.
				m.eip = next - uint32(instruction.Len)
			}
			return stop, detail, err
		}
		if imported, ok := m.imports[target]; ok {
			return "plugin", fmt.Sprintf("unhandled import %s!%s at 0x%08x", imported.module, imported.displayName(), target), nil
		}
		if err := m.push(next); err != nil {
			return "", "", err
		}
		m.callDepth++
		m.callFrames = append(m.callFrames, emulatorCallFrame{site: next - uint32(instruction.Len), target: target})
		if m.callDepth > m.callDepthLimit {
			first := len(m.callFrames) - 12
			if first < 0 {
				first = 0
			}
			chain := make([]string, 0, len(m.callFrames)-first)
			for _, frame := range m.callFrames[first:] {
				chain = append(chain, fmt.Sprintf("0x%08x->0x%08x", frame.site, frame.target))
			}
			return "budget", fmt.Sprintf("call depth limit reached at 0x%08x calling 0x%08x (esp 0x%08x; chain %s; frequent %s)", next-uint32(instruction.Len), target, m.registers[x86asm.ESP], strings.Join(chain, ","), callFrameSummary(m.callFrames, 12)), nil
		}
		m.eip = target
	case x86asm.RET:
		if m.registers[x86asm.ESP] == m.stackHigh {
			m.eip = 0
			return "return", "", nil
		}
		target, err := m.pop()
		if err != nil {
			return "", "", err
		}
		if immediate, ok := instruction.Args[0].(x86asm.Imm); ok {
			m.registers[x86asm.ESP] += uint32(immediate)
		}
		if m.callDepth > 0 {
			m.callDepth--
		}
		if len(m.callFrames) > 0 {
			m.callFrames = m.callFrames[:len(m.callFrames)-1]
		}
		m.eip = target
	case x86asm.LEAVE:
		m.registers[x86asm.ESP] = m.registers[x86asm.EBP]
		value, err := m.pop()
		if err != nil {
			return "", "", err
		}
		m.registers[x86asm.EBP] = value
	case x86asm.CLD:
		m.direction = false
	case x86asm.STD:
		m.direction = true
	case x86asm.STOSB, x86asm.STOSW, x86asm.STOSD:
		width := 1
		if instruction.Op == x86asm.STOSW {
			width = 2
		} else if instruction.Op == x86asm.STOSD {
			width = 4
		}
		count := uint32(1)
		for _, prefix := range instruction.Prefix {
			if prefix&0xff == x86asm.PrefixREP {
				count = m.registers[x86asm.ECX]
				break
			}
		}
		if uint64(count)*uint64(width) > uint64(m.memoryLimit) {
			return "budget", "string operation exceeds memory budget", nil
		}
		value := m.registers[x86asm.EAX]
		var data [4]byte
		switch width {
		case 1:
			data[0] = byte(value)
		case 2:
			binary.LittleEndian.PutUint16(data[:], uint16(value))
		case 4:
			binary.LittleEndian.PutUint32(data[:], value)
		}
		for range count {
			if err := m.writeMemory(m.registers[x86asm.EDI], data[:width]); err != nil {
				return "", "", err
			}
			if m.direction {
				m.registers[x86asm.EDI] -= uint32(width)
			} else {
				m.registers[x86asm.EDI] += uint32(width)
			}
		}
		if count != 1 {
			m.registers[x86asm.ECX] = 0
		}
	case x86asm.CMPSB, x86asm.CMPSW, x86asm.CMPSD:
		width := 1
		if instruction.Op == x86asm.CMPSW {
			width = 2
		} else if instruction.Op == x86asm.CMPSD {
			width = 4
		}
		repeat, repeatWhileEqual := false, false
		for _, prefix := range instruction.Prefix {
			switch prefix & 0xff {
			case x86asm.PrefixREP:
				repeat, repeatWhileEqual = true, true
			case x86asm.PrefixREPN:
				repeat = true
			}
		}
		count := uint32(1)
		if repeat {
			count = m.registers[x86asm.ECX]
		}
		examined := uint64(0)
		for range count {
			examined += uint64(width) * 2
			if examined > uint64(m.memoryLimit) {
				return "budget", "string operation exceeds memory budget", nil
			}
			leftData, err := m.readMemory(m.registers[x86asm.ESI], width, 'r')
			if err != nil {
				return "", "", err
			}
			rightData, err := m.readMemory(m.registers[x86asm.EDI], width, 'r')
			if err != nil {
				return "", "", err
			}
			left, right := littleEndianValue(leftData), littleEndianValue(rightData)
			m.subFlags(left, right, width)
			if m.direction {
				m.registers[x86asm.ESI] -= uint32(width)
				m.registers[x86asm.EDI] -= uint32(width)
			} else {
				m.registers[x86asm.ESI] += uint32(width)
				m.registers[x86asm.EDI] += uint32(width)
			}
			if repeat {
				m.registers[x86asm.ECX]--
				if m.registers[x86asm.ECX] == 0 || m.zero != repeatWhileEqual {
					break
				}
			}
		}
	case x86asm.SCASB, x86asm.SCASW, x86asm.SCASD:
		width := 1
		if instruction.Op == x86asm.SCASW {
			width = 2
		} else if instruction.Op == x86asm.SCASD {
			width = 4
		}
		repeat, repeatWhileEqual := false, false
		for _, prefix := range instruction.Prefix {
			switch prefix & 0xff {
			case x86asm.PrefixREP:
				repeat, repeatWhileEqual = true, true
			case x86asm.PrefixREPN:
				repeat = true
			}
		}
		count := uint32(1)
		if repeat {
			count = m.registers[x86asm.ECX]
		}
		examined := uint64(0)
		for range count {
			examined += uint64(width)
			if examined > uint64(m.memoryLimit) {
				return "budget", "string operation exceeds memory budget", nil
			}
			data, err := m.readMemory(m.registers[x86asm.EDI], width, 'r')
			if err != nil {
				return "", "", err
			}
			m.subFlags(m.registers[x86asm.EAX], littleEndianValue(data), width)
			if m.direction {
				m.registers[x86asm.EDI] -= uint32(width)
			} else {
				m.registers[x86asm.EDI] += uint32(width)
			}
			if repeat {
				m.registers[x86asm.ECX]--
				if m.registers[x86asm.ECX] == 0 || m.zero != repeatWhileEqual {
					break
				}
			}
		}
	case x86asm.MOVSB, x86asm.MOVSW, x86asm.MOVSD:
		width := 1
		if instruction.Op == x86asm.MOVSW {
			width = 2
		} else if instruction.Op == x86asm.MOVSD {
			width = 4
		}
		count := uint32(1)
		for _, prefix := range instruction.Prefix {
			if prefix&0xff == x86asm.PrefixREP {
				count = m.registers[x86asm.ECX]
				break
			}
		}
		if uint64(count)*uint64(width) > uint64(m.memoryLimit) {
			return "budget", "string operation exceeds memory budget", nil
		}
		for range count {
			data, err := m.readMemory(m.registers[x86asm.ESI], width, 'r')
			if err != nil {
				return "", "", err
			}
			if err := m.writeMemory(m.registers[x86asm.EDI], bytes.Clone(data)); err != nil {
				return "", "", err
			}
			if m.direction {
				m.registers[x86asm.ESI] -= uint32(width)
				m.registers[x86asm.EDI] -= uint32(width)
			} else {
				m.registers[x86asm.ESI] += uint32(width)
				m.registers[x86asm.EDI] += uint32(width)
			}
		}
		if count != 1 {
			m.registers[x86asm.ECX] = 0
		}
	default:
		return "unsupported", fmt.Sprintf("unsupported instruction %s at 0x%08x", instruction.Op, next-uint32(instruction.Len)), nil
	}
	return "", "", nil
}

func (m *emulatorX86) x87Push(value float64) error {
	if m.x87Depth == len(m.x87Stack) {
		return fmt.Errorf("x87 stack overflow")
	}
	m.x87Top = (m.x87Top + len(m.x87Stack) - 1) % len(m.x87Stack)
	m.x87Stack[m.x87Top] = value
	m.x87Depth++
	return nil
}

func (m *emulatorX86) x87Pop() {
	if m.x87Depth == 0 {
		return
	}
	m.x87Top = (m.x87Top + 1) % len(m.x87Stack)
	m.x87Depth--
}

func (m *emulatorX86) x87Value(index int) (float64, error) {
	if index < 0 || index >= m.x87Depth {
		return 0, fmt.Errorf("x87 stack underflow")
	}
	return m.x87Stack[(m.x87Top+index)%len(m.x87Stack)], nil
}

func (m *emulatorX86) x87Compare(left, right float64) {
	const conditionMask = uint16(0x4500) // C3, C2, and C0.
	m.x87StatusWord &^= conditionMask
	if math.IsNaN(left) || math.IsNaN(right) {
		m.x87StatusWord |= conditionMask
	} else if left < right {
		m.x87StatusWord |= 0x0100
	} else if left == right {
		m.x87StatusWord |= 0x4000
	}
}

func x87RegisterIndex(argument x86asm.Arg) (int, error) {
	register, ok := argument.(x86asm.Reg)
	if !ok || register < x86asm.F0 || register > x86asm.F7 {
		return 0, fmt.Errorf("unsupported x87 register operand %T", argument)
	}
	return int(register - x86asm.F0), nil
}

func (m *emulatorX86) x87Round(value float64) int64 {
	switch (m.x87ControlWord >> 10) & 3 {
	case 0:
		return int64(math.RoundToEven(value))
	case 1:
		return int64(math.Floor(value))
	case 2:
		return int64(math.Ceil(value))
	default:
		return int64(math.Trunc(value))
	}
}

func (m *emulatorX86) x87IntegerOperand(argument x86asm.Arg, width int) (int64, error) {
	memory, ok := argument.(x86asm.Mem)
	if !ok {
		return 0, fmt.Errorf("unsupported x87 integer operand %T", argument)
	}
	address, err := m.effectiveAddress(memory)
	if err != nil {
		return 0, err
	}
	data, err := m.readMemory(address, width, 'r')
	if err != nil {
		return 0, err
	}
	switch width {
	case 2:
		return int64(int16(binary.LittleEndian.Uint16(data))), nil
	case 4:
		return int64(int32(binary.LittleEndian.Uint32(data))), nil
	case 8:
		return int64(binary.LittleEndian.Uint64(data)), nil
	default:
		return 0, fmt.Errorf("unsupported x87 integer width %d", width)
	}
}

func (m *emulatorX86) x87FloatOperand(argument x86asm.Arg, width int) (float64, error) {
	if register, ok := argument.(x86asm.Reg); ok && register >= x86asm.F0 && register <= x86asm.F7 {
		return m.x87Value(int(register - x86asm.F0))
	}
	memory, ok := argument.(x86asm.Mem)
	if !ok {
		return 0, fmt.Errorf("unsupported x87 floating operand %T", argument)
	}
	address, err := m.effectiveAddress(memory)
	if err != nil {
		return 0, err
	}
	data, err := m.readMemory(address, width, 'r')
	if err != nil {
		return 0, err
	}
	switch width {
	case 4:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(data))), nil
	case 8:
		return math.Float64frombits(binary.LittleEndian.Uint64(data)), nil
	default:
		return 0, fmt.Errorf("unsupported x87 floating width %d", width)
	}
}

func (m *emulatorX86) setX87IntegerOperand(argument x86asm.Arg, width int, value int64) error {
	memory, ok := argument.(x86asm.Mem)
	if !ok {
		return fmt.Errorf("unsupported x87 integer destination %T", argument)
	}
	address, err := m.effectiveAddress(memory)
	if err != nil {
		return err
	}
	var data [8]byte
	switch width {
	case 2:
		binary.LittleEndian.PutUint16(data[:], uint16(value))
	case 4:
		binary.LittleEndian.PutUint32(data[:], uint32(value))
	case 8:
		binary.LittleEndian.PutUint64(data[:], uint64(value))
	default:
		return fmt.Errorf("unsupported x87 integer width %d", width)
	}
	return m.writeMemory(address, data[:width])
}

func (m *emulatorX86) setX87FloatOperand(argument x86asm.Arg, width int, value float64) error {
	if register, ok := argument.(x86asm.Reg); ok && register >= x86asm.F0 && register <= x86asm.F7 {
		index := int(register - x86asm.F0)
		if index >= m.x87Depth {
			return fmt.Errorf("x87 stack underflow")
		}
		m.x87Stack[(m.x87Top+index)%len(m.x87Stack)] = value
		return nil
	}
	memory, ok := argument.(x86asm.Mem)
	if !ok {
		return fmt.Errorf("unsupported x87 floating destination %T", argument)
	}
	address, err := m.effectiveAddress(memory)
	if err != nil {
		return err
	}
	var data [8]byte
	switch width {
	case 4:
		binary.LittleEndian.PutUint32(data[:], math.Float32bits(float32(value)))
	case 8:
		binary.LittleEndian.PutUint64(data[:], math.Float64bits(value))
	default:
		return fmt.Errorf("unsupported x87 floating width %d", width)
	}
	return m.writeMemory(address, data[:width])
}

func (m *emulatorX86) operandValue(argument x86asm.Arg, next uint32) (uint32, error) {
	return m.operandValueWidth(argument, next, 4)
}

func (m *emulatorX86) operandValueWidth(argument x86asm.Arg, next uint32, width int) (uint32, error) {
	switch value := argument.(type) {
	case x86asm.Imm:
		return uint32(int64(value)), nil
	case x86asm.Rel:
		return uint32(int64(next) + int64(value)), nil
	case x86asm.Reg:
		return m.registerValue(value), nil
	case x86asm.Mem:
		return m.memoryOperandValue(value, width)
	default:
		return unsupportedOperandValue(argument)
	}
}

func (m *emulatorX86) memoryOperandValue(memory x86asm.Mem, width int) (uint32, error) {
	address, err := m.effectiveAddress(memory)
	if err != nil {
		return 0, err
	}
	if width != 1 && width != 2 && width != 4 {
		width = 4
	}
	data, err := m.readMemory(address, width, 'r')
	if err != nil {
		return 0, err
	}
	switch width {
	case 1:
		return uint32(data[0]), nil
	case 2:
		return uint32(binary.LittleEndian.Uint16(data)), nil
	default:
		return binary.LittleEndian.Uint32(data), nil
	}
}

func unsupportedOperandValue(argument x86asm.Arg) (uint32, error) {
	return 0, fmt.Errorf("unsupported operand %T", argument)
}

func boolUint32(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}
func (m *emulatorX86) setOperand(argument x86asm.Arg, width int, value uint32) error {
	if width <= 0 {
		width = 4
	}
	switch target := argument.(type) {
	case x86asm.Reg:
		m.setRegisterValue(target, value)
		return nil
	case x86asm.Mem:
		return m.setMemoryOperand(target, width, value)
	default:
		return unsupportedOperandDestination(argument)
	}
}

func (m *emulatorX86) setMemoryOperand(memory x86asm.Mem, width int, value uint32) error {
	address, err := m.effectiveAddress(memory)
	if err != nil {
		return err
	}
	var data [4]byte
	switch width {
	case 1:
		data[0] = byte(value)
	case 2:
		binary.LittleEndian.PutUint16(data[:], uint16(value))
	case 4:
		binary.LittleEndian.PutUint32(data[:], value)
	default:
		return fmt.Errorf("unsupported memory width %d", width)
	}
	return m.writeMemory(address, data[:width])
}

func unsupportedOperandDestination(argument x86asm.Arg) error {
	return fmt.Errorf("unsupported destination %T", argument)
}
func (m *emulatorX86) effectiveAddress(memory x86asm.Mem) (uint32, error) {
	address := int64(memory.Disp)
	if base := m.segmentBases[memory.Segment]; base != 0 {
		address += int64(base)
	}
	if memory.Base != 0 {
		address += int64(m.registerValue(memory.Base))
	}
	if memory.Index != 0 {
		address += int64(m.registerValue(memory.Index)) * int64(memory.Scale)
	}
	return uint32(address), nil
}
func (m *emulatorX86) branchTarget(argument x86asm.Arg, next uint32) (uint32, error) {
	if relative, ok := argument.(x86asm.Rel); ok {
		return uint32(int64(next) + int64(relative)), nil
	}
	return m.operandValue(argument, next)
}
func (m *emulatorX86) operandWidth(argument x86asm.Arg, memoryWidth int) int {
	if _, ok := argument.(x86asm.Mem); ok && memoryWidth != 0 {
		return memoryWidth
	}
	if register, ok := argument.(x86asm.Reg); ok {
		switch register {
		case x86asm.AL, x86asm.AH, x86asm.BL, x86asm.BH, x86asm.CL, x86asm.CH, x86asm.DL, x86asm.DH:
			return 1
		case x86asm.AX, x86asm.BX, x86asm.CX, x86asm.DX, x86asm.SP, x86asm.BP, x86asm.SI, x86asm.DI:
			return 2
		}
	}
	return 4
}

func arithmeticMask(width int) uint64 {
	if width >= 4 {
		return math.MaxUint32
	}
	return uint64(1)<<(width*8) - 1
}

func signedOperand(value uint32, width int) int64 {
	shift := 64 - width*8
	return int64(uint64(value&uint32(arithmeticMask(width)))<<shift) >> shift
}

func littleEndianValue(data []byte) uint32 {
	switch len(data) {
	case 1:
		return uint32(data[0])
	case 2:
		return uint32(binary.LittleEndian.Uint16(data))
	case 4:
		return binary.LittleEndian.Uint32(data)
	default:
		panic("unsupported little-endian integer width")
	}
}

func (m *emulatorX86) flagsValue() uint32 {
	flags := uint32(2)
	flags |= boolUint32(m.carry)
	flags |= boolUint32(m.parity) << 2
	flags |= boolUint32(m.zero) << 6
	flags |= boolUint32(m.sign) << 7
	flags |= boolUint32(m.direction) << 10
	flags |= boolUint32(m.overflow) << 11
	return flags
}

func (m *emulatorX86) setFlagsValue(flags uint32) {
	m.carry = flags&1 != 0
	m.parity = flags&(1<<2) != 0
	m.zero = flags&(1<<6) != 0
	m.sign = flags&(1<<7) != 0
	m.direction = flags&(1<<10) != 0
	m.overflow = flags&(1<<11) != 0
}

func (m *emulatorX86) resultFlags(value uint32, width int) {
	mask := arithmeticMask(width)
	value &= uint32(mask)
	m.zero = value == 0
	m.parity = bits.OnesCount8(uint8(value))%2 == 0
	m.sign = value&(uint32(1)<<(width*8-1)) != 0
}

func (m *emulatorX86) logicalFlags(value uint32, width int) {
	m.carry = false
	m.overflow = false
	m.resultFlags(value, width)
}

func (m *emulatorX86) addFlags(left, right uint32, width int) uint32 {
	return m.addCarryFlags(left, right, false, width)
}

func (m *emulatorX86) addCarryFlags(left, right uint32, carry bool, width int) uint32 {
	mask := arithmeticMask(width)
	l, r := uint64(left)&mask, uint64(right)&mask
	result := l + r + uint64(boolUint32(carry))
	m.carry = result > mask
	signBit := uint64(1) << (width*8 - 1)
	m.overflow = (^(l ^ r) & (l ^ result) & signBit) != 0
	m.resultFlags(uint32(result), width)
	return uint32(result & mask)
}

func (m *emulatorX86) subFlags(left, right uint32, width int) uint32 {
	return m.subBorrowFlags(left, right, false, width)
}

func (m *emulatorX86) subBorrowFlags(left, right uint32, borrow bool, width int) uint32 {
	mask := arithmeticMask(width)
	l, r := uint64(left)&mask, uint64(right)&mask
	subtrahend := r + uint64(boolUint32(borrow))
	result := (l - subtrahend) & mask
	m.carry = l < subtrahend
	signBit := uint64(1) << (width*8 - 1)
	m.overflow = ((l ^ r) & (l ^ result) & signBit) != 0
	m.resultFlags(uint32(result), width)
	return uint32(result)
}

type emulatorRegisterAlias struct {
	full  x86asm.Reg
	mask  uint32
	shift uint8
}

var emulatorRegisterAliases = func() (aliases [256]emulatorRegisterAlias) {
	for index := range aliases {
		aliases[index] = emulatorRegisterAlias{full: x86asm.Reg(index), mask: math.MaxUint32}
	}
	set := func(register, full x86asm.Reg, mask uint32, shift uint8) {
		aliases[register] = emulatorRegisterAlias{full: full, mask: mask, shift: shift}
	}
	set(x86asm.AL, x86asm.EAX, 0xff, 0)
	set(x86asm.AH, x86asm.EAX, 0xff, 8)
	set(x86asm.AX, x86asm.EAX, 0xffff, 0)
	set(x86asm.BL, x86asm.EBX, 0xff, 0)
	set(x86asm.BH, x86asm.EBX, 0xff, 8)
	set(x86asm.BX, x86asm.EBX, 0xffff, 0)
	set(x86asm.CL, x86asm.ECX, 0xff, 0)
	set(x86asm.CH, x86asm.ECX, 0xff, 8)
	set(x86asm.CX, x86asm.ECX, 0xffff, 0)
	set(x86asm.DL, x86asm.EDX, 0xff, 0)
	set(x86asm.DH, x86asm.EDX, 0xff, 8)
	set(x86asm.DX, x86asm.EDX, 0xffff, 0)
	set(x86asm.SP, x86asm.ESP, 0xffff, 0)
	set(x86asm.BP, x86asm.EBP, 0xffff, 0)
	set(x86asm.SI, x86asm.ESI, 0xffff, 0)
	set(x86asm.DI, x86asm.EDI, 0xffff, 0)
	return aliases
}()

func (m *emulatorX86) registerValue(register x86asm.Reg) uint32 {
	alias := emulatorRegisterAliases[register]
	return m.registers[alias.full] >> alias.shift & alias.mask
}
func (m *emulatorX86) setRegisterValue(register x86asm.Reg, value uint32) {
	alias := emulatorRegisterAliases[register]
	if alias.mask == math.MaxUint32 {
		m.registers[register] = value
		return
	}
	mask := alias.mask << alias.shift
	m.registers[alias.full] = m.registers[alias.full]&^mask | (value&alias.mask)<<alias.shift
}

func (m *emulatorX86) invokeHook(thread *starlark.Thread, hook emulatorHook) (string, string, error) {
	esp := m.registers[x86asm.ESP]
	arguments := make([]starlark.Value, hook.argc)
	for index := 0; index < hook.argc; index++ {
		value, err := m.readUint32(esp + uint32(index*4))
		if err != nil {
			return "", "", err
		}
		arguments[index] = starlark.MakeUint64(uint64(value))
	}
	event := newStarlarkRecord(map[string]starlark.Value{
		"machine":          m,
		"module":           starlark.String(hook.module),
		"name":             starlark.String(hook.name),
		"address":          starlark.MakeUint64(uint64(hook.address)),
		"return_address":   starlark.MakeUint64(uint64(m.eip)),
		"argument_address": starlark.MakeUint64(uint64(esp)),
		"args":             starlark.NewList(arguments),
	})
	m.hookDepth++
	result, err := starlark.Call(thread, hook.callback, starlark.Tuple{event}, nil)
	m.hookDepth--
	if err != nil {
		return "plugin", fmt.Sprintf("hook %s!%s: %v", hook.module, hook.name, err), nil
	}
	if m.pendingTransfer {
		m.pendingTransfer = false
		return "", "", nil
	}
	if result != starlark.None {
		if err := m.applyHookResult(result); err != nil {
			return "plugin", fmt.Sprintf("hook %s!%s: %v", hook.module, hook.name, err), nil
		}
	}
	if m.pendingStop != "" {
		stop, detail := m.pendingStop, m.pendingStopDetail
		m.pendingStop, m.pendingStopDetail = "", ""
		return stop, detail, nil
	}
	if hook.convention == "stdcall" {
		m.registers[x86asm.ESP] += uint32(hook.argc * 4)
	}
	return "", "", nil
}

func (m *emulatorX86) invokeTailHook(thread *starlark.Thread, hook emulatorHook) (string, string, error) {
	esp := m.registers[x86asm.ESP]
	returnAddress, err := m.readUint32(esp)
	if err != nil {
		return "", "", err
	}
	arguments := make([]starlark.Value, hook.argc)
	for index := 0; index < hook.argc; index++ {
		value, err := m.readUint32(esp + 4 + uint32(index*4))
		if err != nil {
			return "", "", err
		}
		arguments[index] = starlark.MakeUint64(uint64(value))
	}
	event := newStarlarkRecord(map[string]starlark.Value{
		"machine":          m,
		"module":           starlark.String(hook.module),
		"name":             starlark.String(hook.name),
		"address":          starlark.MakeUint64(uint64(hook.address)),
		"return_address":   starlark.MakeUint64(uint64(returnAddress)),
		"argument_address": starlark.MakeUint64(uint64(esp + 4)),
		"args":             starlark.NewList(arguments),
	})
	m.hookDepth++
	result, err := starlark.Call(thread, hook.callback, starlark.Tuple{event}, nil)
	m.hookDepth--
	if err != nil {
		return "plugin", fmt.Sprintf("hook %s!%s: %v", hook.module, hook.name, err), nil
	}
	if m.pendingTransfer {
		m.pendingTransfer = false
		return "", "", nil
	}
	if result != starlark.None {
		if err := m.applyHookResult(result); err != nil {
			return "plugin", fmt.Sprintf("hook %s!%s: %v", hook.module, hook.name, err), nil
		}
	}
	if m.pendingStop != "" {
		stop, detail := m.pendingStop, m.pendingStopDetail
		m.pendingStop, m.pendingStopDetail = "", ""
		return stop, detail, nil
	}
	returnAddress, err = m.pop()
	if err != nil {
		return "", "", err
	}
	if m.callDepth > 0 {
		m.callDepth--
	}
	if len(m.callFrames) > 0 {
		m.callFrames = m.callFrames[:len(m.callFrames)-1]
	}
	if hook.convention == "stdcall" {
		m.registers[x86asm.ESP] += uint32(hook.argc * 4)
	}
	m.eip = returnAddress
	return "", "", nil
}

func emulatorHookResult(value starlark.Value) (uint32, bool) {
	integer, ok := value.(starlark.Int)
	if !ok {
		return 0, false
	}
	if unsigned, ok := integer.Uint64(); ok && unsigned <= math.MaxUint32 {
		return uint32(unsigned), true
	}
	if signed, ok := integer.Int64(); ok && signed >= math.MinInt32 && signed < 0 {
		return uint32(int32(signed)), true
	}
	return 0, false
}

func (m *emulatorX86) applyHookResult(value starlark.Value) error {
	if integer, ok := emulatorHookResult(value); ok {
		m.registers[x86asm.EAX] = integer
		return nil
	}
	if floating, ok := value.(starlark.Float); ok {
		if err := m.x87Push(float64(floating)); err != nil {
			return fmt.Errorf("return float: %w", err)
		}
		return nil
	}
	return fmt.Errorf("returned %s, want int, float, or None", value.Type())
}

func (m *emulatorX86) hookBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var callback starlark.Callable
	module, name := "", ""
	ordinal, address, argc := 0, 0, 0
	convention := "stdcall"
	if err := starlark.UnpackArgs("hook", args, kwargs, "callback", &callback, "module?", &module, "name?", &name, "ordinal?", &ordinal, "address?", &address, "argc?", &argc, "convention?", &convention); err != nil {
		return nil, err
	}
	if m.frozen || argc < 0 || (convention != "stdcall" && convention != "cdecl") {
		return nil, fmt.Errorf("hook: invalid arguments or frozen machine")
	}
	targets := []uint32{}
	if address != 0 {
		targets = append(targets, uint32(address))
	} else {
		for target, item := range m.imports {
			moduleMatch := module == "" || strings.EqualFold(module, item.module)
			nameMatch := name != "" && strings.EqualFold(name, item.name)
			ordinalMatch := ordinal != 0 && uint16(ordinal) == item.ordinal
			if moduleMatch && (nameMatch || ordinalMatch) {
				targets = append(targets, target)
			}
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("hook: no matching address or import")
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i] < targets[j] })
	for _, target := range targets {
		item := m.imports[target]
		hookModule, hookName := module, name
		if hookModule == "" {
			hookModule = item.module
		}
		if hookName == "" {
			hookName = item.name
			if hookName == "" && item.ordinal != 0 {
				hookName = fmt.Sprintf("#%d", item.ordinal)
			}
		}
		m.hooks[target] = emulatorHook{module: hookModule, name: hookName, address: target, argc: argc, convention: convention, callback: callback}
		if item.module != "" {
			m.hookRules = append(m.hookRules, emulatorHookRule{
				module:     strings.ToLower(item.module),
				name:       strings.ToLower(item.name),
				ordinal:    item.ordinal,
				argc:       argc,
				convention: convention,
				callback:   callback,
			})
		}
	}
	values := make([]starlark.Value, len(targets))
	for i, target := range targets {
		values[i] = starlark.MakeUint64(uint64(target))
	}
	return starlark.NewList(values), nil
}

func (m *emulatorX86) applyHookRules(target uint32, imported emulatorImport) {
	for _, rule := range m.hookRules {
		if rule.module != strings.ToLower(imported.module) {
			continue
		}
		nameMatches := rule.name != "" && strings.EqualFold(rule.name, imported.name)
		ordinalMatches := rule.ordinal != 0 && rule.ordinal == imported.ordinal
		if !nameMatches && !ordinalMatches {
			continue
		}
		name := imported.name
		if name == "" {
			name = fmt.Sprintf("#%d", imported.ordinal)
		}
		m.hooks[target] = emulatorHook{
			module:     imported.module,
			name:       name,
			address:    target,
			argc:       rule.argc,
			convention: rule.convention,
			callback:   rule.callback,
		}
	}
}
func (m *emulatorX86) useBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var plugins starlark.Value
	if err := starlark.UnpackArgs("use", args, kwargs, "plugins", &plugins); err != nil {
		return nil, err
	}
	iterable, ok := plugins.(starlark.Iterable)
	if !ok {
		plugins = starlark.Tuple{plugins}
		iterable = plugins.(starlark.Iterable)
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	var plugin starlark.Value
	for iterator.Next(&plugin) {
		attributes, ok := plugin.(starlark.HasAttrs)
		if !ok {
			return nil, fmt.Errorf("use: plugin %s has no install method", plugin.Type())
		}
		install, err := attributes.Attr("install")
		if err != nil || install == nil {
			return nil, fmt.Errorf("use: plugin %s has no install method", plugin.Type())
		}
		callable, ok := install.(starlark.Callable)
		if !ok {
			return nil, fmt.Errorf("use: install is not callable")
		}
		if _, err := starlark.Call(thread, callable, starlark.Tuple{m}, nil); err != nil {
			return nil, err
		}
		state, err := attributes.Attr("state")
		if err != nil {
			return nil, fmt.Errorf("use: read plugin state: %w", err)
		}
		if state != nil && state != starlark.None {
			m.pluginStates = append(m.pluginStates, state)
		}
	}
	return m, nil
}

func (m *emulatorX86) readBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address, size int
	if err := starlark.UnpackArgs("read", args, kwargs, "address", &address, "size", &size); err != nil {
		return nil, err
	}
	if address < 0 || size < 0 {
		return nil, fmt.Errorf("read: address and size must be non-negative")
	}
	data, err := m.readMemory(uint32(address), size, 'r')
	if err != nil {
		return nil, err
	}
	return starlark.Bytes(bytes.Clone(data)), nil
}

func (m *emulatorX86) allocateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	size, alignment := 0, 16
	name := "plugin"
	value := starlark.Value(starlark.None)
	requestedValue := starlark.Value(starlark.None)
	readable, writable, executable := true, true, false
	if err := starlark.UnpackArgs("allocate", args, kwargs,
		"size?", &size, "value?", &value, "address?", &requestedValue, "alignment?", &alignment, "name?", &name,
		"readable?", &readable, "writable?", &writable, "executable?", &executable,
	); err != nil {
		return nil, err
	}
	var initial []byte
	if value != starlark.None {
		var err error
		initial, err = bytesForBinaryValue(value)
		if err != nil {
			return nil, fmt.Errorf("allocate: value: %w", err)
		}
		if size == 0 {
			size = len(initial)
		}
	}
	if m.frozen || size <= 0 || len(initial) > size || alignment <= 0 || alignment > 1<<20 || alignment&(alignment-1) != 0 {
		return nil, fmt.Errorf("allocate: invalid size, value, alignment, or frozen machine")
	}
	mask := uint32(alignment - 1)
	address := uint32(0)
	if requestedValue != starlark.None {
		requested, err := starlark.AsInt32(requestedValue)
		if err != nil || requested < 0 || uint64(requested)+uint64(size) > uint64(math.MaxUint32)+1 || uint32(requested)&mask != 0 {
			return nil, fmt.Errorf("allocate: requested address does not fit the aligned 32-bit range")
		}
		address = uint32(requested)
	} else {
		for index, available := range m.freeAllocations {
			candidate := (available.start + mask) &^ mask
			availableEnd := uint64(available.start) + uint64(available.size)
			if candidate < available.start || uint64(candidate)+uint64(size) > availableEnd || uint64(candidate)+uint64(size) > uint64(m.stackLow) {
				continue
			}
			m.freeAllocations = append(m.freeAllocations[:index], m.freeAllocations[index+1:]...)
			if candidate > available.start {
				m.addFreeAllocation(available.start, candidate-available.start)
			}
			end := uint64(candidate) + uint64(size)
			if end < availableEnd {
				m.addFreeAllocation(uint32(end), uint32(availableEnd-end))
			}
			address = candidate
			break
		}
		if address == 0 {
			var available bool
			address, available = m.availableAllocation(m.nextAllocation, uint32(size), uint32(alignment))
			if !available {
				return nil, fmt.Errorf("allocate: plugin address space exhausted")
			}
			m.nextAllocation = address + uint32(size)
		}
	}
	data := make([]byte, size)
	copy(data, initial)
	if err := m.addMapping(name, address, data, readable, writable, executable); err != nil {
		if requestedValue == starlark.None {
			m.addFreeAllocation(address, uint32(size))
		}
		return nil, err
	}
	m.allocations[address] = true
	return starlark.MakeUint64(uint64(address)), nil
}

func (m *emulatorX86) availableAllocation(start, size, alignment uint32) (uint32, bool) {
	mask := uint64(alignment - 1)
	candidate := (uint64(start) + mask) &^ mask
	for candidate+uint64(size) <= uint64(m.stackLow) {
		advanced := false
		for _, mapping := range m.mappings {
			mappingStart := uint64(mapping.start)
			mappingEnd := mappingStart + uint64(len(mapping.data))
			if candidate+uint64(size) <= mappingStart {
				break
			}
			if candidate < mappingEnd && mappingStart < candidate+uint64(size) {
				candidate = (mappingEnd + mask) &^ mask
				advanced = true
				break
			}
		}
		if !advanced {
			return uint32(candidate), true
		}
	}
	return 0, false
}

func (m *emulatorX86) addFreeAllocation(start, size uint32) {
	if size == 0 {
		return
	}
	m.freeAllocations = append(m.freeAllocations, emulatorFreeRange{start: start, size: size})
	sort.Slice(m.freeAllocations, func(i, j int) bool { return m.freeAllocations[i].start < m.freeAllocations[j].start })
	merged := m.freeAllocations[:0]
	for _, current := range m.freeAllocations {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		previous := &merged[len(merged)-1]
		previousEnd := uint64(previous.start) + uint64(previous.size)
		if uint64(current.start) <= previousEnd {
			currentEnd := uint64(current.start) + uint64(current.size)
			if currentEnd > previousEnd {
				previous.size = uint32(currentEnd - uint64(previous.start))
			}
			continue
		}
		merged = append(merged, current)
	}
	m.freeAllocations = merged
}

func (m *emulatorX86) freeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address uint64
	if err := starlark.UnpackArgs("free", args, kwargs, "address", &address); err != nil {
		return nil, err
	}
	if m.frozen || address > math.MaxUint32 || !m.allocations[uint32(address)] {
		return nil, fmt.Errorf("free: address %#x is not a live plugin allocation or machine is frozen", address)
	}
	for index, mapping := range m.mappings {
		if mapping.start != uint32(address) {
			continue
		}
		mappingEnd := uint64(mapping.start) + uint64(len(mapping.data))
		protections := m.protections[:0]
		for _, protection := range m.protections {
			protectionStart := uint64(protection.start)
			if protectionStart < mappingEnd && uint64(mapping.start) < protectionStart+protection.size {
				continue
			}
			protections = append(protections, protection)
		}
		m.protections = protections
		m.mappedBytes -= int64(len(mapping.data))
		m.mappings = append(m.mappings[:index], m.mappings[index+1:]...)
		m.mappingCache = [2]int{-1, -1}
		delete(m.allocations, uint32(address))
		m.addFreeAllocation(uint32(address), uint32(len(mapping.data)))
		return starlark.None, nil
	}
	return nil, fmt.Errorf("free: allocation %#x has no mapping", address)
}

func (m *emulatorX86) protectBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address, size uint64
	readable, writable, executable := true, false, false
	if err := starlark.UnpackArgs("protect", args, kwargs,
		"address", &address, "size", &size,
		"readable?", &readable, "writable?", &writable, "executable?", &executable,
	); err != nil {
		return nil, err
	}
	if m.frozen || size == 0 || address > math.MaxUint32 || size > uint64(math.MaxUint32)+1-address {
		return nil, fmt.Errorf("protect: invalid address range or frozen machine")
	}
	end := address + size
	cursor := address
	indices := []int{}
	for cursor < end {
		found := -1
		for index := range m.mappings {
			mapping := &m.mappings[index]
			mappingEnd := uint64(mapping.start) + uint64(len(mapping.data))
			if uint64(mapping.start) <= cursor && cursor < mappingEnd {
				found = index
				cursor = min(end, mappingEnd)
				break
			}
		}
		if found < 0 {
			return nil, fmt.Errorf("protect: unmapped memory at 0x%08x", cursor)
		}
		indices = append(indices, found)
	}
	previous := []starlark.Value{}
	cursor = address
	for cursor < end {
		mapping := &m.mappings[indices[0]]
		for _, index := range indices {
			candidate := &m.mappings[index]
			if uint64(candidate.start) <= cursor && cursor < uint64(candidate.start)+uint64(len(candidate.data)) {
				mapping = candidate
				break
			}
		}
		read, write, execute := mapping.readable, mapping.writable, mapping.executable
		next := min(end, uint64(mapping.start)+uint64(len(mapping.data)))
		for _, protection := range m.protections {
			protectionStart := uint64(protection.start)
			protectionEnd := protectionStart + protection.size
			if protectionEnd <= cursor {
				continue
			}
			if protectionStart > cursor {
				next = min(next, protectionStart)
				break
			}
			read, write, execute = protection.readable, protection.writable, protection.executable
			next = min(next, protectionEnd)
			break
		}
		previous = append(previous, newStarlarkRecord(map[string]starlark.Value{
			"start":      starlark.MakeUint64(cursor),
			"size":       starlark.MakeUint64(next - cursor),
			"readable":   starlark.Bool(read),
			"writable":   starlark.Bool(write),
			"executable": starlark.Bool(execute),
		}))
		cursor = next
	}
	updated := make([]emulatorMemoryProtection, 0, len(m.protections)+1)
	for _, protection := range m.protections {
		protectionStart := uint64(protection.start)
		protectionEnd := protectionStart + protection.size
		if protectionEnd <= address || protectionStart >= end {
			updated = append(updated, protection)
			continue
		}
		if protectionStart < address {
			before := protection
			before.size = address - protectionStart
			updated = append(updated, before)
		}
		if protectionEnd > end {
			after := protection
			after.start = uint32(end)
			after.size = protectionEnd - end
			updated = append(updated, after)
		}
	}
	updated = append(updated, emulatorMemoryProtection{start: uint32(address), size: size, readable: readable, writable: writable, executable: executable})
	sort.Slice(updated, func(i, j int) bool { return updated[i].start < updated[j].start })
	m.protections = updated[:0]
	for _, protection := range updated {
		if len(m.protections) != 0 {
			last := &m.protections[len(m.protections)-1]
			if uint64(last.start)+last.size == uint64(protection.start) && last.readable == protection.readable && last.writable == protection.writable && last.executable == protection.executable {
				last.size += protection.size
				continue
			}
		}
		m.protections = append(m.protections, protection)
	}
	clear(m.decoded)
	m.decodedEntries = nil
	m.decodedCursor = 0
	clear(m.decodedPages)
	m.decodedPage = nil
	clear(m.cachedCodePages)
	clear(m.transformationCache)
	clear(m.crcLoops)
	clear(m.crcLoopsChecked)
	clear(m.wideCompare)
	clear(m.wideCompareChecked)
	clear(m.asciiLower)
	clear(m.asciiLowerChecked)
	clear(m.mixedCompare)
	clear(m.mixedCompareChecked)
	clear(m.zeroByteScan)
	clear(m.zeroByteScanChecked)
	return starlark.NewList(previous), nil
}

func (m *emulatorX86) readCBytesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address int
	maximum := 32 << 10
	requireTerminator := true
	unitWidth := 1
	if err := starlark.UnpackArgs("read_cbytes", args, kwargs, "address", &address, "maximum?", &maximum, "require_terminator?", &requireTerminator, "unit_width?", &unitWidth); err != nil {
		return nil, err
	}
	if address < 0 || uint64(address) > math.MaxUint32 || maximum <= 0 || maximum > defaultBinaryBuilderLimit || unitWidth <= 0 || unitWidth > 16 || maximum%unitWidth != 0 || uint64(address)+uint64(maximum) > uint64(math.MaxUint32)+1 {
		return nil, fmt.Errorf("read_cbytes: invalid address, maximum, or unit_width")
	}
	if unitWidth > 1 {
		data := make([]byte, 0, min(maximum, 256))
		zero := make([]byte, unitWidth)
		for offset := 0; offset < maximum; offset += unitWidth {
			unit, err := m.readMemory(uint32(address+offset), unitWidth, 'r')
			if err != nil {
				return nil, fmt.Errorf("read_cbytes: %w", err)
			}
			if bytes.Equal(unit, zero) {
				return starlark.Bytes(data), nil
			}
			data = append(data, unit...)
		}
		if !requireTerminator {
			return starlark.Bytes(data), nil
		}
		return nil, fmt.Errorf("read_cbytes: terminator not found within %d bytes", maximum)
	}
	data := make([]byte, 0, min(maximum, 256))
	for len(data) < maximum {
		current := uint32(address + len(data))
		mapping, offset, err := m.mapping(current, 1, 'r')
		if err != nil {
			return nil, fmt.Errorf("read_cbytes: %w", err)
		}
		count := min(maximum-len(data), len(mapping.data)-offset, emulatorAcceleratedChunkSize)
		chunk := mapping.data[offset : offset+count]
		if terminator := bytes.IndexByte(chunk, 0); terminator >= 0 {
			data = append(data, chunk[:terminator]...)
			return starlark.Bytes(data), nil
		}
		data = append(data, chunk...)
	}
	if !requireTerminator {
		return starlark.Bytes(data), nil
	}
	return nil, fmt.Errorf("read_cbytes: terminator not found within %d bytes", maximum)
}

func (m *emulatorX86) readCStringBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address int
	encoding := "ascii"
	maximum := 32 << 10
	if err := starlark.UnpackArgs("read_cstring", args, kwargs, "address", &address, "encoding?", &encoding, "maximum?", &maximum); err != nil {
		return nil, err
	}
	if address < 0 || uint64(address) > math.MaxUint32 || maximum <= 0 || maximum > defaultBinaryBuilderLimit || uint64(address)+uint64(maximum) > uint64(math.MaxUint32)+1 {
		return nil, fmt.Errorf("read_cstring: invalid address or maximum")
	}
	width := 1
	normalized := strings.ToLower(strings.ReplaceAll(encoding, "-", ""))
	if normalized == "utf16le" || normalized == "utf16be" {
		width = 2
	} else if normalized != "ascii" && normalized != "utf8" && normalized != "windows1252" && normalized != "cp1252" {
		return nil, fmt.Errorf("read_cstring: unsupported encoding %q", encoding)
	}
	data := make([]byte, 0, min(maximum, 256))
	for offset := 0; offset+width <= maximum; offset += width {
		unit, err := m.readMemory(uint32(address+offset), width, 'r')
		if err != nil {
			return nil, fmt.Errorf("read_cstring: %w", err)
		}
		terminated := unit[0] == 0
		if width == 2 {
			terminated = terminated && unit[1] == 0
		}
		if terminated {
			text, err := binaryapi.DecodeText(data, encoding, false)
			if err != nil {
				return nil, fmt.Errorf("read_cstring: %w", err)
			}
			return starlark.String(text), nil
		}
		data = append(data, unit...)
	}
	return nil, fmt.Errorf("read_cstring: terminator not found within %d bytes", maximum)
}
func (m *emulatorX86) writeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address int
	var value starlark.Value
	if err := starlark.UnpackArgs("write", args, kwargs, "address", &address, "value", &value); err != nil {
		return nil, err
	}
	if m.frozen || address < 0 {
		return nil, fmt.Errorf("write: invalid address or frozen machine")
	}
	data, err := bytesForBinaryValue(value)
	if err != nil {
		return nil, err
	}
	if err := m.writeMemory(uint32(address), data); err != nil {
		return nil, err
	}
	return starlark.None, nil
}

func (m *emulatorX86) watchMemoryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address, size uint64
	limit := 4096
	if err := starlark.UnpackArgs("watch_memory", args, kwargs, "address", &address, "size", &size, "limit?", &limit); err != nil {
		return nil, err
	}
	if m.frozen || size == 0 || address > math.MaxUint32 || size > uint64(math.MaxUint32)+1-address || limit <= 0 || limit > 65536 {
		return nil, fmt.Errorf("watch_memory: invalid address range, limit, or frozen machine")
	}
	id := m.nextMemoryWatch
	m.nextMemoryWatch++
	m.memoryWatches[id] = &emulatorMemoryWatch{id: id, start: uint32(address), size: size, limit: limit}
	return starlark.MakeUint64(id), nil
}

func (m *emulatorX86) memoryWritesBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id uint64
	reset := false
	if err := starlark.UnpackArgs("memory_writes", args, kwargs, "watch", &id, "reset?", &reset); err != nil {
		return nil, err
	}
	watch := m.memoryWatches[id]
	if watch == nil {
		return nil, fmt.Errorf("memory_writes: unknown watch %d", id)
	}
	ordered := append([]emulatorMemoryWrite(nil), watch.entries...)
	if len(ordered) == watch.limit && watch.cursor != 0 {
		ordered = append(ordered[watch.cursor:], ordered[:watch.cursor]...)
	}
	entries := make([]starlark.Value, len(ordered))
	for index, entry := range ordered {
		entries[index] = newStarlarkRecord(map[string]starlark.Value{
			"eip":     starlark.MakeUint64(uint64(entry.eip)),
			"address": starlark.MakeUint64(uint64(entry.address)),
			"before":  starlark.Bytes(entry.before),
			"after":   starlark.Bytes(entry.after),
		})
	}
	result := newStarlarkRecord(map[string]starlark.Value{
		"id":      starlark.MakeUint64(watch.id),
		"start":   starlark.MakeUint64(uint64(watch.start)),
		"size":    starlark.MakeUint64(uint64(watch.size)),
		"limit":   starlark.MakeInt(watch.limit),
		"dropped": starlark.MakeUint64(watch.dropped),
		"entries": starlark.NewList(entries),
	})
	if reset {
		watch.entries = nil
		watch.cursor = 0
		watch.dropped = 0
	}
	return result, nil
}

func (m *emulatorX86) watchCodeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address, size uint64
	limit := 4096
	stackBytes := 0
	var captureValues *starlark.Dict
	if err := starlark.UnpackArgs("watch_code", args, kwargs, "address", &address, "size", &size, "limit?", &limit, "stack_bytes?", &stackBytes, "captures?", &captureValues); err != nil {
		return nil, err
	}
	if m.frozen || size == 0 || address > math.MaxUint32 || size > uint64(math.MaxUint32)+1-address || limit <= 0 || limit > 65536 || stackBytes < 0 || stackBytes > 512 {
		return nil, fmt.Errorf("watch_code: invalid address range, limit, or frozen machine")
	}
	captures := make([]emulatorCodeCapture, 0)
	captureBytes := stackBytes
	if captureValues != nil {
		if captureValues.Len() > 16 {
			return nil, fmt.Errorf("watch_code: captures must contain at most 16 entries")
		}
		for _, item := range captureValues.Items() {
			name, ok := starlark.AsString(item[0])
			if !ok || name == "" {
				return nil, fmt.Errorf("watch_code: capture names must be non-empty strings")
			}
			specification, ok := item[1].(*starlark.Dict)
			if !ok {
				return nil, fmt.Errorf("watch_code: capture %q must be a dictionary", name)
			}
			base := ""
			offset, dereference, captureSize := 0, 0, 0
			if err := starlark.UnpackArgs("watch_code capture", nil, specification.Items(), "base", &base, "size", &captureSize, "offset?", &offset, "dereference?", &dereference); err != nil {
				return nil, err
			}
			register, ok := emulatorRegister(base)
			if !ok || captureSize <= 0 || captureSize > 512 || dereference < 0 || dereference > 2 {
				return nil, fmt.Errorf("watch_code: capture %q has an invalid base, size, or dereference count", name)
			}
			captureBytes += captureSize
			if captureBytes > 512 {
				return nil, fmt.Errorf("watch_code: stack and memory captures exceed 512 bytes per entry")
			}
			captures = append(captures, emulatorCodeCapture{name: name, base: register, offset: offset, dereference: dereference, size: captureSize})
		}
	}
	id := m.nextCodeWatch
	m.nextCodeWatch++
	m.codeWatches[id] = &emulatorCodeWatch{id: id, start: uint32(address), size: size, limit: limit, stackBytes: stackBytes, captures: captures}
	return starlark.MakeUint64(id), nil
}

func (m *emulatorX86) codeTraceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id uint64
	reset := false
	if err := starlark.UnpackArgs("code_trace", args, kwargs, "watch", &id, "reset?", &reset); err != nil {
		return nil, err
	}
	watch := m.codeWatches[id]
	if watch == nil {
		return nil, fmt.Errorf("code_trace: unknown watch %d", id)
	}
	ordered := append([]emulatorCodeEntry(nil), watch.entries...)
	if len(ordered) == watch.limit && watch.cursor != 0 {
		ordered = append(ordered[watch.cursor:], ordered[:watch.cursor]...)
	}
	entries := make([]starlark.Value, len(ordered))
	for index, entry := range ordered {
		registers := newStarlarkRecord(map[string]starlark.Value{
			"eax":    starlark.MakeUint64(uint64(entry.eax)),
			"ebx":    starlark.MakeUint64(uint64(entry.ebx)),
			"ecx":    starlark.MakeUint64(uint64(entry.ecx)),
			"edx":    starlark.MakeUint64(uint64(entry.edx)),
			"esi":    starlark.MakeUint64(uint64(entry.esi)),
			"edi":    starlark.MakeUint64(uint64(entry.edi)),
			"esp":    starlark.MakeUint64(uint64(entry.esp)),
			"ebp":    starlark.MakeUint64(uint64(entry.ebp)),
			"eip":    starlark.MakeUint64(uint64(entry.address)),
			"eflags": starlark.MakeUint64(uint64(entry.eflags)),
		})
		captures := starlark.StringDict{}
		for name, data := range entry.captures {
			captures[name] = starlark.Bytes(data)
		}
		entries[index] = newStarlarkRecord(map[string]starlark.Value{
			"address":     starlark.MakeUint64(uint64(entry.address)),
			"esp":         starlark.MakeUint64(uint64(entry.esp)),
			"instruction": starlark.String(entry.instruction),
			"registers":   registers,
			"stack":       starlark.Bytes(entry.stack),
			"captures":    newStarlarkRecord(captures),
		})
	}
	result := newStarlarkRecord(map[string]starlark.Value{
		"id":          starlark.MakeUint64(watch.id),
		"start":       starlark.MakeUint64(uint64(watch.start)),
		"size":        starlark.MakeUint64(watch.size),
		"limit":       starlark.MakeInt(watch.limit),
		"stack_bytes": starlark.MakeInt(watch.stackBytes),
		"dropped":     starlark.MakeUint64(watch.dropped),
		"entries":     starlark.NewList(entries),
	})
	if reset {
		watch.entries = nil
		watch.cursor = 0
		watch.dropped = 0
	}
	return result, nil
}

func (m *emulatorX86) configureTraceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	enabled := true
	limit := 0
	reset := true
	if err := starlark.UnpackArgs("configure_trace", args, kwargs, "enabled?", &enabled, "limit?", &limit, "reset?", &reset); err != nil {
		return nil, err
	}
	if m.frozen || limit < 0 || limit > 65536 {
		return nil, fmt.Errorf("configure_trace: invalid limit or frozen machine")
	}
	previous := newStarlarkRecord(map[string]starlark.Value{
		"enabled": starlark.Bool(m.trace),
		"limit":   starlark.MakeInt(m.traceLimit),
	})
	m.trace = enabled
	if limit != 0 {
		m.traceLimit = limit
	}
	if reset {
		m.traceEntries = nil
		m.traceCursor = 0
	}
	return previous, nil
}

func (m *emulatorX86) recordCallTrace(site, target uint32) {
	if !m.callTrace {
		return
	}
	if m.callTraceSize != 0 && (site < m.callTraceStart || uint64(site)-uint64(m.callTraceStart) >= m.callTraceSize) {
		return
	}
	entry := emulatorCallFrame{site: site, target: target}
	if len(m.callTraceEntries) < m.callTraceLimit {
		m.callTraceEntries = append(m.callTraceEntries, entry)
		return
	}
	m.callTraceEntries[m.callTraceCursor] = entry
	m.callTraceCursor = (m.callTraceCursor + 1) % len(m.callTraceEntries)
	m.callTraceDropped++
}

func (m *emulatorX86) callTraceValue(reset bool) starlark.Value {
	ordered := append([]emulatorCallFrame(nil), m.callTraceEntries...)
	if len(ordered) == m.callTraceLimit && m.callTraceCursor != 0 {
		ordered = append(ordered[m.callTraceCursor:], ordered[:m.callTraceCursor]...)
	}
	entries := make([]starlark.Value, len(ordered))
	for index, entry := range ordered {
		entries[index] = newStarlarkRecord(map[string]starlark.Value{
			"site":   starlark.MakeUint64(uint64(entry.site)),
			"target": starlark.MakeUint64(uint64(entry.target)),
		})
	}
	result := newStarlarkRecord(map[string]starlark.Value{
		"dropped": starlark.MakeUint64(m.callTraceDropped),
		"entries": starlark.NewList(entries),
		"limit":   starlark.MakeInt(m.callTraceLimit),
		"start":   starlark.MakeUint64(uint64(m.callTraceStart)),
		"size":    starlark.MakeUint64(m.callTraceSize),
	})
	if reset {
		m.callTraceEntries = nil
		m.callTraceCursor = 0
		m.callTraceDropped = 0
	}
	return result
}

func (m *emulatorX86) configureCallTraceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	enabled := true
	limit := 0
	reset := true
	var start, size uint64
	if err := starlark.UnpackArgs("configure_call_trace", args, kwargs, "enabled?", &enabled, "limit?", &limit, "start?", &start, "size?", &size, "reset?", &reset); err != nil {
		return nil, err
	}
	if m.frozen || limit < 0 || limit > 65536 || start > math.MaxUint32 || size > uint64(math.MaxUint32)+1-start {
		return nil, fmt.Errorf("configure_call_trace: invalid limit or frozen machine")
	}
	previous := newStarlarkRecord(map[string]starlark.Value{
		"enabled": starlark.Bool(m.callTrace),
		"limit":   starlark.MakeInt(m.callTraceLimit),
		"start":   starlark.MakeUint64(uint64(m.callTraceStart)),
		"size":    starlark.MakeUint64(m.callTraceSize),
	})
	m.callTrace = enabled
	m.callTraceStart = uint32(start)
	m.callTraceSize = size
	if limit != 0 {
		m.callTraceLimit = limit
	}
	if reset {
		m.callTraceEntries = nil
		m.callTraceCursor = 0
		m.callTraceDropped = 0
	}
	return previous, nil
}

func (m *emulatorX86) callTraceBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	reset := false
	if err := starlark.UnpackArgs("call_trace", args, kwargs, "reset?", &reset); err != nil {
		return nil, err
	}
	return m.callTraceValue(reset), nil
}

func (m *emulatorX86) getRegisterBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("get_register", args, kwargs, "name", &name); err != nil {
		return nil, err
	}
	if strings.EqualFold(name, "eflags") {
		return starlark.MakeUint64(uint64(m.flagsValue())), nil
	}
	register, ok := emulatorRegister(name)
	if !ok {
		return nil, fmt.Errorf("get_register: unknown register %q", name)
	}
	if register == x86asm.EIP {
		return starlark.MakeUint64(uint64(m.eip)), nil
	}
	return starlark.MakeUint64(uint64(m.registerValue(register))), nil
}
func (m *emulatorX86) setRegisterBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var value starlark.Int
	if err := starlark.UnpackArgs("set_register", args, kwargs, "name", &name, "value", &value); err != nil {
		return nil, err
	}
	number, numberOK := value.Uint64()
	if m.frozen || !numberOK || number > math.MaxUint32 {
		return nil, fmt.Errorf("set_register: invalid register, value, or frozen machine")
	}
	if strings.EqualFold(name, "eflags") {
		m.setFlagsValue(uint32(number))
		return m, nil
	}
	register, ok := emulatorRegister(name)
	if !ok {
		return nil, fmt.Errorf("set_register: invalid register, value, or frozen machine")
	}
	if register == x86asm.EIP {
		m.eip = uint32(number)
		return m, nil
	}
	m.setRegisterValue(register, uint32(number))
	return m, nil
}

func (m *emulatorX86) onExceptionBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var callback starlark.Callable
	if err := starlark.UnpackArgs("on_exception", args, kwargs, "callback", &callback); err != nil {
		return nil, err
	}
	if m.frozen || m.exceptionHandler != nil {
		return nil, fmt.Errorf("on_exception: handler already installed or machine frozen")
	}
	m.exceptionHandler = callback
	return starlark.None, nil
}

func (m *emulatorX86) dispatchException(thread *starlark.Thread, code, address uint32, information []uint32) (bool, string) {
	values := make([]starlark.Value, len(information))
	for index, value := range information {
		values[index] = starlark.MakeUint64(uint64(value))
	}
	event := newStarlarkRecord(map[string]starlark.Value{
		"machine":     m,
		"code":        starlark.MakeUint64(uint64(code)),
		"address":     starlark.MakeUint64(uint64(address)),
		"information": starlark.NewList(values),
	})
	m.hookDepth++
	result, err := starlark.Call(thread, m.exceptionHandler, starlark.Tuple{event}, nil)
	m.hookDepth--
	if err != nil {
		return false, err.Error()
	}
	if result != starlark.None {
		return false, fmt.Sprintf("exception handler returned %s, want None", result.Type())
	}
	if m.pendingTransfer {
		m.pendingTransfer = false
		return true, ""
	}
	return false, ""
}

func (m *emulatorX86) stopBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var reason, detail string
	value := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("stop", args, kwargs, "reason", &reason, "detail?", &detail, "value?", &value); err != nil {
		return nil, err
	}
	if m.frozen || m.hookDepth == 0 || reason == "" || reason == "return" || reason == "plugin" || reason == "exception" {
		return nil, fmt.Errorf("stop: requires an active hook and a non-reserved reason")
	}
	if value != starlark.None {
		integer, ok := value.(starlark.Int)
		if !ok {
			return nil, fmt.Errorf("stop: value must be a 32-bit integer")
		}
		number, ok := integer.Uint64()
		if !ok || number > math.MaxUint32 {
			return nil, fmt.Errorf("stop: value must be a 32-bit integer")
		}
		m.registers[x86asm.EAX] = uint32(number)
	}
	m.pendingStop = reason
	m.pendingStopDetail = detail
	return starlark.None, nil
}

func (m *emulatorX86) transferBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var address starlark.Int
	espValue, ebpValue := starlark.Value(starlark.None), starlark.Value(starlark.None)
	returnAddressValue := starlark.Value(starlark.None)
	if err := starlark.UnpackArgs("transfer", args, kwargs, "address", &address, "esp?", &espValue, "ebp?", &ebpValue, "return_address?", &returnAddressValue); err != nil {
		return nil, err
	}
	target, ok := address.Uint64()
	if m.frozen || m.hookDepth == 0 || !ok || target > math.MaxUint32 {
		return nil, fmt.Errorf("transfer: requires an active hook and uint32 address")
	}
	registers := make(map[x86asm.Reg]uint32, 2)
	for name, value := range map[string]starlark.Value{"esp": espValue, "ebp": ebpValue} {
		if value == starlark.None {
			continue
		}
		integer, ok := value.(starlark.Int)
		number, numberOK := integer.Uint64()
		if !ok || !numberOK || number > math.MaxUint32 {
			return nil, fmt.Errorf("transfer: %s must fit uint32", name)
		}
		register, _ := emulatorRegister(name)
		registers[register] = uint32(number)
	}
	returnAddress := uint32(0)
	call := returnAddressValue != starlark.None
	if call {
		integer, ok := returnAddressValue.(starlark.Int)
		number, numberOK := integer.Uint64()
		if !ok || !numberOK || number > math.MaxUint32 {
			return nil, fmt.Errorf("transfer: return_address must fit uint32")
		}
		returnAddress = uint32(number)
		if _, err := m.readMemory(returnAddress, 1, 'x'); err != nil {
			return nil, fmt.Errorf("transfer: return_address is not executable: %w", err)
		}
		if m.callDepth >= m.callDepthLimit {
			return nil, fmt.Errorf("transfer: call depth limit reached at 0x%08x calling 0x%08x", m.currentInstruction, uint32(target))
		}
		esp := m.registers[x86asm.ESP]
		if value, changed := registers[x86asm.ESP]; changed {
			esp = value
		}
		if esp < 4 {
			return nil, fmt.Errorf("transfer: stack underflow while pushing return_address")
		}
		if err := m.writeUint32(esp-4, returnAddress); err != nil {
			return nil, fmt.Errorf("transfer: push return_address: %w", err)
		}
		registers[x86asm.ESP] = esp - 4
	}
	for register, value := range registers {
		m.registers[register] = value
	}
	if call {
		site := m.currentInstruction
		m.recordCallTrace(site, uint32(target))
		m.callDepth++
		m.callFrames = append(m.callFrames, emulatorCallFrame{site: site, target: uint32(target)})
	}
	m.eip = uint32(target)
	m.pendingTransfer = true
	return starlark.None, nil
}

func (e *emulatorExecution) runBuiltin(thread *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	instructionLimit := 0
	if err := starlark.UnpackArgs("execution.run", args, kwargs, "instruction_limit?", &instructionLimit); err != nil {
		return nil, err
	}
	if instructionLimit < 0 || (instructionLimit > 0 && uint64(instructionLimit) > e.machine.instructionLimit) {
		return nil, fmt.Errorf("execution.run: instruction_limit must not exceed the machine limit")
	}
	if e.frozen || e.machine.frozen {
		return nil, fmt.Errorf("execution.run: execution is frozen")
	}
	if e.closed {
		return nil, fmt.Errorf("execution.run: execution is closed")
	}
	if e.done {
		return e.result, nil
	}
	parent, err := e.machine.captureContext()
	if err != nil {
		return nil, fmt.Errorf("execution.run: capture caller: %w", err)
	}
	if err := e.machine.restoreContext(e.context); err != nil {
		return nil, fmt.Errorf("execution.run: restore execution: %w", err)
	}
	traceEntries, traceCursor := e.machine.traceEntries, e.machine.traceCursor
	var result starlark.Value
	var runErr error
	if hook, ok := e.machine.hooks[e.machine.eip]; ok {
		stop, detail, hookErr := e.machine.invokeTailHook(thread, hook)
		if hookErr != nil {
			runErr = hookErr
		} else if stop != "" {
			result = e.machine.result(stop, 0, detail)
		}
	}
	if result == nil && runErr == nil {
		machineLimit := e.machine.instructionLimit
		if instructionLimit > 0 {
			e.machine.instructionLimit = uint64(instructionLimit)
		}
		result, runErr = e.machine.run(thread)
		e.machine.instructionLimit = machineLimit
	}
	context, captureErr := e.machine.captureContext()
	e.context = context
	restoreErr := e.machine.restoreContext(parent)
	e.machine.traceEntries, e.machine.traceCursor = traceEntries, traceCursor
	if runErr != nil {
		return nil, runErr
	}
	if captureErr != nil {
		return nil, fmt.Errorf("execution.run: capture execution: %w", captureErr)
	}
	if restoreErr != nil {
		return nil, fmt.Errorf("execution.run: restore caller: %w", restoreErr)
	}
	e.result = result
	if record, ok := result.(*starlarkRecord); ok {
		if reason, ok := starlark.AsString(record.Values["reason"]); ok && reason == "return" {
			e.done = true
			delete(e.machine.stackSlots, e.stackSlot)
			delete(e.machine.executions, e)
		}
	}
	return result, nil
}

func (e *emulatorExecution) closeBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("execution.close", args, kwargs); err != nil {
		return nil, err
	}
	if e.frozen || e.machine.frozen {
		return nil, fmt.Errorf("execution.close: execution is frozen")
	}
	if !e.closed {
		delete(e.machine.stackSlots, e.stackSlot)
		delete(e.machine.executions, e)
		e.closed = true
	}
	return starlark.None, nil
}

func (e *emulatorExecution) String() string {
	return fmt.Sprintf("<emulator.execution eip=0x%08x done=%t>", e.context.eip, e.done)
}
func (e *emulatorExecution) Type() string         { return "emulator.execution" }
func (e *emulatorExecution) Freeze()              { e.frozen = true }
func (e *emulatorExecution) Truth() starlark.Bool { return starlark.True }
func (e *emulatorExecution) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", e.Type())
}
func (e *emulatorExecution) AttrNames() []string {
	return []string{"close", "closed", "done", "instruction_limit", "run"}
}
func (e *emulatorExecution) Attr(name string) (starlark.Value, error) {
	switch name {
	case "close":
		return starlark.NewBuiltin("execution.close", e.closeBuiltin), nil
	case "closed":
		return starlark.Bool(e.closed), nil
	case "done":
		return starlark.Bool(e.done), nil
	case "instruction_limit":
		return starlark.MakeUint64(e.machine.instructionLimit), nil
	case "run":
		return starlark.NewBuiltin("execution.run", e.runBuiltin), nil
	default:
		return nil, nil
	}
}

func emulatorRegister(name string) (x86asm.Reg, bool) {
	registers := map[string]x86asm.Reg{"eax": x86asm.EAX, "ebx": x86asm.EBX, "ecx": x86asm.ECX, "edx": x86asm.EDX, "esi": x86asm.ESI, "edi": x86asm.EDI, "esp": x86asm.ESP, "ebp": x86asm.EBP, "eip": x86asm.EIP}
	register, ok := registers[strings.ToLower(name)]
	return register, ok
}

func starlarkRegisterValues(name string, value starlark.Value) (map[x86asm.Reg]uint32, error) {
	output := make(map[x86asm.Reg]uint32)
	if value == starlark.None {
		return output, nil
	}
	mapping, ok := value.(starlark.IterableMapping)
	if !ok {
		return nil, fmt.Errorf("%s: registers must be a mapping", name)
	}
	for _, item := range mapping.Items() {
		registerName, ok := starlark.AsString(item[0])
		register, known := emulatorRegister(registerName)
		integer, integerOK := item[1].(starlark.Int)
		number, numberOK := integer.Uint64()
		if !ok || !known || register == x86asm.EIP || !integerOK || !numberOK || number > math.MaxUint32 {
			return nil, fmt.Errorf("%s: invalid initial register %s", name, item[0])
		}
		output[register] = uint32(number)
	}
	return output, nil
}

func (c *emulatorCheckpoint) capture(value starlark.Value, seenDicts map[*starlark.Dict]bool, seenLists map[*starlark.List]bool, seenSets map[*starlark.Set]bool, seenRecords map[*starlarkRecord]bool, seenExecutions map[*emulatorExecution]bool) {
	if value == nil {
		return
	}
	switch value := value.(type) {
	case *starlark.Dict:
		if seenDicts[value] {
			return
		}
		seenDicts[value] = true
		items := value.Items()
		c.dicts = append(c.dicts, emulatorCheckpointDict{value: value, items: items})
		for _, item := range items {
			c.capture(item[0], seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
			c.capture(item[1], seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
		}
	case *starlark.List:
		if seenLists[value] {
			return
		}
		seenLists[value] = true
		items := make([]starlark.Value, value.Len())
		for index := range items {
			items[index] = value.Index(index)
		}
		c.lists = append(c.lists, emulatorCheckpointList{value: value, items: items})
		for _, item := range items {
			c.capture(item, seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
		}
	case *starlark.Set:
		if seenSets[value] {
			return
		}
		seenSets[value] = true
		items := make([]starlark.Value, 0, value.Len())
		iterator := value.Iterate()
		var item starlark.Value
		for iterator.Next(&item) {
			items = append(items, item)
		}
		iterator.Done()
		c.sets = append(c.sets, emulatorCheckpointSet{value: value, items: items})
		for _, item := range items {
			c.capture(item, seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
		}
	case starlark.Tuple:
		for _, item := range value {
			c.capture(item, seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
		}
	case *starlarkRecord:
		if seenRecords[value] {
			return
		}
		seenRecords[value] = true
		for _, item := range value.Values {
			c.capture(item, seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
		}
	case *emulatorExecution:
		if seenExecutions[value] {
			return
		}
		seenExecutions[value] = true
		snapshot := *value
		snapshot.context.callFrames = append([]emulatorCallFrame(nil), value.context.callFrames...)
		c.executions = append(c.executions, emulatorCheckpointExecution{value: value, snapshot: snapshot})
		c.capture(value.result, seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
	}
}

func (c *emulatorCheckpoint) restoreState(machine *emulatorX86) error {
	for _, saved := range c.dicts {
		if err := saved.value.Clear(); err != nil {
			// Frozen values are immutable configuration reachable from a
			// plugin's mutable state. They cannot have changed since capture,
			// so preserving them is already an exact restore.
			if strings.Contains(err.Error(), "frozen") {
				continue
			}
			return fmt.Errorf("restore checkpoint dict: %w", err)
		}
		for _, item := range saved.items {
			if err := saved.value.SetKey(item[0], item[1]); err != nil {
				return fmt.Errorf("restore checkpoint dict item: %w", err)
			}
		}
	}
	for _, saved := range c.lists {
		if err := saved.value.Clear(); err != nil {
			if strings.Contains(err.Error(), "frozen") {
				continue
			}
			return fmt.Errorf("restore checkpoint list: %w", err)
		}
		for _, item := range saved.items {
			if err := saved.value.Append(item); err != nil {
				return fmt.Errorf("restore checkpoint list item: %w", err)
			}
		}
	}
	for _, saved := range c.sets {
		if err := saved.value.Clear(); err != nil {
			if strings.Contains(err.Error(), "frozen") {
				continue
			}
			return fmt.Errorf("restore checkpoint set: %w", err)
		}
		for _, item := range saved.items {
			if err := saved.value.Insert(item); err != nil {
				return fmt.Errorf("restore checkpoint set item: %w", err)
			}
		}
	}
	for _, saved := range c.executions {
		restored := saved.snapshot
		restored.machine = machine
		restored.context.callFrames = append([]emulatorCallFrame(nil), saved.snapshot.context.callFrames...)
		*saved.value = restored
		if !restored.done && !restored.closed {
			machine.executions[saved.value] = true
		}
	}
	return nil
}

func (m *emulatorX86) checkpointBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("checkpoint", args, kwargs); err != nil {
		return nil, err
	}
	if m.frozen || m.hookDepth != 0 || m.invokeDepth != 0 {
		return nil, fmt.Errorf("checkpoint: machine must be mutable and between calls")
	}
	checkpoint := &emulatorCheckpoint{owner: m, machine: m.clone()}
	seenDicts := make(map[*starlark.Dict]bool)
	seenLists := make(map[*starlark.List]bool)
	seenSets := make(map[*starlark.Set]bool)
	seenRecords := make(map[*starlarkRecord]bool)
	seenExecutions := make(map[*emulatorExecution]bool)
	for _, state := range m.pluginStates {
		checkpoint.capture(state, seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
	}
	for execution := range m.executions {
		checkpoint.capture(execution, seenDicts, seenLists, seenSets, seenRecords, seenExecutions)
	}
	return checkpoint, nil
}

func (m *emulatorX86) restoreBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var checkpoint *emulatorCheckpoint
	if err := starlark.UnpackArgs("restore", args, kwargs, "checkpoint", &checkpoint); err != nil {
		return nil, err
	}
	if checkpoint.owner != m {
		return nil, fmt.Errorf("restore: checkpoint belongs to a different machine")
	}
	if m.frozen || m.hookDepth != 0 || m.invokeDepth != 0 {
		return nil, fmt.Errorf("restore: machine must be mutable and between calls")
	}
	restored := checkpoint.machine.clone()
	*m = *restored
	if err := checkpoint.restoreState(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *emulatorX86) snapshotBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("snapshot", args, kwargs); err != nil {
		return nil, err
	}
	return m.clone(), nil
}

func (m *emulatorX86) clone() *emulatorX86 {
	clone := *m
	clone.mappingCache = [2]int{-1, -1}
	clone.exports = make(map[string]uint32, len(m.exports))
	for name, address := range m.exports {
		clone.exports[name] = address
	}
	clone.imports = make(map[uint32]emulatorImport, len(m.imports))
	for address, imported := range m.imports {
		clone.imports[address] = imported
	}
	clone.importsByName = make(map[emulatorImportNameKey][]uint32, len(m.importsByName))
	for key, addresses := range m.importsByName {
		clone.importsByName[key] = append([]uint32(nil), addresses...)
	}
	clone.importsByOrdinal = make(map[emulatorImportOrdinalKey][]uint32, len(m.importsByOrdinal))
	for key, addresses := range m.importsByOrdinal {
		clone.importsByOrdinal[key] = append([]uint32(nil), addresses...)
	}
	clone.importValuesCache = nil
	clone.moduleValuesCache = nil
	clone.attrCache = make(starlark.StringDict)
	clone.cachedCodePages = make(map[uint32]bool, len(m.cachedCodePages))
	for page := range m.cachedCodePages {
		clone.cachedCodePages[page] = true
	}
	// Decoded instructions are derived state and can dominate snapshots after
	// long-running protected-code workloads. Preserve accelerator decisions,
	// but let the clone repopulate its bounded instruction cache lazily.
	clone.decoded = make(map[uint32]*x86asm.Inst)
	clone.decodedEntries = nil
	clone.decodedCursor = 0
	clone.decodedPages = make(map[uint32]*emulatorDecodedPage, len(m.decodedPages))
	clone.decodedPage = nil
	for pageNumber, page := range m.decodedPages {
		copyPage := *page
		copyPage.instructions = [4096]*x86asm.Inst{}
		clone.decodedPages[pageNumber] = &copyPage
	}
	clone.mappings = make([]emulatorMapping, len(m.mappings))
	for i, mapping := range m.mappings {
		clone.mappings[i] = mapping
		clone.mappings[i].data = bytes.Clone(mapping.data)
	}
	clone.allocations = make(map[uint32]bool, len(m.allocations))
	for address, live := range m.allocations {
		clone.allocations[address] = live
	}
	clone.freeAllocations = append([]emulatorFreeRange(nil), m.freeAllocations...)
	clone.protections = append([]emulatorMemoryProtection(nil), m.protections...)
	clone.hooks = make(map[uint32]emulatorHook, len(m.hooks))
	for key, value := range m.hooks {
		clone.hooks[key] = value
	}
	clone.hookRules = append([]emulatorHookRule(nil), m.hookRules...)
	clone.crcLoops = make(map[uint32]*emulatorCRC32Loop, len(m.crcLoops))
	for address, loop := range m.crcLoops {
		copyLoop := *loop
		clone.crcLoops[address] = &copyLoop
	}
	clone.crcLoopsChecked = make(map[uint32]bool, len(m.crcLoopsChecked))
	for address, checked := range m.crcLoopsChecked {
		clone.crcLoopsChecked[address] = checked
	}
	clone.loopAccelerations = make(map[uint32]emulatorLoopAcceleration, len(m.loopAccelerations))
	for address, loop := range m.loopAccelerations {
		loop.pattern = bytes.Clone(loop.pattern)
		clone.loopAccelerations[address] = loop
	}
	clone.regionAccelerations = make(map[uint32]emulatorRegionAcceleration, len(m.regionAccelerations))
	for entry, region := range m.regionAccelerations {
		clone.regionAccelerations[entry] = region
	}
	clone.runtimeRegions = make(map[uint32]emulatorRegionAcceleration, len(m.runtimeRegions))
	for entry, region := range m.runtimeRegions {
		clone.runtimeRegions[entry] = region
	}
	clone.rewrites = make(map[uint32]emulatorRewrite, len(m.rewrites))
	for address, rewrite := range m.rewrites {
		rewrite.pattern = bytes.Clone(rewrite.pattern)
		clone.rewrites[address] = rewrite
	}
	clone.transformations = make([]emulatorTransformation, len(m.transformations))
	for index, transformation := range m.transformations {
		transformation.anchor = bytes.Clone(transformation.anchor)
		transformation.anchorMask = bytes.Clone(transformation.anchorMask)
		clone.transformations[index] = transformation
	}
	clone.transformationCache = make(map[uint32]emulatorTransformationMatch, len(m.transformationCache))
	for address, match := range m.transformationCache {
		clone.transformationCache[address] = match
	}
	clone.wideCompare = make(map[uint32]bool, len(m.wideCompare))
	for address, recognized := range m.wideCompare {
		clone.wideCompare[address] = recognized
	}
	clone.wideCompareChecked = make(map[uint32]bool, len(m.wideCompareChecked))
	for address, checked := range m.wideCompareChecked {
		clone.wideCompareChecked[address] = checked
	}
	clone.asciiLower = make(map[uint32]bool, len(m.asciiLower))
	for address, recognized := range m.asciiLower {
		clone.asciiLower[address] = recognized
	}
	clone.asciiLowerChecked = make(map[uint32]bool, len(m.asciiLowerChecked))
	for address, checked := range m.asciiLowerChecked {
		clone.asciiLowerChecked[address] = checked
	}
	clone.mixedCompare = make(map[uint32]bool, len(m.mixedCompare))
	for address, recognized := range m.mixedCompare {
		clone.mixedCompare[address] = recognized
	}
	clone.mixedCompareChecked = make(map[uint32]bool, len(m.mixedCompareChecked))
	for address, checked := range m.mixedCompareChecked {
		clone.mixedCompareChecked[address] = checked
	}
	clone.zeroByteScan = make(map[uint32]bool, len(m.zeroByteScan))
	for address, recognized := range m.zeroByteScan {
		clone.zeroByteScan[address] = recognized
	}
	clone.zeroByteScanChecked = make(map[uint32]bool, len(m.zeroByteScanChecked))
	for address, checked := range m.zeroByteScanChecked {
		clone.zeroByteScanChecked[address] = checked
	}
	clone.profileCounts = make(map[uint32]uint64, len(m.profileCounts))
	for address, count := range m.profileCounts {
		clone.profileCounts[address] = count
	}
	clone.memoryWatches = make(map[uint64]*emulatorMemoryWatch, len(m.memoryWatches))
	for id, watch := range m.memoryWatches {
		copyWatch := *watch
		copyWatch.entries = make([]emulatorMemoryWrite, len(watch.entries))
		for index, entry := range watch.entries {
			copyWatch.entries[index] = entry
			copyWatch.entries[index].before = bytes.Clone(entry.before)
			copyWatch.entries[index].after = bytes.Clone(entry.after)
		}
		clone.memoryWatches[id] = &copyWatch
	}
	clone.codeWatches = make(map[uint64]*emulatorCodeWatch, len(m.codeWatches))
	for id, watch := range m.codeWatches {
		copyWatch := *watch
		copyWatch.entries = make([]emulatorCodeEntry, len(watch.entries))
		for index, entry := range watch.entries {
			copyWatch.entries[index] = entry
			copyWatch.entries[index].stack = bytes.Clone(entry.stack)
			copyWatch.entries[index].captures = make(map[string][]byte, len(entry.captures))
			for name, data := range entry.captures {
				copyWatch.entries[index].captures[name] = bytes.Clone(data)
			}
		}
		clone.codeWatches[id] = &copyWatch
	}
	clone.modules = make(map[string]*emulatorModule, len(m.modules))
	for name, module := range m.modules {
		copyModule := *module
		copyModule.exports = make(map[string]emulatorModuleExport, len(module.exports))
		for exportName, export := range module.exports {
			copyModule.exports[exportName] = export
		}
		copyModule.ordinals = make(map[uint32]emulatorModuleExport, len(module.ordinals))
		for ordinal, export := range module.ordinals {
			copyModule.ordinals[ordinal] = export
		}
		clone.modules[name] = &copyModule
	}
	clone.stackSlots = make(map[int]bool, len(m.stackSlots))
	for slot, used := range m.stackSlots {
		clone.stackSlots[slot] = used
	}
	clone.invokeStackSlots = append([]int(nil), m.invokeStackSlots...)
	clone.executions = make(map[*emulatorExecution]bool)
	clone.pluginStates = append([]starlark.Value(nil), m.pluginStates...)
	clone.traceEntries = nil
	clone.callTraceEntries = nil
	clone.callTraceCursor = 0
	clone.callTraceDropped = 0
	clone.callFrames = append([]emulatorCallFrame(nil), m.callFrames...)
	clone.traceCursor = 0
	clone.frozen = false
	return &clone
}

func (m *emulatorX86) profileBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	limit := 256
	reset := false
	if err := starlark.UnpackArgs("profile", args, kwargs, "limit?", &limit, "reset?", &reset); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 65536 {
		return nil, fmt.Errorf("profile: limit must be between 1 and 65536")
	}
	type profileEntry struct {
		address uint32
		count   uint64
	}
	ordered := make([]profileEntry, 0, len(m.profileCounts))
	for address, count := range m.profileCounts {
		ordered = append(ordered, profileEntry{address: address, count: count})
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].count != ordered[j].count {
			return ordered[i].count > ordered[j].count
		}
		return ordered[i].address < ordered[j].address
	})
	if len(ordered) > limit {
		ordered = ordered[:limit]
	}
	entries := make([]starlark.Value, len(ordered))
	for index, item := range ordered {
		mappingName := ""
		offset := uint32(0)
		for _, mapping := range m.mappings {
			if item.address >= mapping.start && uint64(item.address) < uint64(mapping.start)+uint64(len(mapping.data)) {
				mappingName = mapping.name
				offset = item.address - mapping.start
				break
			}
		}
		entries[index] = newStarlarkRecord(map[string]starlark.Value{
			"address": starlark.MakeUint64(uint64(item.address)),
			"count":   starlark.MakeUint64(item.count),
			"mapping": starlark.String(mappingName),
			"offset":  starlark.MakeUint64(uint64(offset)),
		})
	}
	result := newStarlarkRecord(map[string]starlark.Value{
		"enabled":    starlark.Bool(m.profile),
		"operations": starlark.MakeUint64(m.profileOperations),
		"interval":   starlark.MakeUint64(m.profileInterval),
		"samples":    starlark.MakeUint64(m.profileSamples),
		"dropped":    starlark.MakeUint64(m.profileDropped),
		"tracked":    starlark.MakeInt(len(m.profileCounts)),
		"entries":    starlark.NewList(entries),
	})
	if reset {
		clear(m.profileCounts)
		m.profileOperations = 0
		m.profileSamples = 0
		m.profileDropped = 0
	}
	return result, nil
}

func (m *emulatorX86) result(reason string, steps uint64, detail string) starlark.Value {
	trace := append([]starlark.Value(nil), m.traceEntries...)
	if len(trace) == m.traceLimit && m.traceCursor != 0 {
		trace = append(trace[m.traceCursor:], trace[:m.traceCursor]...)
	}
	recent := make([]starlark.Value, m.recentEIPCount)
	start := m.recentEIPCursor - m.recentEIPCount
	if start < 0 {
		start += len(m.recentEIPs)
	}
	for index := range recent {
		recent[index] = starlark.MakeUint64(uint64(m.recentEIPs[(start+index)%len(m.recentEIPs)]))
	}
	firstCall := len(m.callFrames) - 32
	if firstCall < 0 {
		firstCall = 0
	}
	calls := make([]starlark.Value, len(m.callFrames)-firstCall)
	for index, frame := range m.callFrames[firstCall:] {
		calls[index] = newStarlarkRecord(map[string]starlark.Value{
			"site":   starlark.MakeUint64(uint64(frame.site)),
			"target": starlark.MakeUint64(uint64(frame.target)),
		})
	}
	registers := starlark.StringDict{}
	for name, register := range map[string]x86asm.Reg{
		"eax": x86asm.EAX, "ebx": x86asm.EBX, "ecx": x86asm.ECX, "edx": x86asm.EDX,
		"esi": x86asm.ESI, "edi": x86asm.EDI, "ebp": x86asm.EBP, "esp": x86asm.ESP,
	} {
		registers[name] = starlark.MakeUint64(uint64(m.registers[register]))
	}
	return newStarlarkRecord(map[string]starlark.Value{
		"reason": starlark.String(reason), "steps": starlark.MakeUint64(steps),
		"eip": starlark.MakeUint64(uint64(m.eip)), "value": starlark.MakeUint64(uint64(m.registers[x86asm.EAX])),
		"detail": starlark.String(detail), "trace": starlark.NewList(trace), "recent": starlark.NewList(recent),
		"calls": starlark.NewList(calls), "call_trace": m.callTraceValue(false), "registers": newStarlarkRecord(registers),
	})
}

func starlarkUint32Values(name string, value starlark.Value) ([]uint32, error) {
	if value == starlark.None {
		return nil, nil
	}
	iterable, ok := value.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("%s: args must be iterable", name)
	}
	iterator := iterable.Iterate()
	defer iterator.Done()
	var item starlark.Value
	var out []uint32
	for iterator.Next(&item) {
		integer, ok := item.(starlark.Int)
		if !ok {
			return nil, fmt.Errorf("%s: argument is %s, want int", name, item.Type())
		}
		number, ok := integer.Uint64()
		if !ok || number > math.MaxUint32 {
			return nil, fmt.Errorf("%s: argument does not fit uint32", name)
		}
		out = append(out, uint32(number))
	}
	return out, nil
}
