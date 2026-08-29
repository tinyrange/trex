package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/tinyrange/trex/storage"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"strings"
	"testing"

	"go.starlark.net/starlark"
)

func TestRegistryHiveReadsSegmentedLargeValues(t *testing.T) {
	data := make([]byte, hiveBaseBlockSize+0x80)
	putCell := func(offset uint32, body []byte) {
		start := hiveBaseBlockSize + int(offset)
		binary.LittleEndian.PutUint32(data[start:start+4], uint32(-int32(len(body)+4)))
		copy(data[start+4:], body)
	}
	descriptor := make([]byte, 8)
	copy(descriptor[:2], "db")
	binary.LittleEndian.PutUint16(descriptor[2:4], 2)
	binary.LittleEndian.PutUint32(descriptor[4:8], 0x20)
	list := make([]byte, 8)
	binary.LittleEndian.PutUint32(list[0:4], 0x40)
	binary.LittleEndian.PutUint32(list[4:8], 0x60)
	putCell(0, descriptor)
	putCell(0x20, list)
	putCell(0x40, []byte("abcd"))
	putCell(0x60, []byte("efghi"))
	hive := &registryHive{file: testHiveFile(data)}
	got, err := hive.readValueData(9, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("abcdefghi")) {
		t.Fatalf("large value = %q", got)
	}
}

func TestBuildRegistryHiveKeyValueMetadata(t *testing.T) {
	root := newRegistryTree("SOFTWARE")
	key := "/Microsoft/Windows NT/CurrentVersion/Drivers32"
	setRegistryValue(root, key, "midimapper", registryString(regSZ, "midimap.dll"))
	setRegistryValue(root, key, "wavemapper", registryString(regSZ, "msacm32.drv"))
	setRegistryValue(root, key, "midi", registryString(regSZ, "beepmidi.dll"))
	setRegistryValue(root, key, "msacm.msgsm610", registryString(regSZ, "msgsm32.acm"))

	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := binary.LittleEndian.Uint32(data[0x24:0x28]), uint32(0x20); got != want {
		t.Fatalf("root cell = %#x, want conventional first cell %#x", got, want)
	}
	hive := &registryHive{
		file:     testHiveFile(data),
		rootCell: binary.LittleEndian.Uint32(data[0x24:0x28]),
	}
	drivers, err := hive.lookup(key)
	if err != nil {
		t.Fatal(err)
	}
	body, err := hive.readCell(drivers.cell)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := binary.LittleEndian.Uint32(body[0x30:0x34]), uint32(0xffffffff); got != want {
		t.Fatalf("class cell = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(body[0x20:0x24]), uint32(0xffffffff); got != want {
		t.Fatalf("volatile subkey list = %#x, want %#x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(body[0x3c:0x40]), uint32(28); got != want {
		t.Fatalf("max value name length = %d, want %d", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(body[0x40:0x44]), uint32(26); got != want {
		t.Fatalf("max value data length = %d, want %d", got, want)
	}
}

func TestBuildRegistryHiveInheritsWindows2000Format(t *testing.T) {
	root := newRegistryTree("SYSTEM")
	ensureRegistryKey(root, "/ControlSet001")
	data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: 3})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data[0x18:0x1c]); got != 3 {
		t.Fatalf("minor version = %d, want 3", got)
	}
	hive := &registryHive{file: testHiveFile(data), rootCell: binary.LittleEndian.Uint32(data[0x24:0x28])}
	rootKey, err := hive.readKey(hive.rootCell)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := hive.readCell(rootKey.subkeyList)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(leaf[:2]); got != "lf" {
		t.Fatalf("leaf signature = %q, want lf", got)
	}
	if got := string(leaf[8:12]); got != "CONT" {
		t.Fatalf("fast-leaf hint = %q, want CONT", got)
	}
}

func TestBuildRegistryHiveSupportsNT351Format(t *testing.T) {
	root := newRegistryTree("SYSTEM")
	ensureRegistryKey(root, "/ControlSet001/Services/Atdisk")
	data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data[0x18:0x1c]); got != 2 {
		t.Fatalf("minor version = %d, want 2", got)
	}
	hive := &registryHive{file: testHiveFile(data), rootCell: binary.LittleEndian.Uint32(data[0x24:0x28])}
	rootKey, err := hive.readKey(hive.rootCell)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := hive.readCell(rootKey.subkeyList)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(leaf[:2]); got != "li" {
		t.Fatalf("leaf signature = %q, want li", got)
	}
	if got, want := len(leaf), 12; got != want {
		t.Fatalf("leaf size = %d, want %d-byte aligned li cell", got, want)
	}
}

func TestBuildRegistryHiveUsesBoundedBins(t *testing.T) {
	root := newRegistryTree("SYSTEM")
	for i := 0; i < 300; i++ {
		setRegistryValue(root, fmt.Sprintf("/ControlSet001/Services/Driver%03d", i), "Start", registryDWORD(0))
	}
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	bins := 0
	for offset := hiveBaseBlockSize; offset < len(data); {
		if offset+0x20 > len(data) || string(data[offset:offset+4]) != "hbin" {
			t.Fatalf("missing hbin at %#x", offset)
		}
		size := int(binary.LittleEndian.Uint32(data[offset+8 : offset+12]))
		if size < hiveBaseBlockSize || size%hiveBaseBlockSize != 0 || offset+size > len(data) {
			t.Fatalf("invalid hbin size %#x at %#x", size, offset)
		}
		if size != hiveBaseBlockSize {
			t.Fatalf("ordinary hbin size = %#x, want %#x", size, hiveBaseBlockSize)
		}
		bins++
		offset += size
	}
	if bins < 2 {
		t.Fatalf("generated %d bins, want multiple bins", bins)
	}
	hive := &registryHive{file: testHiveFile(data), rootCell: binary.LittleEndian.Uint32(data[0x24:0x28])}
	if _, err := hive.lookup("/ControlSet001/Services/Driver299"); err != nil {
		t.Fatalf("lookup in later bin: %v", err)
	}
}

func TestBuildRegistryHiveSplitsAndAlignsLargeSubkeyIndexes(t *testing.T) {
	root := newRegistryTree("SYSTEM")
	for i := 0; i < 1600; i++ {
		ensureRegistryKey(root, fmt.Sprintf("/ControlSet001/Services/Driver%04d", i))
	}
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	hive := &registryHive{file: testHiveFile(data), rootCell: binary.LittleEndian.Uint32(data[0x24:0x28])}
	services, err := hive.lookup("/ControlSet001/Services")
	if err != nil {
		t.Fatal(err)
	}
	index, err := hive.readCell(services.subkeyList)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(index[:2]), "ri"; got != want {
		t.Fatalf("Services index signature = %q, want %q", got, want)
	}
	leafCount := int(binary.LittleEndian.Uint16(index[2:4]))
	if leafCount < 2 {
		t.Fatalf("Services root index has %d leaf, want multiple leaves", leafCount)
	}
	previousName := ""
	for i := 0; i < leafCount; i++ {
		cell := binary.LittleEndian.Uint32(index[4+i*4 : 8+i*4])
		leaf, err := hive.readCell(cell)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := string(leaf[:2]), "lh"; got != want {
			t.Fatalf("leaf %d signature = %q, want %q", i, got, want)
		}
		count := binary.LittleEndian.Uint16(leaf[2:4])
		if count > registrySubkeyLeafEntries {
			t.Fatalf("leaf %d contains %d entries, want at most %d", i, count, registrySubkeyLeafEntries)
		}
		size := len(leaf) + 4
		if cell/hiveBaseBlockSize != (cell+uint32(size)-1)/hiveBaseBlockSize {
			t.Fatalf("leaf %d at %#x size %#x crosses a hive bin", i, cell, size)
		}
		for entry := 0; entry < int(count); entry++ {
			childCell := binary.LittleEndian.Uint32(leaf[4+entry*8 : 8+entry*8])
			child, err := hive.readKey(childCell)
			if err != nil {
				t.Fatal(err)
			}
			name := strings.ToUpper(child.name)
			if previousName != "" && name <= previousName {
				t.Fatalf("leaf %d entry %d name %q does not follow %q", i, entry, child.name, previousName)
			}
			previousName = name
		}
	}
	if got, want := len(hiveMustReadSubkeys(t, hive, services)), 1600; got != want {
		t.Fatalf("Services children = %d, want %d", got, want)
	}
}

func TestBuildRegistryHiveBoundsWindows2000FastLeaves(t *testing.T) {
	root := newRegistryTree("SOFTWARE")
	for i := 0; i < 600; i++ {
		ensureRegistryKey(root, fmt.Sprintf("/Classes/Component%04d", i))
	}
	data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: 3})
	if err != nil {
		t.Fatal(err)
	}
	hive := &registryHive{file: testHiveFile(data), rootCell: binary.LittleEndian.Uint32(data[0x24:0x28])}
	classes, err := hive.lookup("/Classes")
	if err != nil {
		t.Fatal(err)
	}
	index, err := hive.readCell(classes.subkeyList)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(index[:2]); got != "ri" {
		t.Fatalf("Classes index signature = %q, want ri", got)
	}
	leafCount := int(binary.LittleEndian.Uint16(index[2:4]))
	for i := 0; i < leafCount; i++ {
		cell := binary.LittleEndian.Uint32(index[4+i*4 : 8+i*4])
		leaf, err := hive.readCell(cell)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(leaf[:2]); got != "lf" {
			t.Fatalf("leaf %d signature = %q, want lf", i, got)
		}
		if count := int(binary.LittleEndian.Uint16(leaf[2:4])); count > registrySubkeyLeafEntries {
			t.Fatalf("leaf %d contains %d entries, want at most %d", i, count, registrySubkeyLeafEntries)
		}
		size := len(leaf) + 4
		if cell/hiveBaseBlockSize != (cell+uint32(size)-1)/hiveBaseBlockSize {
			t.Fatalf("leaf %d at %#x size %#x crosses a hive bin", i, cell, size)
		}
	}
	if got := len(hiveMustReadSubkeys(t, hive, classes)); got != 600 {
		t.Fatalf("Classes has %d subkeys, want 600", got)
	}
}

func TestGeneratedHiveVersionSupportsHashLeaves(t *testing.T) {
	data, err := buildRegistryHive(newRegistryTree("SOFTWARE"))
	if err != nil {
		t.Fatal(err)
	}
	if major, minor := binary.LittleEndian.Uint32(data[20:24]), binary.LittleEndian.Uint32(data[24:28]); major != 1 || minor != 5 {
		t.Fatalf("hive version = %d.%d, want 1.5", major, minor)
	}
}

func hiveMustReadSubkeys(t *testing.T, hive *registryHive, key hiveKey) []hiveKey {
	t.Helper()
	children, err := hive.readSubkeys(key)
	if err != nil {
		t.Fatal(err)
	}
	return children
}

func TestRegistryNameHash(t *testing.T) {
	if got, want := registryNameHash("ControlSet001"), registryNameHash("controlset001"); got != want {
		t.Fatalf("hash is case-sensitive: %#x != %#x", got, want)
	}
	var want uint32
	for _, r := range "TEST" {
		want = want*37 + uint32(r)
	}
	if got := registryNameHash("Test"); got != want {
		t.Fatalf("hash = %#x, want %#x", got, want)
	}
}

func TestSetRegistryValueReplacesNamesCaseInsensitively(t *testing.T) {
	root := newRegistryTree("SOFTWARE")
	setRegistryValue(root, "/Microsoft/Windows NT/CurrentVersion/Winlogon", "Shell", registryString(regSZ, "first.exe"))
	setRegistryValue(root, "/Microsoft/Windows NT/CurrentVersion/Winlogon", "shell", registryString(regSZ, "Explorer.exe"))
	key := ensureRegistryKey(root, "/Microsoft/Windows NT/CurrentVersion/Winlogon")
	if len(key.values) != 1 {
		t.Fatalf("Winlogon values = %#v, want one case-insensitive Shell value", key.values)
	}
	value, ok := key.values["shell"]
	if !ok || decodeUTF16LE(value.data) != "Explorer.exe\x00" {
		t.Fatalf("shell value = %#v, want Explorer.exe", value)
	}
}

func TestSetRegistryValueIfAbsentPreservesExistingValue(t *testing.T) {
	root := newRegistryTree("SOFTWARE")
	keyPath := "/Classes/Interface/{00000000-0000-0000-0000-000000000000}"
	setRegistryValue(root, keyPath, "ProxyStubClsid32", registryString(regSZ, "custom-proxy"))
	setRegistryValueIfAbsent(root, keyPath, "proxystubclsid32", registryString(regSZ, "derived-proxy"))
	key := ensureRegistryKey(root, keyPath)
	if got, want := len(key.values), 1; got != want {
		t.Fatalf("value count = %d, want %d", got, want)
	}
	for _, value := range key.values {
		if got, want := string(value.data), string(registryString(regSZ, "custom-proxy").data); got != want {
			t.Fatalf("value data = %q, want %q", got, want)
		}
	}
}

func TestApplyRegistryValueHonorsINFBehaviorFlags(t *testing.T) {
	root := newRegistryTree("SOFTWARE")
	keyPath := "/Microsoft/Windows NT/CurrentVersion/Svchost"
	if err := applyRegistryValue(root, keyPath, "netsvcs", registryMultiString([]string{"BITS"}), 0); err != nil {
		t.Fatal(err)
	}
	if err := applyRegistryValue(root, keyPath, "netsvcs", registryMultiString([]string{"CryptSvc", "BITS", "EventSystem"}), infAddRegAppend); err != nil {
		t.Fatal(err)
	}
	key := ensureRegistryKey(root, keyPath)
	_, value, found := registryTreeValue(key, "NETSVCS")
	if !found {
		t.Fatal("appended value is missing")
	}
	if got, want := strings.Join(registryMultiStringValues(value), ","), "BITS,CryptSvc,EventSystem"; got != want {
		t.Fatalf("appended MULTI_SZ = %q, want %q", got, want)
	}

	if err := applyRegistryValue(root, keyPath, "mode", registryString(regSZ, "first"), infAddRegNoClobber); err != nil {
		t.Fatal(err)
	}
	if err := applyRegistryValue(root, keyPath, "MODE", registryString(regSZ, "second"), infAddRegNoClobber); err != nil {
		t.Fatal(err)
	}
	_, value, _ = registryTreeValue(key, "mode")
	if got := strings.TrimRight(decodeUTF16LE(value.data), "\x00"); got != "first" {
		t.Fatalf("NOCLOBBER value = %q, want first", got)
	}
	if err := applyRegistryValue(root, keyPath, "missing", registryString(regSZ, "ignored"), infAddRegOverwriteOnly); err != nil {
		t.Fatal(err)
	}
	if _, _, found := registryTreeValue(key, "missing"); found {
		t.Fatal("OVERWRITEONLY created a missing value")
	}
	if err := applyRegistryValue(root, keyPath, "mode", registryString(regSZ, "updated"), infAddRegOverwriteOnly); err != nil {
		t.Fatal(err)
	}
	if err := applyRegistryValue(root, keyPath, "mode", registryData{}, infAddRegDeleteValue); err != nil {
		t.Fatal(err)
	}
	if _, _, found := registryTreeValue(key, "mode"); found {
		t.Fatal("DELVAL left the value present")
	}
}

func TestMutableHiveAppliesMultiStringAppend(t *testing.T) {
	root := newRegistryTree("SOFTWARE")
	keyPath := "/Microsoft/Windows NT/CurrentVersion/Svchost"
	setRegistryValue(root, keyPath, "netsvcs", registryMultiString([]string{"BITS"}))
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	hive := &mutableHive{data: data}
	if err := hive.applyValue(keyPath, "netsvcs", registryMultiString([]string{"CryptSvc", "BITS"}), infAddRegAppend); err != nil {
		t.Fatal(err)
	}
	value, err := hive.readValue(keyPath, "netsvcs")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(registryMultiStringValues(value), ","), "BITS,CryptSvc"; got != want {
		t.Fatalf("patched MULTI_SZ = %q, want %q", got, want)
	}
}

func TestMutableHiveSortsInsertedSubkeys(t *testing.T) {
	root := newRegistryTree("DEFAULT")
	const explorer = "/Software/Microsoft/Windows/CurrentVersion/Explorer"
	ensureRegistryKey(root, explorer+"/Advanced")
	ensureRegistryKey(root, explorer+"/User Shell Folders")
	data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: 3})
	if err != nil {
		t.Fatal(err)
	}
	hive := &mutableHive{data: data}
	if _, err := hive.ensureKey(explorer + "/Shell Folders"); err != nil {
		t.Fatal(err)
	}
	parentCell, err := hive.lookupKey(explorer)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := hive.cellBody(parentCell)
	if err != nil {
		t.Fatal(err)
	}
	listCell := binary.LittleEndian.Uint32(parent[0x1c:0x20])
	list, err := hive.cellBody(listCell)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(list[:2]); got != "li" {
		t.Fatalf("replacement list signature = %q, want li", got)
	}
	cells, err := hive.subkeyCells(listCell)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(cells))
	for i, cell := range cells {
		names[i], err = hive.subkeyName(cell)
		if err != nil {
			t.Fatal(err)
		}
	}
	if got, want := strings.Join(names, ","), "Advanced,Shell Folders,User Shell Folders"; got != want {
		t.Fatalf("replacement subkeys = %q, want %q", got, want)
	}
}

func TestMutableHiveSplitsLargeInsertedSubkeyIndexes(t *testing.T) {
	root := newRegistryTree("SOFTWARE")
	for i := 0; i < registrySubkeyIndexEntries+1; i++ {
		ensureRegistryKey(root, fmt.Sprintf("/Classes/Component%04d", i))
	}
	data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: 3})
	if err != nil {
		t.Fatal(err)
	}
	hive := &mutableHive{data: data}
	if _, err := hive.ensureKey("/Classes/Added"); err != nil {
		t.Fatal(err)
	}
	classesCell, err := hive.lookupKey("/Classes")
	if err != nil {
		t.Fatal(err)
	}
	classes, err := hive.cellBody(classesCell)
	if err != nil {
		t.Fatal(err)
	}
	listCell := binary.LittleEndian.Uint32(classes[0x1c:0x20])
	index, err := hive.cellBody(listCell)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(index[:2]); got != "ri" {
		t.Fatalf("replacement index signature = %q, want ri", got)
	}
	leafCount := int(binary.LittleEndian.Uint16(index[2:4]))
	for i := 0; i < leafCount; i++ {
		cell := binary.LittleEndian.Uint32(index[4+i*4 : 8+i*4])
		leaf, err := hive.cellBody(cell)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(leaf[:2]); got != "li" {
			t.Fatalf("replacement leaf %d signature = %q, want li", i, got)
		}
		if count := int(binary.LittleEndian.Uint16(leaf[2:4])); count > registrySubkeyIndexEntries {
			t.Fatalf("replacement leaf %d contains %d entries, want at most %d", i, count, registrySubkeyIndexEntries)
		}
	}
	cells, err := hive.subkeyCells(listCell)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(cells), registrySubkeyIndexEntries+2; got != want {
		t.Fatalf("replacement index has %d subkeys, want %d", got, want)
	}
}

func TestMapINFRegistryPathNormalizesCurrentControlSetCaseInsensitively(t *testing.T) {
	for _, input := range []string{
		`SYSTEM\CurrentControlSet\Services\Example`,
		`system\currentcontrolset\services\Example`,
	} {
		hive, key := mapINFRegistryPath("HKLM", input)
		if hive != "SYSTEM" || key != "/ControlSet001/Services/Example" && key != "/ControlSet001/services/Example" {
			t.Fatalf("mapINFRegistryPath(%q) = %q, %q", input, hive, key)
		}
		if strings.Contains(strings.ToLower(key), "currentcontrolset") {
			t.Fatalf("mapINFRegistryPath(%q) retained CurrentControlSet: %q", input, key)
		}
	}
}

func TestRegistryDataFromINFSeparatesTypeAndBehaviorFlags(t *testing.T) {
	multi := registryDataFromINF(0x00010002, nil)
	if multi.typ != regMultiSZ || len(multi.data) != 4 {
		t.Fatalf("MULTI_SZ | NOCLOBBER = type %d data %x", multi.typ, multi.data)
	}
	for _, test := range []struct {
		value string
		want  uint32
	}{
		{value: "32", want: 32},
		{value: "0x20", want: 32},
		{value: "-1", want: 0xffffffff},
	} {
		dword := registryDataFromINF(0x00010001, []string{test.value})
		if dword.typ != regDWORD || len(dword.data) != 4 || binary.LittleEndian.Uint32(dword.data) != test.want {
			t.Fatalf("DWORD %q = type %d data %x, want %#x", test.value, dword.typ, dword.data, test.want)
		}
	}
	binaryValue := registryDataFromINF(0x00000001, []string{"32"})
	if binaryValue.typ != regBinary || string(binaryValue.data) != "\x32" {
		t.Fatalf("binary hex byte = type %d data %x", binaryValue.typ, binaryValue.data)
	}
}

func TestRegistryPatchFromINFAddRegRowParsesDecimalFlags(t *testing.T) {
	for _, flags := range []string{"65537", "0x00010001"} {
		row := starlark.NewList([]starlark.Value{
			starlark.String("HKLM"),
			starlark.String(`System\CurrentControlSet\Services\mnmdd`),
			starlark.String("Start"),
			starlark.String(flags),
			starlark.String("1"),
			starlark.String("0"),
			starlark.String("0"),
			starlark.String("0"),
		})
		hive, patch, ok, err := registryPatchFromINFAddRegRow(row)
		if err != nil {
			t.Fatal(err)
		}
		if !ok || hive != "SYSTEM" {
			t.Fatalf("flags %q: included = %t, hive = %q", flags, ok, hive)
		}
		if patch.typ != "REG_DWORD" || patch.value.String() != "1" {
			t.Fatalf("flags %q: patch = %#v, want REG_DWORD 1", flags, patch)
		}
	}
}

func TestPrivateRegistryTypeRoundTrip(t *testing.T) {
	want := registryData{typ: 0x201, data: []byte{0x34, 0x12}}
	typ, value, err := registryDataToStarlark(want)
	if err != nil {
		t.Fatal(err)
	}
	if typ != "REG_TYPE_513" {
		t.Fatalf("type = %q, want REG_TYPE_513", typ)
	}
	got, err := registryDataFromStarlark(typ, value)
	if err != nil {
		t.Fatal(err)
	}
	if got.typ != want.typ || string(got.data) != string(want.data) {
		t.Fatalf("round trip = type %d data %x, want type %d data %x", got.typ, got.data, want.typ, want.data)
	}
}

func TestRawHivePatchRoundTrip(t *testing.T) {
	root := newRegistryTree("SAM")
	setRegistryValue(root, "/SAM/Domains/Account/Groups/Names/None", "(default)", registryData{typ: 0x201, data: []byte{0xaa, 0x55}})
	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	rawValue, err := hivePatchesBuiltin(nil, nil, starlark.Tuple{testHiveFile(data)}, []starlark.Tuple{{starlark.String("raw"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	raw := rawValue.(*starlark.List)
	if raw.Len() != 1 {
		t.Fatalf("raw patches = %d, want 1", raw.Len())
	}
	patch := raw.Index(0).(*starlark.Dict)
	typeValue, _, err := patch.Get(starlark.String("type"))
	if err != nil {
		t.Fatal(err)
	}
	typ, ok := typeValue.(starlark.Int)
	if !ok {
		t.Fatalf("raw type is %s, want int", typeValue.Type())
	}
	gotType, _ := typ.Uint64()
	if gotType != 0x201 {
		t.Fatalf("raw type = %#x, want %#x", gotType, 0x201)
	}
	rebuiltValue, err := hiveFromPatchesBuiltin(nil, nil, starlark.Tuple{starlark.String("SAM"), raw}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := rebuiltValue.(starfile.File)
	hive, err := newRegistryHive(rebuilt)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hive.lookup("/SAM/Domains/Account/Groups/Names/None")
	if err != nil {
		t.Fatal(err)
	}
	values, err := hive.readRawValues(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].value.typ != 0x201 || string(values[0].value.data) != "\xaa\x55" {
		t.Fatalf("rebuilt raw value = %#v", values)
	}
}

func TestHiveRoundTripPreservesLiteralPathSeparatorsInKeyNames(t *testing.T) {
	root := newRegistryTree("SOFTWARE")
	parts := []string{"Example", "Runtime", "Plugins", "vendor:kind/algorithm/sample/2005"}
	key := ensureRegistryKeyParts(root, parts)
	key.values["ModuleId"] = registryString(regSZ, "fixture-plugin")
	emptyParts := append(append([]string(nil), parts...), "empty/child")
	ensureRegistryKeyParts(root, emptyParts)

	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	source := testHiveFile(data)
	patchesValue, err := hivePatchesBuiltin(nil, nil, starlark.Tuple{source}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keysValue, err := hiveKeysBuiltin(nil, nil, starlark.Tuple{source}, []starlark.Tuple{{starlark.String("metadata"), starlark.True}})
	if err != nil {
		t.Fatal(err)
	}
	rebuiltValue, err := hiveFromPatchesBuiltin(
		nil,
		nil,
		starlark.Tuple{starlark.String("SOFTWARE"), patchesValue},
		[]starlark.Tuple{{starlark.String("keys"), keysValue}},
	)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := newRegistryHive(rebuiltValue.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	got, err := rebuilt.lookupParts(parts)
	if err != nil {
		t.Fatal(err)
	}
	values, err := rebuilt.readRawValues(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || registryDataString(values[0].value) != "fixture-plugin" {
		t.Fatalf("literal-name key values = %#v", values)
	}
	if _, err := rebuilt.lookupParts(emptyParts); err != nil {
		t.Fatalf("empty literal-name key was not preserved: %v", err)
	}
	pathValue := make(starlark.Tuple, len(parts))
	for index, part := range parts {
		pathValue[index] = starlark.String(part)
	}
	keyValue, found, err := rebuilt.Get(pathValue)
	if err != nil || !found {
		t.Fatalf("structured hive lookup failed: found=%t err=%v", found, err)
	}
	emptyValue, found, err := keyValue.(*registryKey).Get(starlark.Tuple{starlark.String("empty/child")})
	if err != nil || !found || emptyValue.(*registryKey).key.name != "empty/child" {
		t.Fatalf("structured relative lookup failed: value=%v found=%t err=%v", emptyValue, found, err)
	}
	nested := []string{"Example", "Runtime", "Plugins", "vendor:kind", "algorithm", "sample", "2005"}
	if _, err := rebuilt.lookupParts(nested); err == nil {
		t.Fatal("literal separators were incorrectly reconstructed as nested keys")
	}
}

func TestHiveFromPatchesAppliesDeleteBehavior(t *testing.T) {
	patch := func(value string, deleteValue bool) *starlark.Dict {
		item := starlark.NewDict(5)
		for key, field := range map[string]starlark.Value{
			"key":   starlark.String("/Microsoft/Windows/CurrentVersion/RunOnce"),
			"name":  starlark.String("CompletedAction"),
			"type":  starlark.String("REG_SZ"),
			"value": starlark.String(value),
		} {
			if err := item.SetKey(starlark.String(key), field); err != nil {
				t.Fatal(err)
			}
		}
		if deleteValue {
			if err := item.SetKey(starlark.String("delete"), starlark.True); err != nil {
				t.Fatal(err)
			}
		}
		return item
	}
	patches := starlark.NewList([]starlark.Value{
		patch("command.exe", false),
		patch("command.exe", true),
	})
	value, err := hiveFromPatchesBuiltin(
		nil,
		nil,
		starlark.Tuple{starlark.String("SOFTWARE"), patches},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	hive, err := newRegistryHive(value.(starfile.File))
	if err != nil {
		t.Fatal(err)
	}
	key, err := hive.lookup("/Microsoft/Windows/CurrentVersion/RunOnce")
	if err != nil {
		t.Fatal(err)
	}
	values, err := hive.readRawValues(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 0 {
		t.Fatalf("RunOnce values = %#v, want completed action deleted", values)
	}
}

func TestBuildRegistryHivePreservesKeyClassAndFlags(t *testing.T) {
	root := newRegistryTree("SYSTEM")
	key := ensureRegistryKey(root, "/ControlSet001/Control/Lsa/JDΩ")
	key.flags = 0
	key.flagsSet = true
	key.class = utf16Bytes("0190cb2f")

	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	hive := &registryHive{file: testHiveFile(data), rootCell: binary.LittleEndian.Uint32(data[0x24:0x28])}
	got, err := hive.lookup("/ControlSet001/Control/Lsa/JDΩ")
	if err != nil {
		t.Fatal(err)
	}
	if got.flags != key.flags {
		t.Fatalf("flags = %#x, want %#x", got.flags, key.flags)
	}
	classData, err := hive.readKeyClass(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(classData) != string(key.class) {
		t.Fatalf("class = %x, want %x", classData, key.class)
	}
}

func TestDefaultRegistrySecurityDescriptorHasOwnerAndGroup(t *testing.T) {
	descriptor := defaultRegistrySecurityDescriptor()
	if len(descriptor) < 20 || descriptor[0] != 1 {
		t.Fatalf("invalid self-relative security descriptor header")
	}
	for _, offset := range []int{4, 8, 16} {
		value := int(binary.LittleEndian.Uint32(descriptor[offset : offset+4]))
		if value < 20 || value >= len(descriptor) {
			t.Fatalf("security descriptor offset at %#x = %#x", offset, value)
		}
	}
	acl := int(binary.LittleEndian.Uint32(descriptor[16:20]))
	if got, want := binary.LittleEndian.Uint16(descriptor[acl+4:acl+6]), uint16(2); got != want {
		t.Fatalf("DACL ACE count = %d, want %d", got, want)
	}
}

func TestBuildRegistryHivePreservesPerKeySecurity(t *testing.T) {
	root := newRegistryTree("SYSTEM")
	first := ensureRegistryKey(root, "/First")
	second := ensureRegistryKey(root, "/Second")
	first.security = defaultRegistrySecurityDescriptor()
	second.security = append([]byte(nil), first.security...)
	dacl := int(binary.LittleEndian.Uint32(second.security[16:20]))
	binary.LittleEndian.PutUint32(second.security[dacl+8+4:dacl+8+8], 0x00020019)

	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	hive := &registryHive{file: testHiveFile(data), rootCell: binary.LittleEndian.Uint32(data[0x24:0x28])}
	firstKey, err := hive.lookup("/First")
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := hive.lookup("/Second")
	if err != nil {
		t.Fatal(err)
	}
	firstDescriptor, err := hive.readKeySecurity(firstKey)
	if err != nil {
		t.Fatal(err)
	}
	secondDescriptor, err := hive.readKeySecurity(secondKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstDescriptor) != string(first.security) {
		t.Fatalf("first security = %x, want %x", firstDescriptor, first.security)
	}
	if string(secondDescriptor) != string(second.security) {
		t.Fatalf("second security = %x, want %x", secondDescriptor, second.security)
	}
	if firstKey.security == secondKey.security {
		t.Fatal("different descriptors unexpectedly share one security cell")
	}
}

func TestBuildRegistryHiveInheritsParentSecurityForCreatedKeys(t *testing.T) {
	root := newRegistryTree("SYSTEM")
	parent := ensureRegistryKey(root, "/ControlSet001/Control/ComputerName")
	parent.security = defaultRegistrySecurityDescriptor()
	dacl := int(binary.LittleEndian.Uint32(parent.security[16:20]))
	binary.LittleEndian.PutUint32(parent.security[dacl+8+4:dacl+8+8], 0x00020019)
	ensureRegistryKey(root, "/ControlSet001/Control/ComputerName/ActiveComputerName")

	data, err := buildRegistryHive(root)
	if err != nil {
		t.Fatal(err)
	}
	hive := &registryHive{file: testHiveFile(data), rootCell: binary.LittleEndian.Uint32(data[0x24:0x28])}
	child, err := hive.lookup("/ControlSet001/Control/ComputerName/ActiveComputerName")
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := hive.readKeySecurity(child)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(descriptor, parent.security) {
		t.Fatalf("child security = %x, want inherited %x", descriptor, parent.security)
	}
}

func TestBuildRegistryHiveRejectsInvalidPerKeySecurity(t *testing.T) {
	root := newRegistryTree("SYSTEM")
	ensureRegistryKey(root, "/Invalid").security = []byte{1, 0, 0, 0}
	if _, err := buildRegistryHive(root); err == nil {
		t.Fatal("invalid key security was accepted")
	}
}

func TestApplyTxtSetupRegistryAddsNLSBootValues(t *testing.T) {
	nls := starlark.NewDict(5)
	setTestINFValue(t, nls, "AnsiCodepage", "c_1252.nls", "1252")
	setTestINFValue(t, nls, "OemCodepage", "c_437.nls", "437", "c_850.nls", "850")
	setTestINFValue(t, nls, "MacCodepage", "c_10000.nls", "10000")
	setTestINFValue(t, nls, "UnicodeCasetable", "l_intl.nls", "0409")
	setTestINFValue(t, nls, "OemHalFont", "vgaoem.fon")

	txtsetupJSON := starlark.NewDict(1)
	if err := txtsetupJSON.SetKey(starlark.String("nls"), nls); err != nil {
		t.Fatal(err)
	}
	root := newRegistryTree("SYSTEM")
	applyTxtSetupNLSRegistry(root, &infFile{json: txtsetupJSON})

	codepage := testRegistryKey(t, root, "/ControlSet001/Control/NLS/CodePage")
	language := testRegistryKey(t, root, "/ControlSet001/Control/NLS/Language")
	locale := testRegistryKey(t, root, "/ControlSet001/Control/NLS/Locale")
	checkRegistryString(t, codepage, "ACP", "1252")
	checkRegistryString(t, codepage, "1252", "c_1252.nls")
	checkRegistryString(t, codepage, "OEMCP", "437")
	checkRegistryString(t, codepage, "437", "c_437.nls")
	checkRegistryString(t, codepage, "850", "c_850.nls")
	checkRegistryString(t, codepage, "MACCP", "10000")
	checkRegistryString(t, codepage, "10000", "c_10000.nls")
	checkRegistryString(t, codepage, "OEMHAL", "vgaoem.fon")
	checkRegistryString(t, language, "Default", "0409")
	checkRegistryString(t, language, "InstallLanguage", "0409")
	checkRegistryString(t, language, "0409", "l_intl.nls")
	checkRegistryString(t, locale, "(default)", "00000409")
	checkRegistryString(t, locale, "00000409", "1")
}

func TestApplyTxtSetupRegistryPromotesInstalledDriverService(t *testing.T) {
	load := starlark.NewDict(1)
	setTestINFValue(t, load, "fat", "fastfat.sys")
	sources := starlark.NewDict(1)
	setTestINFValue(t, sources, "fastfat.sys", "1")
	txtsetupJSON := starlark.NewDict(2)
	if err := txtsetupJSON.SetKey(starlark.String("FileSystems.Load"), load); err != nil {
		t.Fatal(err)
	}
	if err := txtsetupJSON.SetKey(starlark.String("SourceDisksFiles"), sources); err != nil {
		t.Fatal(err)
	}

	system := newRegistryTree("SYSTEM")
	setRegistryValue(system, "/ControlSet001/Services/Fastfat", "Start", registryDWORD(4))
	applyTxtSetupRegistry(map[string]*registryTree{"SYSTEM": system}, &infFile{json: txtsetupJSON})

	services := testRegistryKey(t, system, "/ControlSet001/Services")
	if services.subkeys["FAT"] != nil {
		t.Fatal("TXTSETUP alias created a second service for fastfat.sys")
	}
	fastfat := testRegistryKey(t, system, "/ControlSet001/Services/Fastfat")
	if got := binary.LittleEndian.Uint32(fastfat.values["Start"].data); got != 0 {
		t.Fatalf("Fastfat Start = %d, want boot-start value 0", got)
	}
}

func TestApplyTxtSetupRegistryUsesDriverNameForSelectorAlias(t *testing.T) {
	load := starlark.NewDict(1)
	setTestINFValue(t, load, "STANDARD", "i8042prt.sys")
	sources := starlark.NewDict(1)
	setTestINFValue(t, sources, "i8042prt.sys", "1")
	txtsetupJSON := starlark.NewDict(2)
	if err := txtsetupJSON.SetKey(starlark.String("Keyboard.Load"), load); err != nil {
		t.Fatal(err)
	}
	if err := txtsetupJSON.SetKey(starlark.String("SourceDisksFiles"), sources); err != nil {
		t.Fatal(err)
	}

	system := newRegistryTree("SYSTEM")
	applyTxtSetupRegistry(map[string]*registryTree{"SYSTEM": system}, &infFile{json: txtsetupJSON})

	services := testRegistryKey(t, system, "/ControlSet001/Services")
	if services.subkeys["STANDARD"] != nil {
		t.Fatal("TXTSETUP selector alias became a service name")
	}
	i8042 := testRegistryKey(t, system, "/ControlSet001/Services/i8042prt")
	imagePath := i8042.values["ImagePath"]
	if imagePath.typ != regExpandSZ {
		t.Fatalf("ImagePath type = %d, want REG_EXPAND_SZ", imagePath.typ)
	}
	if got := strings.TrimRight(decodeUTF16LE(imagePath.data), "\x00"); got != "system32\\drivers\\i8042prt.sys" {
		t.Fatalf("ImagePath = %q", got)
	}
}

func setTestINFValue(t *testing.T, dict *starlark.Dict, name string, values ...string) {
	t.Helper()
	items := make([]starlark.Value, len(values))
	for i, value := range values {
		items[i] = starlark.String(value)
	}
	if err := dict.SetKey(starlark.String(name), starlark.NewList(items)); err != nil {
		t.Fatal(err)
	}
}

func testRegistryKey(t *testing.T, root *registryTree, keyPath string) *registryTree {
	t.Helper()
	current := root
	for _, part := range strings.Split(strings.Trim(storage.CleanPath(keyPath), "/"), "/") {
		child := current.subkeys[strings.ToUpper(part)]
		if child == nil {
			t.Fatalf("missing registry key %s", keyPath)
		}
		current = child
	}
	return current
}

func checkRegistryString(t *testing.T, key *registryTree, name, want string) {
	t.Helper()
	value, ok := key.values[name]
	if !ok {
		t.Fatalf("missing registry value %s", name)
	}
	if value.typ != regSZ {
		t.Fatalf("%s type = %d, want REG_SZ", name, value.typ)
	}
	if got := strings.TrimRight(decodeUTF16LE(value.data), "\x00"); got != want {
		t.Fatalf("%s = %q, want %q", name, got, want)
	}
}

type testHiveFile []byte

func (f testHiveFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= int64(len(f)) {
		return 0, io.EOF
	}
	n := copy(p, f[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f testHiveFile) WriteAt(_ []byte, _ int64) (int, error) {
	return 0, fmt.Errorf("test hive file is read-only")
}

func (f testHiveFile) Size() int64          { return int64(len(f)) }
func (f testHiveFile) String() string       { return "<test hive file>" }
func (f testHiveFile) Type() string         { return "file" }
func (f testHiveFile) Freeze()              {}
func (f testHiveFile) Truth() starlark.Bool { return starlark.True }
func (f testHiveFile) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", f.Type())
}
