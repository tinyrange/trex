package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"hash/crc32"
	"math"
	"sort"
	"strings"
	"testing"
	"unicode/utf16"

	"go.starlark.net/starlark"
)

func TestWMIRepositoryMappingRoundTrip(t *testing.T) {
	want := wmiRepositoryMapping{
		objects: wmiMappingSection{generation: 7, physicalPages: 4, base: []uint32{2, 0}, free: []uint32{3, 1}},
		index:   wmiMappingSection{generation: 8, physicalPages: 3, base: []uint32{1, 0}, free: []uint32{2}},
	}
	data := serializeWMIRepositoryMapping(want)
	got, err := parseWMIRepositoryMapping(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.objects.generation != want.objects.generation || got.index.generation != want.index.generation || !equalUint32s(got.objects.base, want.objects.base) || !equalUint32s(got.index.free, want.index.free) {
		t.Fatalf("mapping round trip differs: got %#v", got)
	}
}

func TestWMIRepositoryConfigIsInitialized(t *testing.T) {
	want := []byte{
		0, 0, 0, 0,
		1, 0, 0, 0,
		0, 0, 0, 0,
		6, 0, 0, 0,
		0, 0, 0, 0,
	}
	if got := buildWMIRepositoryConfig(); !bytes.Equal(got, want) {
		t.Fatalf("WMI repository config = %x, want %x", got, want)
	}
}

func TestWMIRepositoryObjectStoreRoundTrip(t *testing.T) {
	want := [][]byte{[]byte("first record"), bytes.Repeat([]byte{0x5a}, 9000), []byte("last record")}
	data, locations, err := buildWMIRepositoryObjects(append([][]byte(nil), want...))
	if err != nil {
		t.Fatal(err)
	}
	base := make([]uint32, len(data)/wmiRepositoryPageSize)
	for index := range base {
		base[index] = uint32(index)
	}
	got, err := parseWMIRepositoryRecords(wmiMappingSection{physicalPages: uint32(len(base)), base: base}, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || len(locations) != len(want) {
		t.Fatalf("got %d records and %d locations, want %d", len(got), len(locations), len(want))
	}
	if binary.LittleEndian.Uint32(data[:4]) != 1 || binary.LittleEndian.Uint32(data[4:8]) != 0 {
		t.Fatalf("object metadata header = %x, want version 1 with an empty cache chain", data[:8])
	}
	if got, want := binary.LittleEndian.Uint32(data[8:12]), uint32(2); got != want {
		t.Fatalf("object cache page count = %d, want %d", got, want)
	}
	for index := uint32(0); index < 2; index++ {
		offset := 12 + int(index)*16
		logical := binary.LittleEndian.Uint32(data[offset : offset+4])
		free := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		checksum := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		if logical == 0 || free >= wmiRepositoryPageSize {
			t.Fatalf("object cache entry %d = page %d free %d", index, logical, free)
		}
		page := data[int(logical)*wmiRepositoryPageSize : int(logical+1)*wmiRepositoryPageSize]
		if got := crc32.ChecksumIEEE(page); got != checksum {
			t.Fatalf("object cache entry %d checksum = %#x, want %#x", index, checksum, got)
		}
	}
	if locations[0].logicalPage != 1 {
		t.Fatalf("first record is on logical page %d, want 1", locations[0].logicalPage)
	}
	for index := range want {
		if !bytes.Equal(got[index].data, want[index]) {
			t.Fatalf("record %d differs", index)
		}
	}
}

func TestWMIRepositoryObjectStoreAllowsRecordIDOne(t *testing.T) {
	data, _, err := buildWMIRepositoryObjects([][]byte{[]byte("record one")})
	if err != nil {
		t.Fatal(err)
	}
	base := []uint32{0, 1}
	got, err := parseWMIRepositoryRecords(wmiMappingSection{physicalPages: 2, base: base}, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].data) != "record one" || got[0].id != 1 {
		t.Fatalf("record ID one did not round trip: %#v", got)
	}
}

func TestWMIRepositoryObjectStoreUsesIDOneForSpanningRecords(t *testing.T) {
	records := [][]byte{
		bytes.Repeat([]byte{0x41}, wmiRepositoryPageSize),
		bytes.Repeat([]byte{0x42}, wmiRepositoryPageSize+257),
	}
	data, locations, err := buildWMIRepositoryObjects(records)
	if err != nil {
		t.Fatal(err)
	}
	if len(locations) != len(records) {
		t.Fatalf("locations = %d, want %d", len(locations), len(records))
	}
	for index, location := range locations {
		if location.id != 1 {
			t.Fatalf("spanning record %d ID = %d, want 1", index, location.id)
		}
	}
	base := make([]uint32, len(data)/wmiRepositoryPageSize)
	for index := range base {
		base[index] = uint32(index)
	}
	got, err := parseWMIRepositoryRecords(wmiMappingSection{physicalPages: uint32(len(base)), base: base}, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(records) {
		t.Fatalf("parsed records = %d, want %d", len(got), len(records))
	}
	for index := range got {
		if got[index].id != 1 || !bytes.Equal(got[index].data, records[index]) {
			t.Fatalf("parsed spanning record %d does not round trip", index)
		}
	}
}

func TestWMIRepositoryIndexPageRoundTrip(t *testing.T) {
	want := []string{
		`NS_A\CD_ONE.1.2.3`,
		`NS_A\CR_PARENT\C_CHILD`,
		`NS_B\KI_CLASS\I_INSTANCE.4.5.6`,
	}
	page, err := buildWMIRepositoryIndexPage(9, want, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseWMIRepositoryIndexPage(page)
	if err != nil {
		t.Fatal(err)
	}
	if got.id != 9 || len(got.keys) != len(want) {
		t.Fatalf("got id=%d keys=%q", got.id, got.keys)
	}
	for index := range want {
		if got.keys[index] != want[index] {
			t.Fatalf("key %d = %q, want %q", index, got.keys[index], want[index])
		}
	}
}

func TestWMIRepositoryMultiPageIndexRoundTrip(t *testing.T) {
	want := make([]string, 2000)
	for index := range want {
		want[index] = fmt.Sprintf(`NS_%032x\CD_%032x.%d.%d.128`, index%23, index, index/7, index+2)
	}
	data, err := buildWMIRepositoryIndex(want)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) <= 3*wmiRepositoryPageSize {
		t.Fatalf("multi-page index only occupied %d pages", len(data)/wmiRepositoryPageSize)
	}
	root := binary.LittleEndian.Uint32(data[12:16])
	if root <= 1 || int(root+1)*wmiRepositoryPageSize > len(data) {
		t.Fatalf("invalid root page %d for %d pages", root, len(data)/wmiRepositoryPageSize)
	}

	var got []string
	for id := uint32(1); int(id+1)*wmiRepositoryPageSize <= len(data); id++ {
		page, err := parseWMIRepositoryIndexPage(data[int(id)*wmiRepositoryPageSize : int(id+1)*wmiRepositoryPageSize])
		if err != nil {
			t.Fatalf("parse page %d: %v", id, err)
		}
		for _, child := range page.children {
			if child != 0 {
				if child >= id {
					t.Fatalf("page %d points to non-descendant page %d", id, child)
				}
			}
		}
		got = append(got, page.keys...)
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %d leaf keys, want %d", len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("key %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestWMIRepositoryBuildsMOFClassesAndInstances(t *testing.T) {
	document, err := parseMOF(`#pragma namespace("\\\\.\\root")
[Abstract] class __SystemClass {};
[Abstract] class __Namespace : __SystemClass {
    [Key] string Name;
};
instance of __Namespace { Name = "SECURITY"; };
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root\cimv2`)
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.records) != 3 {
		t.Fatalf("got %d records, want 3", len(repository.records))
	}
	namespaceRevisionOffset := 4 + len(`__SystemClass`)*2
	namespaceRevision := binary.LittleEndian.Uint64(repository.records[1].data[namespaceRevisionOffset : namespaceRevisionOffset+8])
	instanceRevision := binary.LittleEndian.Uint64(repository.records[2].data[64:72])
	instanceClassRevision := binary.LittleEndian.Uint64(repository.records[2].data[72:80])
	if namespaceRevision == 0 || instanceRevision <= namespaceRevision || instanceClassRevision != namespaceRevision {
		t.Fatalf("invalid repository revisions: class=%#x instance=%#x class-link=%#x", namespaceRevision, instanceRevision, instanceClassRevision)
	}
	var foundClass, foundRootRelation, foundClassInstance, foundKeyInstance bool
	for _, page := range repository.pages {
		for _, key := range page.keys {
			if strings.Contains(key, `\CD_`) {
				foundClass = true
			}
			if strings.Contains(key, `\CR_D41D8CD98F00B204E9800998ECF8427E\C_`) {
				foundRootRelation = true
			}
			if strings.Contains(key, `\CI_`) && strings.Contains(key, `\IL_22FE773B1E794ABF3E2BFAA88EBDD7CC`) {
				foundClassInstance = true
			}
			if strings.Contains(key, `\KI_`) && strings.Contains(key, `\I_22FE773B1E794ABF3E2BFAA88EBDD7CC`) {
				foundKeyInstance = true
			}
		}
	}
	if !foundClass || !foundRootRelation || !foundClassInstance || !foundKeyInstance {
		t.Fatalf("missing repository index: class=%v root=%v class-instance=%v key-instance=%v", foundClass, foundRootRelation, foundClassInstance, foundKeyInstance)
	}

	config, ok := repository.files["$WinMgmt.CFG"].(starfile.File)
	if !ok {
		t.Fatal("repository configuration is missing")
	}
	configData, err := starfile.ReadAll(config)
	if err != nil {
		t.Fatal(err)
	}
	wantConfig := make([]byte, 20)
	binary.LittleEndian.PutUint32(wantConfig[4:8], 1)
	binary.LittleEndian.PutUint32(wantConfig[12:16], 6)
	if !bytes.Equal(configData, wantConfig) {
		t.Fatalf("repository configuration = %x, want %x", configData, wantConfig)
	}
	for name, generation := range map[string]uint32{
		"FS/MAPPING1.MAP": 1,
		"FS/MAPPING2.MAP": 1,
	} {
		data, err := starfile.ReadAll(repository.files[name].(starfile.File))
		if err != nil {
			t.Fatal(err)
		}
		mapping, err := parseWMIRepositoryMapping(data)
		if err != nil {
			t.Fatal(err)
		}
		if mapping.objects.generation != generation || mapping.index.generation != generation {
			t.Fatalf("%s generations = %d/%d, want %d", name, mapping.objects.generation, mapping.index.generation, generation)
		}
		if len(mapping.objects.free) == 0 || len(mapping.index.free) == 0 {
			t.Fatalf("%s has no transactional free pages", name)
		}
		if got := len(mapping.objects.base) + len(mapping.objects.free); got != int(mapping.objects.physicalPages) {
			t.Fatalf("%s object page accounting = %d, want %d", name, got, mapping.objects.physicalPages)
		}
		if got := len(mapping.index.base) + len(mapping.index.free); got != int(mapping.index.physicalPages) {
			t.Fatalf("%s index page accounting = %d, want %d", name, got, mapping.index.physicalPages)
		}
	}

	files := starlark.NewDict(len(repository.files))
	for name, file := range repository.files {
		if name == "$WinMgmt.CFG" {
			continue
		}
		if err := files.SetKey(starlark.String(name), file); err != nil {
			t.Fatal(err)
		}
	}
	parsedValue, err := wmiRepositoryBuiltin(nil, nil, starlark.Tuple{files}, nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed := parsedValue.(*wmiRepositoryFile)
	if len(parsed.records) != len(repository.records) {
		t.Fatalf("parsed %d records, want %d", len(parsed.records), len(repository.records))
	}
}

func TestWMIRepositoryReplacesDuplicateClassDefinition(t *testing.T) {
	first, err := parseMOF(`class Updated { uint32 OldValue; };`)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseMOF(`class Updated { string NewValue; };`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{first, second}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.records) != 1 {
		t.Fatalf("got %d records, want one replacement class", len(repository.records))
	}
	if bytes.Contains(repository.records[0].data, []byte("OldValue")) || !bytes.Contains(repository.records[0].data, []byte("NewValue")) {
		t.Fatalf("replacement class did not supersede the earlier definition: %x", repository.records[0].data)
	}
}

func TestWMIRepositoryIndexesReferenceRelations(t *testing.T) {
	document, err := parseMOF(`
class Target {
    [Key] string Name;
};
class Association {
    Target ref First;
    Target ref Second;
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	want := `NS_` + wmiUpperUTF16MD5(`ROOT`) + `\CR_` + wmiUpperUTF16MD5(`Target`) + `\R_` + wmiUpperUTF16MD5(`Association`)
	count := 0
	for _, page := range repository.pages {
		for _, key := range page.keys {
			if key == want {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("reference relation %q occurs %d times, want once", want, count)
	}
}

func TestWMIRepositoryIndexesInheritedAndReferenceInstanceKeys(t *testing.T) {
	document, err := parseMOF(`
#pragma namespace("\\\\.\\root\\provider")
class Provider {
    [Key] string Name;
};
class ConcreteProvider : Provider {
    string CLSID;
};
class Registration {
    [Key] Provider ref Provider;
};
instance of ConcreteProvider as $provider {
    Name = "Synthetic";
    CLSID = "{00000000-0000-0000-0000-000000000001}";
};
instance of Registration {
    Provider = $provider;
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.records) != 6 {
		t.Fatalf("got %d records, want three classes, two instances, and one reference projection", len(repository.records))
	}

	namespaceHash := wmiUpperUTF16MD5(`ROOT\PROVIDER`)
	providerKey := wmiUpperUTF16MD5(`Synthetic`)
	referencePath := `\\.\ROOT\PROVIDER:ConcreteProvider.Name="Synthetic"`
	registrationKey := wmiUpperUTF16MD5(referencePath)
	prefix := `NS_` + namespaceHash + `\`
	var inheritedKey, registrationKeyIndex, reverseReference bool
	for _, page := range repository.pages {
		for _, key := range page.keys {
			switch {
			case strings.HasPrefix(key, prefix+`KI_`+wmiUpperUTF16MD5(`Provider`)+`\I_`+providerKey+`.`):
				inheritedKey = true
			case strings.HasPrefix(key, prefix+`KI_`+wmiUpperUTF16MD5(`Registration`)+`\I_`+registrationKey+`.`):
				registrationKeyIndex = true
			case strings.HasPrefix(key, prefix+`KI_`+wmiUpperUTF16MD5(`Provider`)+`\IR_`+providerKey+`\R_`):
				reverseReference = true
			}
		}
	}
	if !inheritedKey || !registrationKeyIndex || !reverseReference {
		t.Fatalf("instance indexes: inherited=%v registration=%v reverse=%v", inheritedKey, registrationKeyIndex, reverseReference)
	}

	projection := repository.records[len(repository.records)-1].data
	for _, value := range []string{`ROOT\PROVIDER`, `Registration`, `provider`} {
		var encoded []byte
		for _, unit := range utf16.Encode([]rune(value)) {
			encoded = binary.LittleEndian.AppendUint16(encoded, unit)
		}
		if !bytes.Contains(projection, encoded) {
			t.Fatalf("reference projection does not contain %q: %x", value, projection)
		}
	}
	sourcePath := `\NS_` + namespaceHash + `\KI_` + wmiUpperUTF16MD5(`Registration`) + `\I_` + registrationKey
	var encodedSource []byte
	for _, unit := range utf16.Encode([]rune(sourcePath)) {
		encodedSource = binary.LittleEndian.AppendUint16(encodedSource, unit)
	}
	if !bytes.Contains(projection, encodedSource) {
		t.Fatalf("reference projection does not contain source index path %q: %x", sourcePath, projection)
	}
}

func TestWMIRepositoryAllowsUnresolvedWeakInstanceReference(t *testing.T) {
	document, err := parseMOF(`
class Target {
    [Key] string Name;
};
class Registration {
    [Key] Target ref Target;
};
instance of Registration {
    Target = "Target.Name=\"created by provider\"";
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.records) != 3 {
		t.Fatalf("got %d records, want two classes and one weak-reference instance", len(repository.records))
	}
	for _, page := range repository.pages {
		for _, key := range page.keys {
			if strings.Contains(key, `\IR_`) {
				t.Fatalf("unresolved weak reference unexpectedly produced reverse index %q", key)
			}
		}
	}
}

func TestWMIRepositoryUsesImplicitSingletonInstanceKey(t *testing.T) {
	document, err := parseMOF(`
[singleton] class Singleton {
    string Value;
};
instance of Singleton {};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	wantFragment := `\IL_` + wmiUpperUTF16MD5(`@`) + `.`
	found := false
	for _, page := range repository.pages {
		for _, key := range page.keys {
			if strings.Contains(key, wantFragment) {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("repository has no singleton instance key containing %q", wantFragment)
	}
}

func TestWMIRepositoryInstanceKeysUsePropertyDefaults(t *testing.T) {
	document, err := parseMOF(`
class LocalizedValue {
    [key] string RelPath;
    [key] string PropertyName;
    [key] string ObjectLocator = "Description";
    string Text;
};
instance of LocalizedValue {
    RelPath = "Target.Name=\"example\"";
    PropertyName = "Description";
    Text = "Example";
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	wantFragment := `\I_` + wmiUpperUTF16MD5(`Target.Name="example"`+`Description`+`Description`) + `.`
	for _, page := range repository.pages {
		for _, key := range page.keys {
			if strings.Contains(key, wantFragment) {
				return
			}
		}
	}
	t.Fatalf("repository has no default-backed instance key containing %q", wantFragment)
}

func TestWMIRepositoryCanonicalizesInstanceClassSpelling(t *testing.T) {
	document, err := parseMOF(`
class __NAMESPACE {
    [Key] string Name;
};
instance of __Namespace { Name = "CIMV2"; };
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	record := repository.records[1].data
	if !bytes.Contains(record, []byte("__NAMESPACE\x00")) || bytes.Contains(record, []byte("__Namespace\x00")) {
		t.Fatalf("instance does not use canonical class spelling: %x", record)
	}
}

func TestWMIRepositoryReplacesDuplicateInstanceDefinition(t *testing.T) {
	document, err := parseMOF(`
class Updated {
    [Key] string Name;
    string Value;
};
instance of Updated { Name = "same"; Value = "old"; };
instance of Updated { Name = "same"; Value = "new"; };
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.records) != 2 {
		t.Fatalf("got %d records, want one class and one replacement instance", len(repository.records))
	}
	record := repository.records[1].data
	if bytes.Contains(record, []byte("old")) || !bytes.Contains(record, []byte("new")) {
		t.Fatalf("replacement instance did not supersede the earlier definition: %x", record)
	}
}

func TestWMIRepositoryLocalizedClassUsesParentSchema(t *testing.T) {
	base, err := parseMOF(`
#pragma namespace("\\\\.\\root\\schema")
class Base { uint32 BaseValue; };
`)
	if err != nil {
		t.Fatal(err)
	}
	localized, err := parseMOF(`
#pragma namespace("\\\\.\\root\\schema\\ms_409")
class Child : Base { string Caption; };
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{base, localized}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.records) != 2 {
		t.Fatalf("got %d records, want base and localized child", len(repository.records))
	}
}

func TestWMIClassHeaderStoresDefaultDataWidth(t *testing.T) {
	document, err := parseMOF(`[Abstract] class __SystemClass {};
class __Namespace : __SystemClass {
    [Key] string Name;
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.records) != 2 {
		t.Fatalf("got %d records, want 2", len(repository.records))
	}
	record := repository.records[1].data
	classPart := 4 + len(`__SystemClass`)*2 + 8
	if got := binary.LittleEndian.Uint32(record[classPart+9 : classPart+13]); got != 5 {
		t.Fatalf("class default-data width = %d, want one bitmap byte plus one four-byte value", got)
	}
}

func TestWMIClassDefaultStateBitmapMarksUnusedSlots(t *testing.T) {
	document, err := parseMOF(`
class StateBits {
    uint32 First;
    string Second;
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	record := repository.records[0].data
	classPart := 12
	derivation := classPart + 13
	qualifiers := derivation + int(binary.LittleEndian.Uint32(record[derivation:derivation+4]))
	lookup := qualifiers + int(binary.LittleEndian.Uint32(record[qualifiers:qualifiers+4]))
	defaultData := lookup + 4 + int(binary.LittleEndian.Uint32(record[lookup:lookup+4]))*8
	if got := record[defaultData]; got != 0xf5 {
		t.Fatalf("default-state bitmap = %#x, want two null properties and sentinel padding %#x", got, byte(0xf5))
	}
}

func TestWMICIMTypeUsesIntrinsicQualifierEncoding(t *testing.T) {
	var heap wmiHeapBuilder
	qualifiers, err := buildWMIQualifierSet([]mofQualifier{
		wmiCIMTypeQualifier(mofType{Name: "string"}),
	}, &heap)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(qualifiers[4:8]); got != 0x8000000a {
		t.Fatalf("CIMTYPE qualifier name = %#x, want intrinsic name %#x", got, uint32(0x8000000a))
	}
	if got := qualifiers[8]; got != 3 {
		t.Fatalf("CIMTYPE qualifier flavor = %#x, want propagating/overridable flavor 3", got)
	}
	if bytes.Contains(heap.data, []byte("CIMTYPE")) {
		t.Fatalf("CIMTYPE was redundantly stored in the object heap: %x", heap.data)
	}
}

func TestWMICIMTypePreservesSpellingWithoutArraySuffix(t *testing.T) {
	code, name, size, err := wmiCIMType(mofType{Name: "STRING", Array: true})
	if err != nil {
		t.Fatal(err)
	}
	if code != 0x2008 || name != "STRING" || size != 4 {
		t.Fatalf("array CIM type = (%#x, %q, %d), want (0x2008, STRING, 4)", code, name, size)
	}

	code, name, size, err = wmiCIMType(mofType{Name: "Widget", Array: true})
	if err != nil {
		t.Fatal(err)
	}
	if code != 0x200d || name != "object:Widget" || size != 4 {
		t.Fatalf("object array CIM type = (%#x, %q, %d), want (0x200d, object:Widget, 4)", code, name, size)
	}
}

func TestWMIKeyUsesIntrinsicQualifierEncoding(t *testing.T) {
	var heap wmiHeapBuilder
	qualifiers, err := buildWMIQualifierSet([]mofQualifier{{Name: "Key"}}, &heap)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(qualifiers[4:8]); got != 0x80000001 {
		t.Fatalf("Key qualifier name = %#x, want intrinsic name %#x", got, uint32(0x80000001))
	}
	if got := qualifiers[8]; got != 0x13 {
		t.Fatalf("Key qualifier flavor = %#x, want key flavor %#x", got, byte(0x13))
	}
	if bytes.Contains(heap.data, []byte("Key")) {
		t.Fatalf("Key was redundantly stored in the object heap: %x", heap.data)
	}
}

func TestWMISingletonUsesPropagatingQualifierFlavor(t *testing.T) {
	var heap wmiHeapBuilder
	qualifiers, err := buildWMIQualifierSet([]mofQualifier{{Name: "singleton"}}, &heap)
	if err != nil {
		t.Fatal(err)
	}
	if got := qualifiers[8]; got != 0x13 {
		t.Fatalf("singleton qualifier flavor = %#x, want propagating flavor %#x", got, byte(0x13))
	}
	if !bytes.Contains(heap.data, []byte("singleton")) {
		t.Fatalf("singleton qualifier name is absent from the object heap: %x", heap.data)
	}
}

func TestWMIValuesQualifierKeepsDefaultFlavor(t *testing.T) {
	var heap wmiHeapBuilder
	qualifiers, err := buildWMIQualifierSet([]mofQualifier{{
		Name: "Values",
		Values: []mofValue{
			{Kind: mofValueString, Text: "First"},
			{Kind: mofValueString, Text: "Second"},
		},
	}}, &heap)
	if err != nil {
		t.Fatal(err)
	}
	if got := qualifiers[8]; got != 0 {
		t.Fatalf("Values qualifier flavor = %#x, want default flavor", got)
	}
}

func TestWMIQualifierPreservesExplicitFlavors(t *testing.T) {
	tests := []struct {
		name     string
		flavors  []string
		fallback byte
		want     byte
	}{
		{name: "provider", flavors: []string{"ToInstance"}, fallback: 3, want: 0x01},
		{name: "key", flavors: []string{"ToInstance", "ToSubclass", "DisableOverride"}, fallback: 0, want: 0x13},
		{name: "localized", flavors: []string{"ToSubclass", "Amended"}, fallback: 0, want: 0x82},
		{name: "restricted", flavors: []string{"Restricted", "EnableOverride"}, fallback: 3, want: 0},
	}
	for _, test := range tests {
		got, err := wmiQualifierFlavor(mofQualifier{Name: test.name, Flavors: test.flavors}, test.fallback)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got != test.want {
			t.Fatalf("%s flavor = %#x, want %#x", test.name, got, test.want)
		}
	}
	if _, err := wmiQualifierFlavor(mofQualifier{
		Name:    "invalid",
		Flavors: []string{"Restricted", "ToInstance"},
	}, 0); err == nil {
		t.Fatal("Restricted with ToInstance unexpectedly succeeded")
	}
}

func TestWMIStandardDynamicAndProviderQualifierFlavors(t *testing.T) {
	var heap wmiHeapBuilder
	data, err := buildWMIQualifierSet([]mofQualifier{
		{Name: "Dynamic"},
		{Name: "Provider", Values: []mofValue{{Kind: mofValueString, Text: "Example"}}, Flavors: []string{"ToInstance"}},
	}, &heap)
	if err != nil {
		t.Fatal(err)
	}
	if got := data[8]; got != 0x03 {
		t.Fatalf("Dynamic flavor = %#x, want %#x", got, byte(0x03))
	}
	// The first Boolean qualifier occupies eleven bytes after the set header.
	if got := data[19]; got != 0x01 {
		t.Fatalf("Provider flavor = %#x, want %#x", got, byte(0x01))
	}
}

func TestWMIStandardQualifierNamesUseIntrinsicEncoding(t *testing.T) {
	tests := []struct {
		name string
		id   uint32
	}{
		{name: "Read", id: 0x80000003},
		{name: "Write", id: 0x80000004},
		{name: "Volatile", id: 0x80000005},
		{name: "Provider", id: 0x80000006},
		{name: "Dynamic", id: 0x80000007},
	}
	for _, test := range tests {
		var heap wmiHeapBuilder
		qualifier := mofQualifier{Name: test.name}
		if test.name == "Provider" {
			qualifier.Values = []mofValue{{Kind: mofValueString, Text: "Example"}}
		}
		data, err := buildWMIQualifierSet([]mofQualifier{qualifier}, &heap)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got := binary.LittleEndian.Uint32(data[4:8]); got != test.id {
			t.Fatalf("%s qualifier name = %#x, want %#x", test.name, got, test.id)
		}
		if bytes.Contains(heap.data, []byte(test.name)) {
			t.Fatalf("%s was redundantly stored in the object heap: %x", test.name, heap.data)
		}
	}
}

func TestWMIQualifierIntegerInferenceUsesCompactCIMTypes(t *testing.T) {
	tests := []struct {
		name  string
		value mofValue
		want  uint32
	}{
		{name: "positive sint32", value: mofValue{Kind: mofValueInteger, Unsigned: 1033}, want: 3},
		{name: "negative sint32", value: mofValue{Kind: mofValueInteger, Integer: -1, Negative: true}, want: 3},
		{name: "uint32", value: mofValue{Kind: mofValueInteger, Unsigned: math.MaxUint32}, want: 19},
		{name: "uint64", value: mofValue{Kind: mofValueInteger, Unsigned: uint64(math.MaxUint32) + 1}, want: 21},
		{name: "sint64", value: mofValue{Kind: mofValueInteger, Integer: math.MinInt64, Negative: true}, want: 20},
	}
	for _, test := range tests {
		var heap wmiHeapBuilder
		data, err := buildWMIQualifierSet([]mofQualifier{{
			Name:   "Synthetic",
			Values: []mofValue{test.value},
		}}, &heap)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if got := binary.LittleEndian.Uint32(data[9:13]); got != test.want {
			t.Fatalf("%s CIM type = %#x, want %#x", test.name, got, test.want)
		}
	}
}

func TestWMIRepositoryAppliesQualifierDeclarations(t *testing.T) {
	document, err := parseMOF(`
Qualifier Synthetic : uint32 = 7, Scope(class), Flavor(ToSubclass);
[Synthetic] class DeclaredDefault {};
[Synthetic(9) : ToInstance] class ExplicitFlavor {};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	for index, want := range []struct {
		value  uint32
		flavor byte
	}{
		{value: 7, flavor: 0x02},
		{value: 9, flavor: 0x01},
	} {
		record := repository.records[index].data
		classPart := 12
		derivation := classPart + 13
		qualifiers := derivation + int(binary.LittleEndian.Uint32(record[derivation:derivation+4]))
		if got := record[qualifiers+8]; got != want.flavor {
			t.Fatalf("class %d qualifier flavor = %#x, want %#x", index, got, want.flavor)
		}
		if got := binary.LittleEndian.Uint32(record[qualifiers+9 : qualifiers+13]); got != 19 {
			t.Fatalf("class %d qualifier CIM type = %#x, want uint32", index, got)
		}
		if got := binary.LittleEndian.Uint32(record[qualifiers+13 : qualifiers+17]); got != want.value {
			t.Fatalf("class %d qualifier value = %d, want %d", index, got, want.value)
		}
	}
}

func TestWMIHeapPreservesRepeatedStrings(t *testing.T) {
	var heap wmiHeapBuilder
	first, err := heap.addString("string")
	if err != nil {
		t.Fatal(err)
	}
	second, err := heap.addString("string")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("repeated strings shared heap handle %#x", first)
	}
}

func TestWMIPropertyDescriptorImmediatelyFollowsName(t *testing.T) {
	document, err := parseMOF(`
class Ordered {
    [Description("payload")] string Value;
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	record := repository.records[0].data
	classPart := 4 + 8
	derivation := classPart + 13
	qualifiers := derivation + int(binary.LittleEndian.Uint32(record[derivation:derivation+4]))
	lookup := qualifiers + int(binary.LittleEndian.Uint32(record[qualifiers:qualifiers+4]))
	defaultData := lookup + 4 + int(binary.LittleEndian.Uint32(record[lookup:lookup+4]))*8
	heap := defaultData + int(binary.LittleEndian.Uint32(record[classPart+9:classPart+13]))
	heapData := heap + 4
	name := binary.LittleEndian.Uint32(record[lookup+4 : lookup+8])
	descriptor := binary.LittleEndian.Uint32(record[lookup+8 : lookup+12])
	if got, want := descriptor, name+uint32(len("Value"))+2; got != want {
		t.Fatalf("property descriptor offset = %d, want name-adjacent offset %d", got, want)
	}
	if got := binary.LittleEndian.Uint32(record[heapData+int(descriptor) : heapData+int(descriptor)+4]); got != 8 {
		t.Fatalf("property descriptor CIM type = %#x, want string", got)
	}
}

func TestWMIPropertyHeapUsesLookupOrder(t *testing.T) {
	document, err := parseMOF(`
class Ordered {
    string Zulu;
    string Alpha;
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	record := repository.records[0].data
	classPart := 4 + 8
	derivation := classPart + 13
	qualifiers := derivation + int(binary.LittleEndian.Uint32(record[derivation:derivation+4]))
	lookup := qualifiers + int(binary.LittleEndian.Uint32(record[qualifiers:qualifiers+4]))
	alphaName := binary.LittleEndian.Uint32(record[lookup+4 : lookup+8])
	alphaDescriptor := binary.LittleEndian.Uint32(record[lookup+8 : lookup+12])
	zuluName := binary.LittleEndian.Uint32(record[lookup+12 : lookup+16])
	if alphaName >= zuluName {
		t.Fatalf("property heap handles are not in lookup order: Alpha=%d Zulu=%d", alphaName, zuluName)
	}
	if got, want := alphaDescriptor, alphaName+uint32(len("Alpha"))+2; got != want {
		t.Fatalf("Alpha descriptor offset = %d, want %d", got, want)
	}
}

func TestWMIHeapStringArrayIsContiguous(t *testing.T) {
	var heap wmiHeapBuilder
	offset, err := heap.addArray([]mofValue{
		{Kind: mofValueString, Text: "one"},
		{Kind: mofValueString, Text: "two"},
	}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 0 || binary.LittleEndian.Uint32(heap.data[:4]) != 2 {
		t.Fatalf("array header = %x at %#x", heap.data[:4], offset)
	}
	for index := 0; index < 2; index++ {
		handle := binary.LittleEndian.Uint32(heap.data[4+index*4 : 8+index*4])
		if handle < 12 {
			t.Fatalf("array element %d handle %#x points inside array header", index, handle)
		}
	}
}

func TestWMIMethodDescriptorsReferenceEmptyParameterObjects(t *testing.T) {
	document, err := parseMOF(`
class Methods {
    void NoParameters();
    void InputOnly([In] string Value);
};
`)
	if err != nil {
		t.Fatal(err)
	}
	class := document.Classes[0]
	methodPart, err := buildWMIMethodPart(class, 0, wmiObjectContext{})
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint16(methodPart[4:6]); got != 2 {
		t.Fatalf("method count = %d, want 2", got)
	}
	heapData := 8 + 2*24 + 4
	for methodIndex := 0; methodIndex < 2; methodIndex++ {
		descriptor := 8 + methodIndex*24
		if got := binary.LittleEndian.Uint32(methodPart[descriptor+8 : descriptor+12]); got != 0 {
			t.Fatalf("method %d inheritance depth = %d, want 0", methodIndex, got)
		}
		for _, handleOffset := range []int{16, 20} {
			handle := binary.LittleEndian.Uint32(methodPart[descriptor+handleOffset : descriptor+handleOffset+4])
			if handle == math.MaxUint32 {
				t.Fatalf("method %d parameter handle at +%d uses an invalid sentinel", methodIndex, handleOffset)
			}
			absolute := heapData + int(handle)
			if absolute+4 > len(methodPart) {
				t.Fatalf("method %d parameter handle %#x exceeds method heap", methodIndex, handle)
			}
		}
	}
	first := 8
	firstInput := binary.LittleEndian.Uint32(methodPart[first+16 : first+20])
	firstOutput := binary.LittleEndian.Uint32(methodPart[first+20 : first+24])
	second := 8 + 24
	secondInput := binary.LittleEndian.Uint32(methodPart[second+16 : second+20])
	secondOutput := binary.LittleEndian.Uint32(methodPart[second+20 : second+24])
	for name, handle := range map[string]uint32{
		"first input":   firstInput,
		"first output":  firstOutput,
		"second output": secondOutput,
	} {
		got := binary.LittleEndian.Uint32(methodPart[heapData+int(handle) : heapData+int(handle)+4])
		if got != 0 {
			t.Fatalf("%s parameter object length = %d, want zero", name, got)
		}
	}
	if got := binary.LittleEndian.Uint32(methodPart[heapData+int(secondInput) : heapData+int(secondInput)+4]); got == 0 {
		t.Fatal("second input parameter object is unexpectedly empty")
	}
}

func TestWMIEmbeddedParameterObjectContainsBothSchemaPairs(t *testing.T) {
	document, err := parseMOF(`class Methods { void Set([In] string Value); };`)
	if err != nil {
		t.Fatal(err)
	}
	methodPart, err := buildWMIMethodPart(document.Classes[0], 0, wmiObjectContext{})
	if err != nil {
		t.Fatal(err)
	}
	descriptor := 8
	handle := binary.LittleEndian.Uint32(methodPart[descriptor+16 : descriptor+20])
	heapData := 8 + 24 + 4
	object := methodPart[heapData+int(handle):]
	payloadLength := int(binary.LittleEndian.Uint32(object[:4]))
	if payloadLength > len(object)-4 {
		t.Fatalf("embedded object payload length = %d, exceeds method heap", payloadLength)
	}
	object = object[:4+payloadLength]
	if got, want := binary.LittleEndian.Uint32(object[:4]), uint32(len(object)-4); got != want {
		t.Fatalf("embedded object payload length = %d, want %d", got, want)
	}
	if object[4] != 1 {
		t.Fatalf("embedded object path flag = %#x, want pathless flag 1", object[4])
	}
	offset := 5
	if got := binary.LittleEndian.Uint32(object[offset : offset+4]); got != 29 {
		t.Fatalf("empty instance class part length = %d, want 29", got)
	}
	offset += 29
	if got := binary.LittleEndian.Uint32(object[offset : offset+4]); got != 12 {
		t.Fatalf("empty instance method part length = %d, want 12", got)
	}
	offset += 12
	classLength := int(binary.LittleEndian.Uint32(object[offset : offset+4]))
	if classLength <= 29 {
		t.Fatalf("parameter class part length = %d, want a populated class", classLength)
	}
	offset += classLength
	if got := binary.LittleEndian.Uint32(object[offset : offset+4]); got != 12 {
		t.Fatalf("empty parameter method part length = %d, want 12", got)
	}
}

func TestWMIEmbeddedParameterObjectCarriesRepositoryPath(t *testing.T) {
	document, err := parseMOF(`class Methods { void Set([In] string Value); };`)
	if err != nil {
		t.Fatal(err)
	}
	methodPart, err := buildWMIMethodPart(document.Classes[0], 0, wmiObjectContext{
		serverName: "HOST",
		namespace:  `ROOT\SYNTHETIC`,
	})
	if err != nil {
		t.Fatal(err)
	}
	handle := binary.LittleEndian.Uint32(methodPart[24:28])
	heapData := 8 + 24 + 4
	object := methodPart[heapData+int(handle):]
	if object[4] != 5 {
		t.Fatalf("embedded object path flag = %#x, want 5", object[4])
	}
	if !bytes.Contains(object, []byte("\x00HOST\x00")) || !bytes.Contains(object, []byte("\x00ROOT\\SYNTHETIC\x00")) {
		t.Fatalf("embedded object path is absent: %x", object[:min(len(object), 80)])
	}
	if !bytes.Contains(object, []byte("\x00ID\x00")) {
		t.Fatalf("embedded parameter ID qualifier is absent: %x", object)
	}
}

func TestWMIRepositorySerializesEmbeddedInstancesAndArrays(t *testing.T) {
	document, err := parseMOF(`
class Child {
    string Name;
};
class Parent {
    [Key] string Id;
    Child Embedded;
    Child Children[];
};
instance of Parent {
    Id = "one";
    Embedded = instance of Child { Name = "scalar"; };
    Children = {
        instance of Child { Name = "first"; },
        instance of Child { Name = "second"; }
    };
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	if len(repository.records) != 3 {
		t.Fatalf("record count = %d, want two classes and one instance", len(repository.records))
	}
	record := repository.records[2].data
	const (
		instancePart = 80
		body         = instancePart + 4
		data         = body + 4 + 1 + 1
		heapBlock    = data + 3*4 + 4 + 1
		heapData     = heapBlock + 4
	)
	if got := binary.LittleEndian.Uint32(record[instancePart : instancePart+4]); got != uint32(len(record)-instancePart) {
		t.Fatalf("instance part length = %d, want %d", got, len(record)-instancePart)
	}
	scalarHandle := binary.LittleEndian.Uint32(record[data+4 : data+8])
	scalar := record[heapData+int(scalarHandle):]
	if scalar[4] != 2 {
		t.Fatalf("scalar embedded object flag = %#x, want 2", scalar[4])
	}
	scalarPayload := int(binary.LittleEndian.Uint32(scalar[:4]))
	if scalarPayload+4 > len(scalar) {
		t.Fatalf("scalar embedded payload length = %d, exceeds heap", scalarPayload)
	}
	scalarClassLength := int(binary.LittleEndian.Uint32(scalar[5:9]))
	scalarInstance := 5 + scalarClassLength
	if scalarInstance+4 > scalarPayload+4 {
		t.Fatalf("scalar class length = %d, exceeds embedded payload", scalarClassLength)
	}
	if got := int(binary.LittleEndian.Uint32(scalar[scalarInstance : scalarInstance+4])); got != scalarPayload+4-scalarInstance {
		t.Fatalf("scalar instance length = %d, want %d", got, scalarPayload+4-scalarInstance)
	}
	if !bytes.Contains(scalar[:scalarPayload+4], []byte("\x00Child\x00")) ||
		!bytes.Contains(scalar[:scalarPayload+4], []byte("\x00scalar\x00")) {
		t.Fatalf("scalar embedded object lacks schema or value: %x", scalar[:min(scalarPayload+4, 160)])
	}

	arrayHandle := binary.LittleEndian.Uint32(record[data+8 : data+12])
	array := record[heapData+int(arrayHandle):]
	if got := binary.LittleEndian.Uint32(array[:4]); got != 2 {
		t.Fatalf("embedded array count = %d, want 2", got)
	}
	for index, value := range []string{"first", "second"} {
		handle := binary.LittleEndian.Uint32(array[4+index*4 : 8+index*4])
		object := record[heapData+int(handle):]
		if object[4] != 2 {
			t.Fatalf("embedded array element %d flag = %#x, want 2", index, object[4])
		}
		length := int(binary.LittleEndian.Uint32(object[:4])) + 4
		if length > len(object) || !bytes.Contains(object[:length], []byte("\x00"+value+"\x00")) {
			t.Fatalf("embedded array element %d lacks value %q", index, value)
		}
	}
}

func TestWMIRepositoryRejectsUnresolvedSuperclass(t *testing.T) {
	document, err := parseMOF(`class Child : Missing {};`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err == nil || !strings.Contains(err.Error(), "unresolved superclass Missing") {
		t.Fatalf("build error = %v, want unresolved superclass", err)
	}
}

func TestWMIClassLayoutIncludesInheritedProperties(t *testing.T) {
	document, err := parseMOF(`
class Base {
    uint32 BaseValue;
};
class Child : Base {
    string ChildValue;
};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	record := repository.records[1].data
	classPart := 4 + len(`Base`)*2 + 8
	if got := binary.LittleEndian.Uint32(record[classPart+9 : classPart+13]); got != 9 {
		t.Fatalf("class default-data width = %d, want one bitmap byte and two four-byte values", got)
	}
	derivation := classPart + 13
	qualifiers := derivation + int(binary.LittleEndian.Uint32(record[derivation:derivation+4]))
	lookup := qualifiers + int(binary.LittleEndian.Uint32(record[qualifiers:qualifiers+4]))
	defaultData := lookup + 4 + int(binary.LittleEndian.Uint32(record[lookup:lookup+4]))*8
	if got := record[defaultData]; got != 0xf7 {
		t.Fatalf("class default state = %#x, want inherited slot 3, local-null slot 1, and sentinel padding", got)
	}
	// The local string property occupies inherited slot one at byte offset four.
	descriptor := []byte{8, 0, 0, 0, 1, 0, 4, 0, 0, 0, 1, 0, 0, 0}
	if !bytes.Contains(record, descriptor) {
		t.Fatalf("derived property descriptor does not reference inherited layout: %x", record)
	}
}

func TestWMIClassDerivationStoresDirectSuperclassOnly(t *testing.T) {
	document, err := parseMOF(`
class Base {};
class Child : Base {};
class Grandchild : Child {};
`)
	if err != nil {
		t.Fatal(err)
	}
	repository, err := buildWMIRepositoryDocuments([]*mofDocument{document}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	record := repository.records[2].data
	classPart := 4 + len(`Child`)*2 + 8
	derivation := classPart + 13
	if got, want := binary.LittleEndian.Uint32(record[derivation:derivation+4]), uint32(len(`Child`)+10); got != want {
		t.Fatalf("derivation size = %d, want direct superclass block size %d", got, want)
	}
	if bytes.Contains(record, []byte("Base")) {
		t.Fatalf("grandchild derivation unexpectedly contains transitive superclass: %x", record)
	}
	// The grandchild's local descriptor would carry depth two. This class has
	// no local properties, so verify the same field on a derived property.
	withProperty, err := parseMOF(`class Root {}; class Middle : Root {}; class Leaf : Middle { string Value; };`)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := buildWMIRepositoryDocuments([]*mofDocument{withProperty}, `root`)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := []byte{8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0}
	if !bytes.Contains(derived.records[2].data, descriptor) {
		t.Fatalf("leaf property descriptor does not carry inheritance depth two: %x", derived.records[2].data)
	}
}

func equalUint32s(left, right []uint32) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
