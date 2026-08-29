package windows

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const wmiHeapLengthFlag = uint32(0x80000000)

type wmiHeapBuilder struct {
	data             []byte
	embeddedInstance func(mofInstance) ([]byte, error)
}

func (h *wmiHeapBuilder) addString(value string) (uint32, error) {
	if len(h.data) > math.MaxInt32 {
		return 0, fmt.Errorf("wmi object: heap exceeds 31-bit offset space")
	}
	offset := uint32(len(h.data))
	ascii := true
	for _, character := range value {
		if character == 0 || character > 0x7f {
			ascii = false
			break
		}
	}
	if ascii {
		h.data = append(h.data, 0)
		h.data = append(h.data, value...)
		h.data = append(h.data, 0)
	} else {
		h.data = append(h.data, 1)
		for _, unit := range append(utf16.Encode([]rune(value)), 0) {
			h.data = binary.LittleEndian.AppendUint16(h.data, unit)
		}
	}
	return offset, nil
}

func (h *wmiHeapBuilder) block() ([]byte, error) {
	if len(h.data) > math.MaxInt32 {
		return nil, fmt.Errorf("wmi object: heap exceeds 31-bit length space")
	}
	output := binary.LittleEndian.AppendUint32(nil, wmiHeapLengthFlag|uint32(len(h.data)))
	return append(output, h.data...), nil
}

func (h *wmiHeapBuilder) addArray(values []mofValue, scalarType uint32) (uint32, error) {
	if len(h.data) > math.MaxInt32 {
		return 0, fmt.Errorf("wmi object: heap exceeds 31-bit offset space")
	}
	offset := uint32(len(h.data))
	base := scalarType & 0xfff
	if base == 8 || base == 13 || base == 101 || base == 102 {
		h.data = binary.LittleEndian.AppendUint32(h.data, uint32(len(values)))
		elements := len(h.data)
		h.data = append(h.data, make([]byte, len(values)*4)...)
		for index, value := range values {
			handle := uint32(math.MaxUint32)
			if value.Kind != mofValueNull {
				var err error
				handle, err = h.addIndirectValue(value, base)
				if err != nil {
					return 0, fmt.Errorf("array element %d: %w", index, err)
				}
			}
			binary.LittleEndian.PutUint32(h.data[elements+index*4:elements+(index+1)*4], handle)
		}
		return offset, nil
	}

	array := binary.LittleEndian.AppendUint32(nil, uint32(len(values)))
	var err error
	for _, value := range values {
		array, err = appendWMIValue(array, value, scalarType, h)
		if err != nil {
			return 0, err
		}
	}
	h.data = append(h.data, array...)
	return offset, nil
}

func (h *wmiHeapBuilder) addIndirectValue(value mofValue, base uint32) (uint32, error) {
	if base == 13 && value.Kind == mofValueInstance {
		if value.Instance == nil {
			return 0, fmt.Errorf("embedded instance has no value")
		}
		if h.embeddedInstance == nil {
			return 0, fmt.Errorf("embedded instance of %s has no class resolver", value.Instance.Class)
		}
		object, err := h.embeddedInstance(*value.Instance)
		if err != nil {
			return 0, err
		}
		return h.addBlob(object)
	}
	if value.Kind != mofValueString && value.Kind != mofValueIdentifier && value.Kind != mofValueAlias {
		if base == 13 {
			return 0, fmt.Errorf("got %s, want embedded instance or string-compatible value", value.Kind)
		}
		return 0, fmt.Errorf("got %s, want string-compatible value", value.Kind)
	}
	return h.addString(value.Text)
}

func (h *wmiHeapBuilder) addBlob(value []byte) (uint32, error) {
	if len(h.data) > math.MaxInt32 || len(value) > math.MaxInt32-len(h.data) {
		return 0, fmt.Errorf("wmi object: heap exceeds 31-bit offset space")
	}
	offset := uint32(len(h.data))
	h.data = append(h.data, value...)
	return offset, nil
}

func wmiCIMType(t mofType) (uint32, string, int, error) {
	if t.Reference != "" {
		code := uint32(102)
		name := "ref:" + t.Reference
		if t.Array {
			code |= 0x2000
		}
		return code, name, 4, nil
	}
	var code uint32
	var size int
	switch strings.ToLower(t.Name) {
	case "sint8":
		code, size = 16, 1
	case "uint8":
		code, size = 17, 1
	case "sint16":
		code, size = 2, 2
	case "uint16", "char16":
		code, size = 18, 2
		if strings.EqualFold(t.Name, "char16") {
			code = 103
		}
	case "sint32":
		code, size = 3, 4
	case "uint32":
		code, size = 19, 4
	case "sint64":
		code, size = 20, 8
	case "uint64":
		code, size = 21, 8
	case "real32":
		code, size = 4, 4
	case "real64":
		code, size = 5, 8
	case "boolean":
		code, size = 11, 2
	case "string":
		code, size = 8, 4
	case "datetime":
		code, size = 101, 4
	case "object":
		code, size = 13, 4
	default:
		// MOF permits an embedded class name in the type position. The
		// repository stores it as CIM_OBJECT while retaining the declared
		// class in the automatic CIMTYPE qualifier.
		code, size = 13, 4
		name := "object:" + t.Name
		if t.Array {
			code |= 0x2000
		}
		return code, name, 4, nil
	}
	// The numeric CIM type carries array-ness. Native MOF compilation keeps
	// the source spelling in the automatic CIMTYPE qualifier and does not add
	// an "[]" suffix.
	name := t.Name
	if t.Array {
		code |= 0x2000
		size = 4
	}
	return code, name, size, nil
}

func wmiQualifierType(value mofValue) (uint32, int, error) {
	switch value.Kind {
	case mofValueBool:
		return 11, 2, nil
	case mofValueString, mofValueIdentifier, mofValueAlias:
		return 8, 4, nil
	case mofValueInteger:
		if value.Negative {
			if value.Integer >= math.MinInt32 {
				return 3, 4, nil
			}
			return 20, 8, nil
		}
		if value.Unsigned <= math.MaxInt32 {
			return 3, 4, nil
		}
		if value.Unsigned <= math.MaxUint32 {
			return 19, 4, nil
		}
		return 21, 8, nil
	case mofValueReal:
		return 5, 8, nil
	case mofValueArray:
		if len(value.Items) == 0 {
			return 0, 0, fmt.Errorf("empty qualifier array has no inferable element type")
		}
		cimType, _, err := wmiQualifierType(value.Items[0])
		return cimType | 0x2000, 4, err
	case mofValueNull:
		return 0, 0, fmt.Errorf("null qualifier value is invalid")
	default:
		return 0, 0, fmt.Errorf("unsupported qualifier value kind %q", value.Kind)
	}
}

func appendWMIValue(output []byte, value mofValue, cimType uint32, heap *wmiHeapBuilder) ([]byte, error) {
	base := cimType & 0xfff
	if cimType&0x2000 != 0 {
		if value.Kind == mofValueNull {
			return binary.LittleEndian.AppendUint32(output, math.MaxUint32), nil
		}
		if value.Kind != mofValueArray {
			return nil, fmt.Errorf("got %s, want array value", value.Kind)
		}
		offset, err := heap.addArray(value.Items, cimType&^0x2000)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.AppendUint32(output, offset), nil
	}
	switch base {
	case 8, 13, 101, 102:
		if value.Kind == mofValueNull {
			return binary.LittleEndian.AppendUint32(output, math.MaxUint32), nil
		}
		offset, err := heap.addIndirectValue(value, base)
		if err != nil {
			return nil, err
		}
		return binary.LittleEndian.AppendUint32(output, offset), nil
	case 11:
		if value.Kind == mofValueString || value.Kind == mofValueIdentifier {
			parsed, err := strconv.ParseBool(strings.ToLower(value.Text))
			if err != nil {
				return nil, fmt.Errorf("invalid boolean %q", value.Text)
			}
			value.Kind, value.Bool = mofValueBool, parsed
		}
		if value.Kind != mofValueBool {
			return nil, fmt.Errorf("got %s, want boolean value", value.Kind)
		}
		if value.Bool {
			return binary.LittleEndian.AppendUint16(output, math.MaxUint16), nil
		}
		return binary.LittleEndian.AppendUint16(output, 0), nil
	case 4:
		if value.Kind == mofValueString || value.Kind == mofValueIdentifier {
			parsed, err := strconv.ParseFloat(value.Text, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid real32 %q", value.Text)
			}
			value.Kind, value.Real = mofValueReal, parsed
		}
		if value.Kind != mofValueReal {
			return nil, fmt.Errorf("got %s, want real value", value.Kind)
		}
		return binary.LittleEndian.AppendUint32(output, math.Float32bits(float32(value.Real))), nil
	case 5:
		if value.Kind == mofValueString || value.Kind == mofValueIdentifier {
			parsed, err := strconv.ParseFloat(value.Text, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid real64 %q", value.Text)
			}
			value.Kind, value.Real = mofValueReal, parsed
		}
		if value.Kind != mofValueReal {
			return nil, fmt.Errorf("got %s, want real value", value.Kind)
		}
		return binary.LittleEndian.AppendUint64(output, math.Float64bits(value.Real)), nil
	case 2, 3, 16, 20:
		if value.Kind == mofValueString || value.Kind == mofValueIdentifier {
			parsed, err := strconv.ParseInt(value.Text, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid signed integer %q", value.Text)
			}
			value.Kind, value.Integer, value.Negative = mofValueInteger, parsed, parsed < 0
		}
		if value.Kind != mofValueInteger {
			return nil, fmt.Errorf("got %s, want integer value", value.Kind)
		}
		switch base {
		case 16:
			return append(output, byte(int8(value.Integer))), nil
		case 2:
			return binary.LittleEndian.AppendUint16(output, uint16(int16(value.Integer))), nil
		case 3:
			return binary.LittleEndian.AppendUint32(output, uint32(int32(value.Integer))), nil
		default:
			return binary.LittleEndian.AppendUint64(output, uint64(value.Integer)), nil
		}
	case 17, 18, 19, 21, 103:
		if value.Kind == mofValueString || value.Kind == mofValueIdentifier {
			parsed, err := strconv.ParseUint(value.Text, 0, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid unsigned integer %q", value.Text)
			}
			value.Kind, value.Unsigned = mofValueInteger, parsed
		}
		if value.Kind != mofValueInteger {
			return nil, fmt.Errorf("got %s, want integer value", value.Kind)
		}
		n := value.Unsigned
		if value.Negative {
			n = uint64(value.Integer)
		}
		switch base {
		case 17:
			return append(output, byte(n)), nil
		case 18, 103:
			return binary.LittleEndian.AppendUint16(output, uint16(n)), nil
		case 19:
			return binary.LittleEndian.AppendUint32(output, uint32(n)), nil
		default:
			return binary.LittleEndian.AppendUint64(output, n), nil
		}
	default:
		return nil, fmt.Errorf("unsupported CIM value type %#x", cimType)
	}
}

func wmiQualifierFlavor(qualifier mofQualifier, fallback byte) (byte, error) {
	flavors := qualifier.Flavors
	if len(flavors) == 0 {
		flavors = qualifier.DeclaredFlavors
	}
	if len(flavors) == 0 {
		return fallback, nil
	}
	var flavor byte
	var restricted, propagating, enableOverride, disableOverride bool
	for _, value := range flavors {
		switch strings.ToLower(value) {
		case "toinstance":
			flavor |= 0x01
			propagating = true
		case "tosubclass":
			flavor |= 0x02
			propagating = true
		case "enableoverride":
			enableOverride = true
		case "disableoverride":
			flavor |= 0x10
			disableOverride = true
		case "restricted":
			restricted = true
		case "amended", "translatable":
			flavor |= 0x80
		default:
			return 0, fmt.Errorf("qualifier %s has unknown flavor %q", qualifier.Name, value)
		}
	}
	if restricted && propagating {
		return 0, fmt.Errorf("qualifier %s combines Restricted with propagation", qualifier.Name)
	}
	if enableOverride && disableOverride {
		return 0, fmt.Errorf("qualifier %s combines EnableOverride with DisableOverride", qualifier.Name)
	}
	return flavor, nil
}

func buildWMIQualifierSet(qualifiers []mofQualifier, heap *wmiHeapBuilder) ([]byte, error) {
	entries := make([]byte, 0)
	for _, qualifier := range qualifiers {
		value := mofValue{Kind: mofValueBool, Bool: true}
		if len(qualifier.Values) == 0 && strings.EqualFold(qualifier.Name, "Values") {
			value = mofValue{Kind: mofValueArray}
		} else if len(qualifier.Values) > 1 {
			value = mofValue{Kind: mofValueArray, Items: append([]mofValue(nil), qualifier.Values...)}
		} else if len(qualifier.Values) == 1 {
			value = qualifier.Values[0]
		}
		var name uint32
		var defaultFlavor byte
		var err error
		switch {
		case strings.EqualFold(qualifier.Name, "CIMTYPE"):
			// Standard qualifier names occupy an intrinsic repository string
			// table. CIMTYPE is generated for every property and carries the
			// propagating/overridable flavor used by NT5 class merging.
			name = 0x8000000a
			defaultFlavor = 3
		case strings.EqualFold(qualifier.Name, "Key"):
			// Key participates in class identity and must use the intrinsic
			// qualifier ID so repository consumers recognize it during merge.
			name = 0x80000001
			defaultFlavor = 0x13
		case strings.EqualFold(qualifier.Name, "Read"):
			name = 0x80000003
		case strings.EqualFold(qualifier.Name, "Write"):
			name = 0x80000004
		case strings.EqualFold(qualifier.Name, "Volatile"):
			name = 0x80000005
		case strings.EqualFold(qualifier.Name, "Provider"):
			name = 0x80000006
			defaultFlavor = 3
		case strings.EqualFold(qualifier.Name, "Dynamic"):
			name = 0x80000007
			defaultFlavor = 3
		case strings.EqualFold(qualifier.Name, "Singleton"):
			// Singleton is inherited by derived classes and identifies the
			// otherwise keyless instance path "@". NT5 system classes store
			// it with the same propagating flavor as key qualifiers.
			name, err = heap.addString(qualifier.Name)
			defaultFlavor = 0x13
		case strings.EqualFold(qualifier.Name, "Values"):
			name, err = heap.addString(qualifier.Name)
		case strings.EqualFold(qualifier.Name, "SubType"):
			name, err = heap.addString(qualifier.Name)
			defaultFlavor = 3
		default:
			name, err = heap.addString(qualifier.Name)
		}
		if err != nil {
			return nil, err
		}
		flavor, err := wmiQualifierFlavor(qualifier, defaultFlavor)
		if err != nil {
			return nil, err
		}
		cimType := uint32(0x2008)
		if qualifier.DeclaredType != nil {
			cimType, _, _, err = wmiCIMType(*qualifier.DeclaredType)
		} else if value.Kind != mofValueArray || len(value.Items) != 0 || !strings.EqualFold(qualifier.Name, "Values") {
			cimType, _, err = wmiQualifierType(value)
		}
		if err != nil {
			return nil, fmt.Errorf("qualifier %s: %w", qualifier.Name, err)
		}
		entries = binary.LittleEndian.AppendUint32(entries, name)
		entries = append(entries, flavor)
		entries = binary.LittleEndian.AppendUint32(entries, cimType)
		entries, err = appendWMIValue(entries, value, cimType, heap)
		if err != nil {
			return nil, fmt.Errorf("qualifier %s: %w", qualifier.Name, err)
		}
	}
	output := binary.LittleEndian.AppendUint32(nil, uint32(4+len(entries)))
	return append(output, entries...), nil
}

func wmiCIMTypeQualifier(t mofType) mofQualifier {
	_, name, _, _ := wmiCIMType(t)
	return mofQualifier{Name: "CIMTYPE", Values: []mofValue{{Kind: mofValueString, Text: name}}}
}

func buildWMIDataTable(properties []mofFeature, values map[string]mofValue, inherited map[string]bool, heap *wmiHeapBuilder) ([]byte, []uint32, error) {
	nullnessSize := (len(properties)*2 + 7) / 8
	nullness := make([]byte, nullnessSize)
	for index := range nullness {
		// Four two-bit property states occupy each byte. Slots beyond the
		// declared property count are sentinels and must remain 11.
		nullness[index] = 0xff
	}
	setState := func(index int, state byte) {
		shift := uint((index % 4) * 2)
		nullness[index/4] = (nullness[index/4] &^ (3 << shift)) | state<<shift
	}
	data := make([]byte, 0)
	offsets := make([]uint32, len(properties))
	for index, property := range properties {
		cimType, _, size, err := wmiCIMType(property.Type)
		if err != nil {
			return nil, nil, fmt.Errorf("property %s: %w", property.Name, err)
		}
		offsets[index] = uint32(len(data))
		if inherited[strings.ToLower(property.Name)] {
			// Class default tables distinguish inherited storage from a local
			// property with no default. The former uses both state bits; the
			// reader then obtains the value and metadata from the parent class.
			setState(index, 3)
			data = append(data, make([]byte, size)...)
			for byteIndex := len(data) - size; byteIndex < len(data); byteIndex++ {
				data[byteIndex] = 0xff
			}
			continue
		}
		value, present := values[strings.ToLower(property.Name)]
		if !present && property.Value != nil {
			value, present = *property.Value, true
		}
		if !present || value.Kind == mofValueNull {
			setState(index, 1)
			data = append(data, make([]byte, size)...)
			for byteIndex := len(data) - size; byteIndex < len(data); byteIndex++ {
				data[byteIndex] = 0xff
			}
			continue
		}
		setState(index, 0)
		data, err = appendWMIValue(data, value, cimType, heap)
		if err != nil {
			return nil, nil, fmt.Errorf("property %s: %w", property.Name, err)
		}
	}
	return append(nullness, data...), offsets, nil
}

func buildWMIDerivation(ancestors []string) ([]byte, error) {
	output := make([]byte, 4)
	for _, ancestor := range ancestors {
		var compressed wmiHeapBuilder
		if _, err := compressed.addString(ancestor); err != nil {
			return nil, err
		}
		output = append(output, compressed.data...)
		output = binary.LittleEndian.AppendUint32(output, uint32(len(compressed.data)))
	}
	binary.LittleEndian.PutUint32(output, uint32(len(output)))
	return output, nil
}

func buildWMIClassPart(class mofClass, ancestors []string, properties []mofFeature, depth uint32) ([]byte, error) {
	var heap wmiHeapBuilder
	className, err := heap.addString(class.Name)
	if err != nil {
		return nil, err
	}
	qualifiers, err := buildWMIQualifierSet(class.Qualifiers, &heap)
	if err != nil {
		return nil, fmt.Errorf("class %s qualifiers: %w", class.Name, err)
	}
	var localProperties []mofFeature
	for _, feature := range class.Features {
		if feature.Kind == "property" {
			localProperties = append(localProperties, feature)
		}
	}
	sort.SliceStable(localProperties, func(i, j int) bool {
		return strings.ToLower(localProperties[i].Name) < strings.ToLower(localProperties[j].Name)
	})
	propertyIndexes := make(map[string]int, len(properties))
	for index, property := range properties {
		propertyIndexes[strings.ToLower(property.Name)] = index
	}
	inherited := make(map[string]bool, len(properties))
	for _, property := range properties {
		inherited[strings.ToLower(property.Name)] = true
	}
	for _, property := range localProperties {
		delete(inherited, strings.ToLower(property.Name))
	}
	dataTable, dataOffsets, err := buildWMIDataTable(properties, nil, inherited, &heap)
	if err != nil {
		return nil, fmt.Errorf("class %s: %w", class.Name, err)
	}
	type propertyRecord struct {
		name, descriptor uint32
		sortName         string
	}
	records := make([]propertyRecord, len(localProperties))
	for index, property := range localProperties {
		propertyIndex, ok := propertyIndexes[strings.ToLower(property.Name)]
		if !ok {
			return nil, fmt.Errorf("class %s property %s is absent from its inherited layout", class.Name, property.Name)
		}
		if propertyIndex > math.MaxUint16 {
			return nil, fmt.Errorf("class %s property %s index exceeds 16 bits", class.Name, property.Name)
		}
		name, err := heap.addString(property.Name)
		if err != nil {
			return nil, err
		}
		cimType, _, _, err := wmiCIMType(property.Type)
		if err != nil {
			return nil, fmt.Errorf("class %s property %s: %w", class.Name, property.Name, err)
		}
		propertyQualifiers := append([]mofQualifier{wmiCIMTypeQualifier(property.Type)}, property.Qualifiers...)
		// Property descriptors canonically follow their name in the object
		// heap. Reserve the descriptor before adding qualifier payloads, then
		// backfill it with handles into the now-complete heap. FastProx accepts
		// the handles as offsets, but its force-update path also expects this
		// physical ordering when it merges an existing class.
		var sizingHeap wmiHeapBuilder
		sizingQualifierSet, err := buildWMIQualifierSet(propertyQualifiers, &sizingHeap)
		if err != nil {
			return nil, fmt.Errorf("class %s property %s qualifiers: %w", class.Name, property.Name, err)
		}
		if len(heap.data) > math.MaxInt32 {
			return nil, fmt.Errorf("class %s heap is too large", class.Name)
		}
		descriptor := uint32(len(heap.data))
		descriptorSize := 14 + len(sizingQualifierSet)
		heap.data = append(heap.data, make([]byte, descriptorSize)...)
		qualifierSet, err := buildWMIQualifierSet(propertyQualifiers, &heap)
		if err != nil {
			return nil, fmt.Errorf("class %s property %s qualifiers: %w", class.Name, property.Name, err)
		}
		descriptorData := heap.data[int(descriptor) : int(descriptor)+descriptorSize]
		binary.LittleEndian.PutUint32(descriptorData[0:4], cimType)
		binary.LittleEndian.PutUint16(descriptorData[4:6], uint16(propertyIndex))
		binary.LittleEndian.PutUint32(descriptorData[6:10], dataOffsets[propertyIndex])
		binary.LittleEndian.PutUint32(descriptorData[10:14], depth)
		copy(descriptorData[14:], qualifierSet)
		records[index] = propertyRecord{name: name, descriptor: descriptor, sortName: strings.ToLower(property.Name)}
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].sortName < records[j].sortName
	})
	lookup := binary.LittleEndian.AppendUint32(nil, uint32(len(records)))
	for _, record := range records {
		lookup = binary.LittleEndian.AppendUint32(lookup, record.name)
		lookup = binary.LittleEndian.AppendUint32(lookup, record.descriptor)
	}
	derivation, err := buildWMIDerivation(ancestors)
	if err != nil {
		return nil, err
	}
	heapBlock, err := heap.block()
	if err != nil {
		return nil, err
	}
	classPart := make([]byte, 13)
	classPart[4] = 0
	binary.LittleEndian.PutUint32(classPart[5:9], className)
	// This field is the byte width of the class's default-value table, not a
	// property count. Readers use it to lay out the class before interpreting
	// the property descriptors.
	binary.LittleEndian.PutUint32(classPart[9:13], uint32(len(dataTable)))
	classPart = append(classPart, derivation...)
	classPart = append(classPart, qualifiers...)
	classPart = append(classPart, lookup...)
	classPart = append(classPart, dataTable...)
	classPart = append(classPart, heapBlock...)
	binary.LittleEndian.PutUint32(classPart[:4], uint32(len(classPart)))
	return classPart, nil
}

func hasMOFQualifier(qualifiers []mofQualifier, name string) bool {
	for _, qualifier := range qualifiers {
		if strings.EqualFold(qualifier.Name, name) {
			return true
		}
	}
	return false
}

type wmiObjectContext struct {
	serverName string
	namespace  string
}

func buildWMIParameterClassPart(method mofFeature, output bool, context wmiObjectContext) ([]byte, error) {
	class := mofClass{
		Name:       "__PARAMETERS",
		Qualifiers: []mofQualifier{{Name: "abstract"}},
	}
	for parameterIndex, parameter := range method.Parameters {
		include := hasMOFQualifier(parameter.Qualifiers, "out")
		if !output {
			include = hasMOFQualifier(parameter.Qualifiers, "in") || !include
		}
		if !include {
			continue
		}
		qualifiers := append([]mofQualifier(nil), parameter.Qualifiers...)
		if !hasMOFQualifier(qualifiers, "ID") {
			qualifiers = append(qualifiers, mofQualifier{
				Name: "ID",
				Values: []mofValue{{
					Kind:     mofValueInteger,
					Unsigned: uint64(parameterIndex),
				}},
				Flavors: []string{"ToInstance", "DisableOverride"},
			})
		}
		class.Features = append(class.Features, mofFeature{
			Kind:       "property",
			Name:       parameter.Name,
			Type:       parameter.Type,
			Qualifiers: qualifiers,
			Value:      parameter.Default,
		})
	}
	if output && !strings.EqualFold(method.Type.Name, "void") {
		class.Features = append(class.Features, mofFeature{
			Kind:       "property",
			Name:       "ReturnValue",
			Type:       method.Type,
			Qualifiers: []mofQualifier{{Name: "Out"}},
		})
	}
	if len(class.Features) == 0 {
		// Method descriptors always reference an input and output parameter
		// object. FastProx represents an absent side with a zero-length object
		// rather than a sentinel heap handle.
		return make([]byte, 4), nil
	}
	properties := make([]mofFeature, 0, len(class.Features))
	for _, feature := range class.Features {
		if feature.Kind == "property" {
			properties = append(properties, feature)
		}
	}
	classPart, err := buildWMIClassPart(class, nil, properties, 0)
	if err != nil {
		return nil, err
	}
	return buildWMIEmbeddedClassObject(classPart, context), nil
}

func buildWMIEmbeddedClassObject(classPart []byte, context wmiObjectContext) []byte {
	// Embedded method parameter objects contain both an empty instance schema
	// and the class schema. Repository classes carry their server and namespace
	// path so FastProx can resolve parameter schemas without reopening them.
	emptyClassPart := []byte{
		0x1d, 0, 0, 0,
		0,
		0xff, 0xff, 0xff, 0xff,
		0, 0, 0, 0,
		4, 0, 0, 0,
		4, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0x80,
	}
	emptyMethodPart := []byte{
		12, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0x80,
	}
	var path []byte
	pathFlag := byte(1)
	if context.serverName != "" || context.namespace != "" {
		var heap wmiHeapBuilder
		_, _ = heap.addString(context.serverName)
		_, _ = heap.addString(context.namespace)
		path = heap.data
		pathFlag = 5
	}
	payload := make([]byte, 0, 1+len(path)+len(emptyClassPart)+len(emptyMethodPart)+len(classPart)+len(emptyMethodPart))
	payload = append(payload, pathFlag)
	payload = append(payload, path...)
	payload = append(payload, emptyClassPart...)
	payload = append(payload, emptyMethodPart...)
	payload = append(payload, classPart...)
	payload = append(payload, emptyMethodPart...)
	output := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	return append(output, payload...)
}

func buildWMIMethodPart(class mofClass, depth uint32, context wmiObjectContext) ([]byte, error) {
	var methods []mofFeature
	for _, feature := range class.Features {
		if feature.Kind == "method" {
			methods = append(methods, feature)
		}
	}
	if len(methods) > math.MaxUint16 {
		return nil, fmt.Errorf("class %s has too many methods", class.Name)
	}
	var heap wmiHeapBuilder
	descriptors := make([]byte, 0, len(methods)*24)
	for _, method := range methods {
		name, err := heap.addString(method.Name)
		if err != nil {
			return nil, err
		}
		var sizingHeap wmiHeapBuilder
		sizingQualifiers, err := buildWMIQualifierSet(method.Qualifiers, &sizingHeap)
		if err != nil {
			return nil, fmt.Errorf("class %s method %s qualifiers: %w", class.Name, method.Name, err)
		}
		qualifierHandle := uint32(len(heap.data))
		heap.data = append(heap.data, make([]byte, len(sizingQualifiers))...)
		qualifiers, err := buildWMIQualifierSet(method.Qualifiers, &heap)
		if err != nil {
			return nil, fmt.Errorf("class %s method %s qualifiers: %w", class.Name, method.Name, err)
		}
		copy(heap.data[qualifierHandle:qualifierHandle+uint32(len(qualifiers))], qualifiers)
		input, err := buildWMIParameterClassPart(method, false, context)
		if err != nil {
			return nil, fmt.Errorf("class %s method %s input: %w", class.Name, method.Name, err)
		}
		inputHandle, err := heap.addBlob(input)
		if err != nil {
			return nil, err
		}
		output, err := buildWMIParameterClassPart(method, true, context)
		if err != nil {
			return nil, fmt.Errorf("class %s method %s output: %w", class.Name, method.Name, err)
		}
		outputHandle, err := heap.addBlob(output)
		if err != nil {
			return nil, err
		}
		descriptors = binary.LittleEndian.AppendUint32(descriptors, name)
		descriptors = append(descriptors, 0, 0, 0, 0)
		descriptors = binary.LittleEndian.AppendUint32(descriptors, depth)
		descriptors = binary.LittleEndian.AppendUint32(descriptors, qualifierHandle)
		descriptors = binary.LittleEndian.AppendUint32(descriptors, inputHandle)
		descriptors = binary.LittleEndian.AppendUint32(descriptors, outputHandle)
	}
	heapBlock, err := heap.block()
	if err != nil {
		return nil, err
	}
	methodPart := make([]byte, 8)
	binary.LittleEndian.PutUint16(methodPart[4:6], uint16(len(methods)))
	methodPart = append(methodPart, descriptors...)
	methodPart = append(methodPart, heapBlock...)
	binary.LittleEndian.PutUint32(methodPart[:4], uint32(len(methodPart)))
	return methodPart, nil
}

func buildWMIClassRecord(class mofClass, ancestors []string, properties []mofFeature, depth uint32, revision uint64, context wmiObjectContext) ([]byte, error) {
	classPart, err := buildWMIClassPart(class, ancestors, properties, depth)
	if err != nil {
		return nil, err
	}

	methodPart, err := buildWMIMethodPart(class, depth, context)
	if err != nil {
		return nil, err
	}

	output := binary.LittleEndian.AppendUint32(nil, uint32(len(class.Super)))
	for _, unit := range utf16.Encode([]rune(class.Super)) {
		output = binary.LittleEndian.AppendUint16(output, unit)
	}
	output = binary.LittleEndian.AppendUint64(output, revision)
	output = append(output, classPart...)
	return append(output, methodPart...), nil
}

func wmiUpperUTF16MD5(value string) string {
	var encoded []byte
	for _, unit := range utf16.Encode([]rune(strings.ToUpper(value))) {
		encoded = binary.LittleEndian.AppendUint16(encoded, unit)
	}
	return strings.ToUpper(fmt.Sprintf("%x", md5.Sum(encoded)))
}

func appendWMICountedUTF16(output []byte, value string) []byte {
	units := utf16.Encode([]rune(value))
	output = binary.LittleEndian.AppendUint32(output, uint32(len(units)))
	for _, unit := range units {
		output = binary.LittleEndian.AppendUint16(output, unit)
	}
	return output
}

func buildWMIReferenceProjection(namespace, className, propertyName, sourcePath string) []byte {
	var output []byte
	output = appendWMICountedUTF16(output, namespace)
	output = appendWMICountedUTF16(output, className)
	output = appendWMICountedUTF16(output, strings.ToLower(propertyName))
	output = appendWMICountedUTF16(output, sourcePath)
	return binary.LittleEndian.AppendUint64(output, 0)
}

func buildWMIInstancePart(instance mofInstance, class mofClass, properties []mofFeature, embeddedInstance func(mofInstance) ([]byte, error)) ([]byte, error) {
	values := make(map[string]mofValue, len(instance.Properties))
	for _, property := range instance.Properties {
		values[strings.ToLower(property.Name)] = property.Value
	}
	known := make(map[string]bool, len(properties))
	for _, property := range properties {
		known[strings.ToLower(property.Name)] = true
	}
	for _, property := range instance.Properties {
		if !known[strings.ToLower(property.Name)] {
			return nil, fmt.Errorf("instance of %s assigns undeclared property %s", instance.Class, property.Name)
		}
	}
	heap := wmiHeapBuilder{embeddedInstance: embeddedInstance}
	// Repository instances use the canonical spelling from the class
	// declaration. MOF references are case-insensitive, but NT5's namespace
	// loader compares intrinsic class names from the serialized object body.
	className, err := heap.addString(class.Name)
	if err != nil {
		return nil, err
	}
	dataTable, _, err := buildWMIDataTable(properties, values, nil, &heap)
	if err != nil {
		return nil, fmt.Errorf("instance of %s: %w", instance.Class, err)
	}
	qualifiers, err := buildWMIQualifierSet(instance.Qualifiers, &heap)
	if err != nil {
		return nil, fmt.Errorf("instance of %s qualifiers: %w", instance.Class, err)
	}
	heapBlock, err := heap.block()
	if err != nil {
		return nil, err
	}
	body := binary.LittleEndian.AppendUint32(nil, className)
	body = append(body, 0)
	body = append(body, dataTable...)
	body = append(body, qualifiers...)
	body = append(body, 1)
	body = append(body, heapBlock...)
	output := binary.LittleEndian.AppendUint32(nil, uint32(4+len(body)))
	return append(output, body...), nil
}

func buildWMIEmbeddedInstanceObject(classPart, instancePart []byte) []byte {
	payload := make([]byte, 0, 1+len(classPart)+len(instancePart))
	payload = append(payload, 2)
	payload = append(payload, classPart...)
	payload = append(payload, instancePart...)
	output := binary.LittleEndian.AppendUint32(nil, uint32(len(payload)))
	return append(output, payload...)
}

func buildWMIInstanceRecord(instance mofInstance, class mofClass, properties []mofFeature, revision, classRevision uint64, embeddedInstance func(mofInstance) ([]byte, error)) ([]byte, string, error) {
	instancePart, err := buildWMIInstancePart(instance, class, properties, embeddedInstance)
	if err != nil {
		return nil, "", err
	}

	classHash := wmiUpperUTF16MD5(class.Name)
	var output []byte
	for _, unit := range utf16.Encode([]rune(classHash)) {
		output = binary.LittleEndian.AppendUint16(output, unit)
	}
	output = binary.LittleEndian.AppendUint64(output, revision)
	output = binary.LittleEndian.AppendUint64(output, classRevision)
	output = append(output, instancePart...)

	values := make(map[string]mofValue, len(instance.Properties))
	for _, property := range instance.Properties {
		values[strings.ToLower(property.Name)] = property.Value
	}
	var key strings.Builder
	for _, property := range properties {
		isKey := false
		for _, qualifier := range property.Qualifiers {
			if strings.EqualFold(qualifier.Name, "key") {
				isKey = true
				break
			}
		}
		if !isKey {
			continue
		}
		value, ok := values[strings.ToLower(property.Name)]
		if !ok && property.Value != nil {
			value, ok = *property.Value, true
		}
		if !ok {
			return nil, "", fmt.Errorf("instance of %s has no value for key %s", instance.Class, property.Name)
		}
		key.WriteString(value.Text)
	}
	if key.Len() == 0 && hasMOFQualifier(class.Qualifiers, "singleton") {
		key.WriteByte('@')
	}
	return output, wmiUpperUTF16MD5(key.String()), nil
}
