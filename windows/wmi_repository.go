package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"hash/crc32"
	"io"
	"sort"
	"strings"

	"go.starlark.net/starlark"
)

const (
	wmiRepositoryPageSize      = 8192
	wmiRepositoryConfigVersion = 6
	// Revisions are FILETIME values. A fixed epoch keeps generated repositories
	// reproducible while preserving the monotonic class/instance identity that
	// repository readers require.
	wmiRepositoryRevisionBase = uint64(125911584000000000) // 2000-01-01 UTC
	wmiMappingStart           = 0x0000abcd
	wmiMappingEnd             = 0x0000dcba
	wmiIndexPageSignature     = 0x0000accc
	wmiIndexMetaSignature     = 0x0000addd
)

type wmiMappingSection struct {
	generation    uint32
	physicalPages uint32
	base          []uint32
	free          []uint32
}

type wmiRepositoryMapping struct {
	objects wmiMappingSection
	index   wmiMappingSection
}

type wmiRepositoryRecord struct {
	logicalPage uint32
	id          uint32
	data        []byte
}

type wmiRepositoryIndexPage struct {
	id       uint32
	children []uint32
	keys     []string
}

type wmiRepositoryFile struct {
	mapping wmiRepositoryMapping
	records []wmiRepositoryRecord
	pages   []wmiRepositoryIndexPage
	files   starlark.StringDict
}

func buildWMIRepositoryConfig() []byte {
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[4:8], 1)
	binary.LittleEndian.PutUint32(data[12:16], wmiRepositoryConfigVersion)
	return data
}

func wmiRepositorySource(files *starlark.Dict, name string) (starfile.File, error) {
	for _, candidate := range []string{name, "FS/" + name, `FS\` + name} {
		value, found, err := files.Get(starlark.String(candidate))
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		file, ok := value.(starfile.File)
		if !ok {
			return nil, fmt.Errorf("wmi_repository: %s has type %s, want file", candidate, value.Type())
		}
		return file, nil
	}
	return nil, fmt.Errorf("wmi_repository: missing %s", name)
}

func wmiRepositoryBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var files *starlark.Dict
	var documents *starlark.List
	defaultNamespace := `root\cimv2`
	serverName := ""
	if err := starlark.UnpackArgs(
		"wmi_repository",
		args,
		kwargs,
		"files?", &files,
		"documents?", &documents,
		"default_namespace?", &defaultNamespace,
		"server_name?", &serverName,
	); err != nil {
		return nil, err
	}
	if (files == nil) == (documents == nil) {
		return nil, fmt.Errorf("wmi_repository: specify exactly one of files or documents")
	}
	if documents != nil {
		mofs := make([]*mofDocument, documents.Len())
		for index := 0; index < documents.Len(); index++ {
			file, ok := documents.Index(index).(*mofFile)
			if !ok {
				return nil, fmt.Errorf("wmi_repository: documents[%d] has type %s, want windows.mof", index, documents.Index(index).Type())
			}
			mofs[index] = file.document
		}
		return buildWMIRepositoryDocumentsWithOptions(mofs, defaultNamespace, wmiRepositoryOptions{serverName: serverName})
	}
	required := []string{"MAPPING.VER", "MAPPING1.MAP", "MAPPING2.MAP", "OBJECTS.DATA", "INDEX.BTR"}
	sources := make(starlark.StringDict, len(required))
	for _, name := range required {
		file, err := wmiRepositorySource(files, name)
		if err != nil {
			return nil, err
		}
		sources[name] = file
	}
	versionData, err := readWMIRepositoryFile(sources["MAPPING.VER"].(starfile.File), "MAPPING.VER")
	if err != nil {
		return nil, err
	}
	if len(versionData) != 4 {
		return nil, fmt.Errorf("wmi_repository: MAPPING.VER must contain one uint32")
	}
	version := binary.LittleEndian.Uint32(versionData)
	if version != 1 && version != 2 {
		return nil, fmt.Errorf("wmi_repository: invalid active mapping version %d", version)
	}
	mappingName := fmt.Sprintf("MAPPING%d.MAP", version)
	mappingData, err := readWMIRepositoryFile(sources[mappingName].(starfile.File), mappingName)
	if err != nil {
		return nil, err
	}
	mapping, err := parseWMIRepositoryMapping(mappingData)
	if err != nil {
		return nil, err
	}
	objectsData, err := readWMIRepositoryFile(sources["OBJECTS.DATA"].(starfile.File), "OBJECTS.DATA")
	if err != nil {
		return nil, err
	}
	indexData, err := readWMIRepositoryFile(sources["INDEX.BTR"].(starfile.File), "INDEX.BTR")
	if err != nil {
		return nil, err
	}
	if uint64(mapping.objects.physicalPages)*wmiRepositoryPageSize != uint64(len(objectsData)) {
		return nil, fmt.Errorf("wmi_repository: OBJECTS.DATA has %d pages, mapping declares %d", len(objectsData)/wmiRepositoryPageSize, mapping.objects.physicalPages)
	}
	if uint64(mapping.index.physicalPages)*wmiRepositoryPageSize != uint64(len(indexData)) {
		return nil, fmt.Errorf("wmi_repository: INDEX.BTR has %d pages, mapping declares %d", len(indexData)/wmiRepositoryPageSize, mapping.index.physicalPages)
	}
	records, err := parseWMIRepositoryRecords(mapping.objects, objectsData)
	if err != nil {
		return nil, err
	}
	pages, err := parseWMIRepositoryIndex(mapping.index, indexData)
	if err != nil {
		return nil, err
	}
	return &wmiRepositoryFile{mapping: mapping, records: records, pages: pages, files: sources}, nil
}

type wmiPendingRecord struct {
	namespace          string
	kind               string
	className          string
	superclass         string
	references         []string
	instanceKey        string
	keyClassName       string
	canonicalPath      string
	instanceReferences []wmiInstanceReference
	referenceClassName string
	referencedKey      string
	relationKey        string
	data               []byte
}

type wmiInstanceReference struct {
	propertyName string
	className    string
	targetPath   string
}

func normalizeWMINamespace(value, fallback string) string {
	value = strings.ReplaceAll(value, "/", `\`)
	value = strings.ReplaceAll(value, `\\`, `\`)
	value = strings.TrimSpace(value)
	for _, prefix := range []string{`\.\`, `.\`} {
		if strings.HasPrefix(value, prefix) {
			value = strings.TrimPrefix(value, prefix)
		}
	}
	value = strings.Trim(value, `\`)
	if value == "" {
		value = fallback
	}
	return strings.ToUpper(value)
}

func wmiLocalizedParentNamespace(namespace string) string {
	separator := strings.LastIndex(namespace, `\`)
	if separator < 0 {
		return ""
	}
	component := namespace[separator+1:]
	if len(component) <= 3 || !strings.EqualFold(component[:3], "MS_") {
		return ""
	}
	for _, character := range component[3:] {
		if !((character >= '0' && character <= '9') || (character >= 'A' && character <= 'F') || (character >= 'a' && character <= 'f')) {
			return ""
		}
	}
	return namespace[:separator]
}

func canonicalWMIReferencePath(value, namespace string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, `\\.\`) {
		return value
	}
	if strings.HasPrefix(value, `\`) {
		return `\` + value
	}
	return `\\.\` + namespace + ":" + value
}

func cloneMOFValue(value mofValue) mofValue {
	value.Items = append([]mofValue(nil), value.Items...)
	for index := range value.Items {
		value.Items[index] = cloneMOFValue(value.Items[index])
	}
	if value.Instance != nil {
		instance := *value.Instance
		value.Instance = &instance
	}
	return value
}

func resolveWMIQualifiers(qualifiers []mofQualifier, namespace string, declarations map[string]mofQualifierDeclaration) []mofQualifier {
	resolved := append([]mofQualifier(nil), qualifiers...)
	for index := range resolved {
		qualifier := &resolved[index]
		identity := namespace + "\x00" + strings.ToUpper(qualifier.Name)
		declaration, found := declarations[identity]
		if !found {
			if parent := wmiLocalizedParentNamespace(namespace); parent != "" {
				declaration, found = declarations[parent+"\x00"+strings.ToUpper(qualifier.Name)]
			}
		}
		if !found {
			continue
		}
		if declaration.Type.Name != "" || declaration.Type.Reference != "" {
			declaredType := declaration.Type
			qualifier.DeclaredType = &declaredType
		}
		qualifier.DeclaredFlavors = append([]string(nil), declaration.Flavors...)
		if len(qualifier.Values) == 0 && declaration.Default != nil {
			qualifier.Values = []mofValue{cloneMOFValue(*declaration.Default)}
		}
	}
	return resolved
}

func resolveWMIClassQualifiers(class mofClass, namespace string, declarations map[string]mofQualifierDeclaration) mofClass {
	class.Qualifiers = resolveWMIQualifiers(class.Qualifiers, namespace, declarations)
	class.Features = append([]mofFeature(nil), class.Features...)
	for featureIndex := range class.Features {
		feature := &class.Features[featureIndex]
		feature.Qualifiers = resolveWMIQualifiers(feature.Qualifiers, namespace, declarations)
		feature.Parameters = append([]mofParameter(nil), feature.Parameters...)
		for parameterIndex := range feature.Parameters {
			parameter := &feature.Parameters[parameterIndex]
			parameter.Qualifiers = resolveWMIQualifiers(parameter.Qualifiers, namespace, declarations)
		}
	}
	return class
}

func buildWMIRepositoryDocuments(documents []*mofDocument, defaultNamespace string) (*wmiRepositoryFile, error) {
	return buildWMIRepositoryDocumentsWithOptions(documents, defaultNamespace, wmiRepositoryOptions{})
}

type wmiRepositoryOptions struct {
	serverName string
}

func buildWMIRepositoryDocumentsWithOptions(documents []*mofDocument, defaultNamespace string, options wmiRepositoryOptions) (*wmiRepositoryFile, error) {
	defaultNamespace = normalizeWMINamespace(defaultNamespace, `ROOT\CIMV2`)
	type classEntry struct {
		class     mofClass
		namespace string
	}
	type propertyEntry struct {
		feature   mofFeature
		declaring classEntry
	}
	classes := make(map[string]classEntry)
	classOrder := make(map[string]int)
	var ordered []classEntry
	documentInstances := make([][]mofInstance, len(documents))
	declarations := make(map[string]mofQualifierDeclaration)
	for _, document := range documents {
		for _, declaration := range document.Qualifiers {
			namespace := normalizeWMINamespace(declaration.Namespace, defaultNamespace)
			declarations[namespace+"\x00"+strings.ToUpper(declaration.Name)] = declaration
		}
	}
	for documentIndex, document := range documents {
		for _, class := range document.Classes {
			namespace := normalizeWMINamespace(class.Namespace, defaultNamespace)
			class = resolveWMIClassQualifiers(class, namespace, declarations)
			identity := namespace + "\x00" + strings.ToUpper(class.Name)
			entry := classEntry{class: class, namespace: namespace}
			classes[identity] = entry
			if index, exists := classOrder[identity]; exists {
				ordered[index] = entry
			} else {
				classOrder[identity] = len(ordered)
				ordered = append(ordered, entry)
			}
		}
		documentInstances[documentIndex] = append([]mofInstance(nil), document.Instances...)
		for instanceIndex := range documentInstances[documentIndex] {
			instance := &documentInstances[documentIndex][instanceIndex]
			namespace := normalizeWMINamespace(instance.Namespace, defaultNamespace)
			instance.Qualifiers = resolveWMIQualifiers(instance.Qualifiers, namespace, declarations)
		}
	}

	lookupClass := func(namespace, name string) (classEntry, bool) {
		identity := namespace + "\x00" + strings.ToUpper(name)
		if entry, ok := classes[identity]; ok {
			return entry, true
		}
		if localizedParent := wmiLocalizedParentNamespace(namespace); localizedParent != "" {
			identity = localizedParent + "\x00" + strings.ToUpper(name)
			if entry, ok := classes[identity]; ok {
				return entry, true
			}
		}
		entry, ok := classes[`__SYSTEMCLASS`+"\x00"+strings.ToUpper(name)]
		return entry, ok
	}

	classChain := func(entry classEntry) ([]classEntry, error) {
		chain := []classEntry{entry}
		seen := map[string]bool{entry.namespace + "\x00" + strings.ToUpper(entry.class.Name): true}
		currentNamespace := entry.namespace
		for superclass := entry.class.Super; superclass != ""; {
			parent, ok := lookupClass(currentNamespace, superclass)
			if !ok {
				return nil, fmt.Errorf("class %s in %s has unresolved superclass %s", entry.class.Name, entry.namespace, superclass)
			}
			identity := parent.namespace + "\x00" + strings.ToUpper(parent.class.Name)
			if seen[identity] {
				return nil, fmt.Errorf("wmi repository: inheritance cycle at %s in %s", parent.class.Name, parent.namespace)
			}
			seen[identity] = true
			chain = append(chain, parent)
			currentNamespace = parent.namespace
			superclass = parent.class.Super
		}
		return chain, nil
	}
	classPropertyEntries := func(entry classEntry) ([]propertyEntry, error) {
		chain, err := classChain(entry)
		if err != nil {
			return nil, err
		}
		var properties []propertyEntry
		indexes := make(map[string]int)
		for index := len(chain) - 1; index >= 0; index-- {
			for _, feature := range chain[index].class.Features {
				if feature.Kind == "property" {
					name := strings.ToLower(feature.Name)
					property := propertyEntry{feature: feature, declaring: chain[index]}
					if propertyIndex, exists := indexes[name]; exists {
						properties[propertyIndex] = property
					} else {
						indexes[name] = len(properties)
						properties = append(properties, property)
					}
				}
			}
		}
		return properties, nil
	}
	classProperties := func(entry classEntry) ([]mofFeature, error) {
		entries, err := classPropertyEntries(entry)
		if err != nil {
			return nil, err
		}
		properties := make([]mofFeature, len(entries))
		for index := range entries {
			properties[index] = entries[index].feature
		}
		return properties, nil
	}
	formatReferenceValue := func(value mofValue) (string, error) {
		switch value.Kind {
		case mofValueString, mofValueIdentifier, mofValueAlias:
			return `"` + strings.ReplaceAll(strings.ReplaceAll(value.Text, `\`, `\\`), `"`, `\"`) + `"`, nil
		case mofValueBool:
			if value.Bool {
				return "TRUE", nil
			}
			return "FALSE", nil
		case mofValueInteger:
			if value.Negative {
				return fmt.Sprintf("%d", value.Integer), nil
			}
			return fmt.Sprintf("%d", value.Unsigned), nil
		default:
			return "", fmt.Errorf("unsupported key value kind %s", value.Kind)
		}
	}
	var instancePath func(mofInstance, map[string]mofInstance) (string, error)
	instancePath = func(instance mofInstance, aliases map[string]mofInstance) (string, error) {
		namespace := normalizeWMINamespace(instance.Namespace, defaultNamespace)
		entry, ok := lookupClass(namespace, instance.Class)
		if !ok {
			return "", fmt.Errorf("alias instance class %s is not declared in %s", instance.Class, namespace)
		}
		properties, err := classProperties(entry)
		if err != nil {
			return "", err
		}
		values := make(map[string]mofValue, len(instance.Properties))
		for _, assignment := range instance.Properties {
			values[strings.ToLower(assignment.Name)] = assignment.Value
		}
		var keys []string
		for _, property := range properties {
			if !hasMOFQualifier(property.Qualifiers, "key") {
				continue
			}
			value, found := values[strings.ToLower(property.Name)]
			if !found && property.Value != nil {
				value, found = *property.Value, true
			}
			if !found {
				return "", fmt.Errorf("instance of %s has no value for key %s", instance.Class, property.Name)
			}
			if value.Kind == mofValueAlias {
				target, found := aliases[strings.ToLower(value.Text)]
				if !found {
					return "", fmt.Errorf("unknown instance alias $%s", value.Text)
				}
				path, err := instancePath(target, aliases)
				if err != nil {
					return "", err
				}
				value = mofValue{Kind: mofValueString, Text: path}
			}
			encoded, err := formatReferenceValue(value)
			if err != nil {
				return "", err
			}
			keys = append(keys, property.Name+"="+encoded)
		}
		path := instance.Class
		if len(keys) != 0 {
			path += "." + strings.Join(keys, ",")
		}
		return `\\.\` + namespace + ":" + path, nil
	}
	var resolveValue func(mofValue, map[string]mofInstance) (mofValue, error)
	resolveValue = func(value mofValue, aliases map[string]mofInstance) (mofValue, error) {
		if value.Kind == mofValueAlias {
			target, found := aliases[strings.ToLower(value.Text)]
			if !found {
				return mofValue{}, fmt.Errorf("unknown instance alias $%s", value.Text)
			}
			path, err := instancePath(target, aliases)
			if err != nil {
				return mofValue{}, err
			}
			value.Kind, value.Text = mofValueString, path
			return value, nil
		}
		if value.Kind == mofValueArray {
			for index := range value.Items {
				resolved, err := resolveValue(value.Items[index], aliases)
				if err != nil {
					return mofValue{}, err
				}
				value.Items[index] = resolved
			}
		}
		if value.Kind == mofValueInstance && value.Instance != nil {
			instance := *value.Instance
			instance.Properties = append([]mofPropertyAssignment(nil), instance.Properties...)
			for index := range instance.Properties {
				resolved, err := resolveValue(instance.Properties[index].Value, aliases)
				if err != nil {
					return mofValue{}, err
				}
				instance.Properties[index].Value = resolved
			}
			value.Instance = &instance
		}
		return value, nil
	}
	var instances []mofInstance
	for _, sourceInstances := range documentInstances {
		aliases := make(map[string]mofInstance)
		for _, instance := range sourceInstances {
			if instance.Alias != "" {
				aliases[strings.ToLower(instance.Alias)] = instance
			}
		}
		for _, instance := range sourceInstances {
			for index := range instance.Properties {
				value, err := resolveValue(instance.Properties[index].Value, aliases)
				if err != nil {
					return nil, fmt.Errorf("wmi repository: instance of %s property %s: %w", instance.Class, instance.Properties[index].Name, err)
				}
				instance.Properties[index].Value = value
			}
			instances = append(instances, instance)
		}
	}

	var pending []wmiPendingRecord
	classRevisions := make(map[string]uint64, len(ordered))
	nextRevision := wmiRepositoryRevisionBase
	for _, entry := range ordered {
		nextRevision++
		revision := nextRevision
		chain, err := classChain(entry)
		if err != nil {
			return nil, err
		}
		var ancestors []string
		if entry.class.Super != "" {
			ancestors = []string{entry.class.Super}
		}
		properties, err := classProperties(entry)
		if err != nil {
			return nil, err
		}
		record, err := buildWMIClassRecord(
			entry.class,
			ancestors,
			properties,
			uint32(len(chain)-1),
			revision,
			wmiObjectContext{serverName: options.serverName, namespace: entry.namespace},
		)
		if err != nil {
			return nil, fmt.Errorf("wmi repository: %s/%s: %w", entry.namespace, entry.class.Name, err)
		}
		var references []string
		seenReferences := make(map[string]bool)
		for _, feature := range entry.class.Features {
			if feature.Kind != "property" || feature.Type.Reference == "" {
				continue
			}
			identity := strings.ToUpper(feature.Type.Reference)
			if seenReferences[identity] {
				continue
			}
			seenReferences[identity] = true
			references = append(references, feature.Type.Reference)
		}
		sort.Slice(references, func(i, j int) bool {
			return strings.ToUpper(references[i]) < strings.ToUpper(references[j])
		})
		classRevisions[entry.namespace+"\x00"+strings.ToUpper(entry.class.Name)] = revision
		pending = append(pending, wmiPendingRecord{
			namespace:  entry.namespace,
			kind:       "class",
			className:  entry.class.Name,
			superclass: entry.class.Super,
			references: references,
			data:       record,
		})
	}
	instanceOrder := make(map[string]int)
	var encodeEmbeddedInstance func(string, mofInstance) ([]byte, error)
	encodeEmbeddedInstance = func(parentNamespace string, instance mofInstance) ([]byte, error) {
		namespace := parentNamespace
		if instance.Namespace != "" {
			namespace = normalizeWMINamespace(instance.Namespace, parentNamespace)
		}
		entry, ok := lookupClass(namespace, instance.Class)
		if !ok {
			return nil, fmt.Errorf("embedded instance class %s is not declared in %s", instance.Class, namespace)
		}
		chain, err := classChain(entry)
		if err != nil {
			return nil, err
		}
		properties, err := classProperties(entry)
		if err != nil {
			return nil, err
		}
		var ancestors []string
		if entry.class.Super != "" {
			ancestors = []string{entry.class.Super}
		}
		classPart, err := buildWMIClassPart(entry.class, ancestors, properties, uint32(len(chain)-1))
		if err != nil {
			return nil, fmt.Errorf("embedded class %s: %w", entry.class.Name, err)
		}
		instancePart, err := buildWMIInstancePart(instance, entry.class, properties, func(child mofInstance) ([]byte, error) {
			return encodeEmbeddedInstance(namespace, child)
		})
		if err != nil {
			return nil, err
		}
		return buildWMIEmbeddedInstanceObject(classPart, instancePart), nil
	}
	for _, instance := range instances {
		namespace := normalizeWMINamespace(instance.Namespace, defaultNamespace)
		entry, ok := lookupClass(namespace, instance.Class)
		if !ok {
			return nil, fmt.Errorf("wmi repository: instance class %s is not declared in %s", instance.Class, namespace)
		}
		propertyEntries, err := classPropertyEntries(entry)
		if err != nil {
			return nil, err
		}
		properties := make([]mofFeature, len(propertyEntries))
		for index := range propertyEntries {
			properties[index] = propertyEntries[index].feature
		}
		classRevision, ok := classRevisions[entry.namespace+"\x00"+strings.ToUpper(entry.class.Name)]
		if !ok {
			return nil, fmt.Errorf("wmi repository: instance class %s in %s has no revision", instance.Class, namespace)
		}
		nextRevision++
		record, key, err := buildWMIInstanceRecord(
			instance,
			entry.class,
			properties,
			nextRevision,
			classRevision,
			func(child mofInstance) ([]byte, error) {
				return encodeEmbeddedInstance(namespace, child)
			},
		)
		if err != nil {
			return nil, fmt.Errorf("wmi repository: %s: %w", namespace, err)
		}
		keyClassName := entry.class.Name
		var keyOwner string
		var instanceReferences []wmiInstanceReference
		values := make(map[string]mofValue, len(instance.Properties))
		for _, assignment := range instance.Properties {
			values[strings.ToLower(assignment.Name)] = assignment.Value
		}
		for _, property := range propertyEntries {
			if !hasMOFQualifier(property.feature.Qualifiers, "key") {
				continue
			}
			if property.feature.Type.Reference != "" {
				value, found := values[strings.ToLower(property.feature.Name)]
				if !found && property.feature.Value != nil {
					value, found = *property.feature.Value, true
				}
				if !found {
					return nil, fmt.Errorf("wmi repository: instance of %s has no value for key %s", instance.Class, property.feature.Name)
				}
				instanceReferences = append(instanceReferences, wmiInstanceReference{
					propertyName: strings.ToLower(property.feature.Name),
					className:    property.feature.Type.Reference,
					targetPath:   value.Text,
				})
				continue
			}
			if keyOwner == "" {
				keyOwner = property.declaring.class.Name
			} else if !strings.EqualFold(keyOwner, property.declaring.class.Name) {
				keyOwner = entry.class.Name
			}
		}
		if len(instanceReferences) == 0 && keyOwner != "" {
			keyClassName = keyOwner
		}
		canonicalPath, err := instancePath(instance, nil)
		if err != nil {
			return nil, fmt.Errorf("wmi repository: instance path for %s: %w", instance.Class, err)
		}
		pendingRecord := wmiPendingRecord{
			namespace:          namespace,
			kind:               "instance",
			className:          entry.class.Name,
			instanceKey:        key,
			keyClassName:       keyClassName,
			canonicalPath:      canonicalPath,
			instanceReferences: instanceReferences,
			data:               record,
		}
		identity := namespace + "\x00" + strings.ToUpper(instance.Class) + "\x00" + key
		if index, exists := instanceOrder[identity]; exists {
			pending[index] = pendingRecord
		} else {
			instanceOrder[identity] = len(pending)
			pending = append(pending, pendingRecord)
		}
	}

	instancesByPath := make(map[string]wmiPendingRecord)
	for _, record := range pending {
		if record.kind == "instance" {
			instancesByPath[strings.ToUpper(record.canonicalPath)] = record
		}
	}
	var projections []wmiPendingRecord
	for _, record := range pending {
		if record.kind != "instance" {
			continue
		}
		sourcePath := `\NS_` + wmiUpperUTF16MD5(record.namespace) +
			`\KI_` + wmiUpperUTF16MD5(record.keyClassName) +
			`\I_` + record.instanceKey
		for _, reference := range record.instanceReferences {
			targetPath := canonicalWMIReferencePath(reference.targetPath, record.namespace)
			target, found := instancesByPath[strings.ToUpper(targetPath)]
			if !found {
				// MOF permits weak references to instances supplied later by a
				// provider. They have no repository target to reverse-index.
				continue
			}
			projection := buildWMIReferenceProjection(
				record.namespace,
				record.className,
				reference.propertyName,
				sourcePath,
			)
			projections = append(projections, wmiPendingRecord{
				namespace:          target.namespace,
				kind:               "reference",
				referenceClassName: reference.className,
				referencedKey:      target.instanceKey,
				relationKey:        wmiUpperUTF16MD5(sourcePath + "\x00" + reference.propertyName),
				data:               projection,
			})
		}
	}
	pending = append(pending, projections...)

	recordData := make([][]byte, len(pending))
	for index := range pending {
		recordData[index] = pending[index].data
	}
	objectsData, locations, err := buildWMIRepositoryObjects(recordData)
	if err != nil {
		return nil, err
	}
	var keys []string
	for index, record := range pending {
		location := locations[index]
		namespaceHash := wmiUpperUTF16MD5(record.namespace)
		classHash := wmiUpperUTF16MD5(record.className)
		position := fmt.Sprintf("%d.%d.%d", location.logicalPage, location.id, len(record.data))
		prefix := "NS_" + namespaceHash + `\`
		switch record.kind {
		case "class":
			keys = append(keys, prefix+"CD_"+classHash+"."+position)
			keys = append(keys, prefix+"CR_"+wmiUpperUTF16MD5(record.superclass)+`\C_`+classHash)
			for _, reference := range record.references {
				keys = append(keys, prefix+"CR_"+wmiUpperUTF16MD5(reference)+`\R_`+classHash)
			}
		case "instance":
			location := record.instanceKey + "." + position
			keys = append(keys,
				prefix+"CI_"+classHash+`\IL_`+location,
				prefix+"KI_"+wmiUpperUTF16MD5(record.keyClassName)+`\I_`+location,
			)
		case "reference":
			keys = append(keys,
				prefix+"KI_"+wmiUpperUTF16MD5(record.referenceClassName)+
					`\IR_`+record.referencedKey+
					`\R_`+record.relationKey+"."+position,
			)
		}
	}
	indexData, err := buildWMIRepositoryIndex(keys)
	if err != nil {
		return nil, err
	}
	basePages := func(pageCount int) []uint32 {
		pages := make([]uint32, pageCount)
		for index := range pages {
			pages[index] = uint32(index)
		}
		return pages
	}
	reservePages := func(data []byte, minimum int) ([]byte, []uint32) {
		allocated := len(data) / wmiRepositoryPageSize
		reserve := max(minimum, (allocated+15)/16)
		free := make([]uint32, reserve)
		for index := range free {
			free[index] = uint32(allocated + index)
		}
		return append(data, make([]byte, reserve*wmiRepositoryPageSize)...), free
	}
	objectBase := basePages(len(objectsData) / wmiRepositoryPageSize)
	indexBase := basePages(len(indexData) / wmiRepositoryPageSize)
	var objectFree, indexFree []uint32
	objectsData, objectFree = reservePages(objectsData, 3)
	indexData, indexFree = reservePages(indexData, 2)
	mapping := wmiRepositoryMapping{
		objects: wmiMappingSection{generation: 1, physicalPages: uint32(len(objectsData) / wmiRepositoryPageSize), base: objectBase, free: objectFree},
		index:   wmiMappingSection{generation: 1, physicalPages: uint32(len(indexData) / wmiRepositoryPageSize), base: indexBase, free: indexFree},
	}
	mappingData := serializeWMIRepositoryMapping(mapping)
	standbyMapping := mapping
	standbyMappingData := serializeWMIRepositoryMapping(standbyMapping)
	versionData := binary.LittleEndian.AppendUint32(nil, 1)
	sources := starlark.StringDict{
		"$WinMgmt.CFG":    &starfile.Bytes{Name: "$WinMgmt.CFG", Data: buildWMIRepositoryConfig()},
		"FS/MAPPING.VER":  &starfile.Bytes{Name: "MAPPING.VER", Data: versionData},
		"FS/MAPPING1.MAP": &starfile.Bytes{Name: "MAPPING1.MAP", Data: mappingData},
		"FS/MAPPING2.MAP": &starfile.Bytes{Name: "MAPPING2.MAP", Data: standbyMappingData},
		"FS/OBJECTS.DATA": &starfile.Bytes{Name: "OBJECTS.DATA", Data: objectsData},
		"FS/INDEX.BTR":    &starfile.Bytes{Name: "INDEX.BTR", Data: indexData},
	}
	pages, err := parseWMIRepositoryIndex(mapping.index, indexData)
	if err != nil {
		return nil, err
	}
	return &wmiRepositoryFile{mapping: mapping, records: locations, pages: pages, files: sources}, nil
}

func (r *wmiRepositoryFile) String() string {
	keys := 0
	for _, page := range r.pages {
		keys += len(page.keys)
	}
	return fmt.Sprintf("<windows.wmi_repository records=%d keys=%d>", len(r.records), keys)
}
func (r *wmiRepositoryFile) Type() string          { return "windows.wmi_repository" }
func (r *wmiRepositoryFile) Freeze()               {}
func (r *wmiRepositoryFile) Truth() starlark.Bool  { return starlark.True }
func (r *wmiRepositoryFile) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: %s", r.Type()) }
func (r *wmiRepositoryFile) AttrNames() []string {
	return []string{"files", "keys", "pages", "records"}
}
func (r *wmiRepositoryFile) Attr(name string) (starlark.Value, error) {
	switch name {
	case "files":
		values := starlark.NewDict(len(r.files))
		for name, file := range r.files {
			if err := values.SetKey(starlark.String(name), file); err != nil {
				return nil, err
			}
		}
		return values, nil
	case "keys":
		values := make([]starlark.Value, 0)
		for _, page := range r.pages {
			for _, key := range page.keys {
				values = append(values, starlark.String(key))
			}
		}
		return starlark.NewList(values), nil
	case "pages":
		values := make([]starlark.Value, len(r.pages))
		for index, page := range r.pages {
			children := make([]starlark.Value, len(page.children))
			for childIndex, child := range page.children {
				children[childIndex] = starlark.MakeUint64(uint64(child))
			}
			keys := make([]starlark.Value, len(page.keys))
			for keyIndex, key := range page.keys {
				keys[keyIndex] = starlark.String(key)
			}
			values[index] = starfile.NewRecord(starlark.StringDict{
				"children": starlark.NewList(children),
				"id":       starlark.MakeUint64(uint64(page.id)),
				"keys":     starlark.NewList(keys),
			})
		}
		return starlark.NewList(values), nil
	case "records":
		values := make([]starlark.Value, len(r.records))
		for index, record := range r.records {
			values[index] = starfile.NewRecord(starlark.StringDict{
				"data": starlark.Value(&starfile.Bytes{Name: fmt.Sprintf("wmi-record-%d", record.id), Data: append([]byte(nil), record.data...)}),
				"id":   starlark.MakeUint64(uint64(record.id)),
				"page": starlark.MakeUint64(uint64(record.logicalPage)),
			})
		}
		return starlark.NewList(values), nil
	}
	return nil, nil
}

func parseWMIRepositoryMapping(data []byte) (wmiRepositoryMapping, error) {
	offset := 0
	readSection := func(name string) (wmiMappingSection, error) {
		readUint32 := func(description string) (uint32, error) {
			if offset+4 > len(data) {
				return 0, fmt.Errorf("wmi repository: truncated %s %s", name, description)
			}
			value := binary.LittleEndian.Uint32(data[offset : offset+4])
			offset += 4
			return value, nil
		}
		magic, err := readUint32("start marker")
		if err != nil {
			return wmiMappingSection{}, err
		}
		if magic != wmiMappingStart {
			return wmiMappingSection{}, fmt.Errorf("wmi repository: invalid %s start marker %#x", name, magic)
		}
		generation, err := readUint32("generation")
		if err != nil {
			return wmiMappingSection{}, err
		}
		physicalPages, err := readUint32("physical page count")
		if err != nil {
			return wmiMappingSection{}, err
		}
		baseCount, err := readUint32("base page count")
		if err != nil {
			return wmiMappingSection{}, err
		}
		if baseCount > 1<<24 || uint64(baseCount)*4 > uint64(len(data)-offset) {
			return wmiMappingSection{}, fmt.Errorf("wmi repository: invalid %s base page count %d", name, baseCount)
		}
		section := wmiMappingSection{generation: generation, physicalPages: physicalPages, base: make([]uint32, baseCount)}
		for index := range section.base {
			section.base[index], _ = readUint32("base page")
		}
		freeCount, err := readUint32("free page count")
		if err != nil {
			return wmiMappingSection{}, err
		}
		if freeCount > 1<<24 || uint64(freeCount)*4 > uint64(len(data)-offset) {
			return wmiMappingSection{}, fmt.Errorf("wmi repository: invalid %s free page count %d", name, freeCount)
		}
		section.free = make([]uint32, freeCount)
		for index := range section.free {
			section.free[index], _ = readUint32("free page")
		}
		end, err := readUint32("end marker")
		if err != nil {
			return wmiMappingSection{}, err
		}
		if end != wmiMappingEnd {
			return wmiMappingSection{}, fmt.Errorf("wmi repository: invalid %s end marker %#x", name, end)
		}
		seen := make([]bool, physicalPages)
		for _, page := range append(append([]uint32(nil), section.base...), section.free...) {
			if page >= physicalPages {
				return wmiMappingSection{}, fmt.Errorf("wmi repository: %s page %d exceeds physical page count %d", name, page, physicalPages)
			}
			if seen[page] {
				return wmiMappingSection{}, fmt.Errorf("wmi repository: %s physical page %d appears more than once", name, page)
			}
			seen[page] = true
		}
		if uint64(len(section.base))+uint64(len(section.free)) != uint64(physicalPages) {
			return wmiMappingSection{}, fmt.Errorf("wmi repository: %s maps %d of %d physical pages", name, len(section.base)+len(section.free), physicalPages)
		}
		return section, nil
	}
	objects, err := readSection("object mapping")
	if err != nil {
		return wmiRepositoryMapping{}, err
	}
	index, err := readSection("index mapping")
	if err != nil {
		return wmiRepositoryMapping{}, err
	}
	if offset != len(data) {
		return wmiRepositoryMapping{}, fmt.Errorf("wmi repository: mapping has %d trailing bytes", len(data)-offset)
	}
	return wmiRepositoryMapping{objects: objects, index: index}, nil
}

func appendWMIRepositoryMappingSection(output []byte, section wmiMappingSection) []byte {
	appendUint32 := func(value uint32) { output = binary.LittleEndian.AppendUint32(output, value) }
	appendUint32(wmiMappingStart)
	appendUint32(section.generation)
	appendUint32(section.physicalPages)
	appendUint32(uint32(len(section.base)))
	for _, page := range section.base {
		appendUint32(page)
	}
	appendUint32(uint32(len(section.free)))
	for _, page := range section.free {
		appendUint32(page)
	}
	appendUint32(wmiMappingEnd)
	return output
}

func serializeWMIRepositoryMapping(mapping wmiRepositoryMapping) []byte {
	output := appendWMIRepositoryMappingSection(nil, mapping.objects)
	return appendWMIRepositoryMappingSection(output, mapping.index)
}

func resolveWMIIndexPages(section wmiMappingSection, data []byte) ([]uint32, error) {
	pages := append([]uint32(nil), section.base...)
	for logical, physical := range pages {
		offset := uint64(physical) * wmiRepositoryPageSize
		if offset+wmiRepositoryPageSize > uint64(len(data)) {
			return nil, fmt.Errorf("wmi repository: index page %d is truncated", physical)
		}
		page := data[offset : offset+wmiRepositoryPageSize]
		signature := binary.LittleEndian.Uint32(page[:4])
		if signature == wmiIndexMetaSignature {
			if logical != 0 {
				return nil, fmt.Errorf("wmi repository: index metadata appears at logical page %d", logical)
			}
			continue
		}
		if signature != wmiIndexPageSignature {
			return nil, fmt.Errorf("wmi repository: index page %d has invalid signature", physical)
		}
		identity := binary.LittleEndian.Uint32(page[4:8])
		if identity != uint32(logical) {
			return nil, fmt.Errorf("wmi repository: logical index page %d identifies itself as %d", logical, identity)
		}
	}
	return pages, nil
}

func parseWMIRepositoryRecords(section wmiMappingSection, data []byte) ([]wmiRepositoryRecord, error) {
	physicalPages := section.base
	if len(physicalPages) == 0 {
		return nil, fmt.Errorf("wmi repository: object mapping has no metadata page")
	}
	metadataOffset := uint64(physicalPages[0]) * wmiRepositoryPageSize
	if metadataOffset+wmiRepositoryPageSize > uint64(len(data)) {
		return nil, fmt.Errorf("wmi repository: object metadata page is truncated")
	}
	metadata := data[metadataOffset : metadataOffset+wmiRepositoryPageSize]
	if binary.LittleEndian.Uint32(metadata[:4]) != 1 {
		return nil, fmt.Errorf("wmi repository: invalid object metadata version %#x", binary.LittleEndian.Uint32(metadata[:4]))
	}
	cacheCount := binary.LittleEndian.Uint32(metadata[8:12])
	if cacheCount > uint32((wmiRepositoryPageSize-12)/16) {
		return nil, fmt.Errorf("wmi repository: invalid object cache page count %d", cacheCount)
	}
	cachePages := make(map[uint32]bool, cacheCount)
	for index := uint32(0); index < cacheCount; index++ {
		offset := 12 + int(index)*16
		logical := binary.LittleEndian.Uint32(metadata[offset : offset+4])
		free := binary.LittleEndian.Uint32(metadata[offset+4 : offset+8])
		checksum := binary.LittleEndian.Uint32(metadata[offset+8 : offset+12])
		if logical == 0 || logical >= uint32(len(physicalPages)) {
			return nil, fmt.Errorf("wmi repository: object cache entry %d has invalid logical page %d", index, logical)
		}
		if free >= wmiRepositoryPageSize {
			return nil, fmt.Errorf("wmi repository: object cache page %d has invalid free size %d", logical, free)
		}
		if cachePages[logical] {
			return nil, fmt.Errorf("wmi repository: duplicate object cache page %d", logical)
		}
		cachePages[logical] = true
		physical := physicalPages[logical]
		page := data[int(physical)*wmiRepositoryPageSize : int(physical+1)*wmiRepositoryPageSize]
		if crc32.ChecksumIEEE(page) != checksum {
			return nil, fmt.Errorf("wmi repository: object cache page %d checksum mismatch", logical)
		}
	}
	var records []wmiRepositoryRecord
	continuations := make(map[int]bool)
	for logical, physical := range physicalPages {
		if logical == 0 {
			continue
		}
		if continuations[logical] {
			continue
		}
		pageOffset := uint64(physical) * wmiRepositoryPageSize
		if pageOffset+wmiRepositoryPageSize > uint64(len(data)) {
			return nil, fmt.Errorf("wmi repository: object page %d is truncated", physical)
		}
		page := data[pageOffset : pageOffset+wmiRepositoryPageSize]
		firstRecordOffset := binary.LittleEndian.Uint32(page[4:8])
		if firstRecordOffset < 32 || firstRecordOffset > wmiRepositoryPageSize || firstRecordOffset%16 != 0 {
			return nil, fmt.Errorf("wmi repository: object page %d has invalid record data offset %d", logical, firstRecordOffset)
		}
		terminated := false
		for descriptorOffset := 0; descriptorOffset+16 <= int(firstRecordOffset); descriptorOffset += 16 {
			recordID := binary.LittleEndian.Uint32(page[descriptorOffset : descriptorOffset+4])
			recordOffset := binary.LittleEndian.Uint32(page[descriptorOffset+4 : descriptorOffset+8])
			size := binary.LittleEndian.Uint32(page[descriptorOffset+8 : descriptorOffset+12])
			checksum := binary.LittleEndian.Uint32(page[descriptorOffset+12 : descriptorOffset+16])
			if recordID == 0 && recordOffset == 0 && size == 0 && checksum == 0 {
				terminated = true
				break
			}
			if recordID == 0 || size == 0 {
				return nil, fmt.Errorf("wmi repository: object record %d has zero size", recordID)
			}
			if recordOffset < firstRecordOffset {
				return nil, fmt.Errorf("wmi repository: object record %d overlaps its descriptor table", recordID)
			}
			absolute := uint64(logical)*wmiRepositoryPageSize + uint64(recordOffset)
			if absolute+uint64(size) > uint64(len(physicalPages))*wmiRepositoryPageSize {
				return nil, fmt.Errorf("wmi repository: object record %d exceeds logical page store", recordID)
			}
			lastLogicalPage := int((absolute + uint64(size) - 1) / wmiRepositoryPageSize)
			for continuation := logical + 1; continuation <= lastLogicalPage; continuation++ {
				continuations[continuation] = true
			}
			recordData := make([]byte, size)
			for copied := uint32(0); copied < size; {
				position := absolute + uint64(copied)
				logicalPage := uint32(position / wmiRepositoryPageSize)
				within := uint32(position % wmiRepositoryPageSize)
				if logicalPage >= uint32(len(physicalPages)) {
					return nil, fmt.Errorf("wmi repository: object record %d crosses missing page", recordID)
				}
				amount := min(size-copied, uint32(wmiRepositoryPageSize)-within)
				physicalPage := physicalPages[logicalPage]
				physicalOffset := uint64(physicalPage)*wmiRepositoryPageSize + uint64(within)
				copy(recordData[copied:copied+amount], data[physicalOffset:physicalOffset+uint64(amount)])
				copied += amount
			}
			if crc32.ChecksumIEEE(recordData) != checksum {
				return nil, fmt.Errorf("wmi repository: object record %d checksum mismatch", recordID)
			}
			records = append(records, wmiRepositoryRecord{logicalPage: uint32(logical), id: recordID, data: recordData})
		}
		if !terminated {
			return nil, fmt.Errorf("wmi repository: object page %d has no descriptor terminator", logical)
		}
	}
	return records, nil
}

func parseWMIRepositoryIndexPage(page []byte) (wmiRepositoryIndexPage, error) {
	if len(page) != wmiRepositoryPageSize || binary.LittleEndian.Uint32(page[:4]) != wmiIndexPageSignature {
		return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: invalid index page")
	}
	count := binary.LittleEndian.Uint32(page[16:20])
	if count > 1<<16 {
		return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: invalid index key count %d", count)
	}
	position := uint64(20)
	need := uint64(count)*4 + uint64(count+1)*4 + uint64(count)*2
	if position+need+6 > uint64(len(page)) {
		return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: truncated index arrays")
	}
	position += uint64(count) * 4
	children := make([]uint32, count+1)
	for index := range children {
		children[index] = binary.LittleEndian.Uint32(page[position : position+4])
		position += 4
	}
	sequence := make([]uint16, count)
	for index := range sequence {
		sequence[index] = binary.LittleEndian.Uint16(page[position : position+2])
		position += 2
	}
	nodeCount := uint64(binary.LittleEndian.Uint16(page[position : position+2]))
	position += 2
	if position+nodeCount*2+4 > uint64(len(page)) {
		return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: truncated index trie")
	}
	nodes := make([]uint16, nodeCount)
	for index := range nodes {
		nodes[index] = binary.LittleEndian.Uint16(page[position : position+2])
		position += 2
	}
	tokenCount := uint64(binary.LittleEndian.Uint16(page[position : position+2]))
	position += 2
	if position+tokenCount*2+2 > uint64(len(page)) {
		return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: truncated index token table")
	}
	offsets := make([]uint16, tokenCount)
	for index := range offsets {
		offsets[index] = binary.LittleEndian.Uint16(page[position : position+2])
		position += 2
	}
	dataSize := uint64(binary.LittleEndian.Uint16(page[position : position+2]))
	position += 2
	if position+dataSize > uint64(len(page)) {
		return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: truncated index string storage")
	}
	storage := page[position : position+dataSize]
	keys := make([]string, count)
	for index, start := range sequence {
		if int(start) >= len(nodes) {
			return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: key %d has invalid trie node %d", index, start)
		}
		parts := int(nodes[start])
		if parts < 1 || int(start)+1+parts > len(nodes) {
			return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: key %d has invalid segment count %d", index, parts)
		}
		segments := make([]string, parts)
		for part := 0; part < parts; part++ {
			token := int(nodes[int(start)+1+part])
			if token >= len(offsets) || int(offsets[token]) >= len(storage) {
				return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: key %d has invalid token %d", index, token)
			}
			value := storage[offsets[token]:]
			if end := bytes.IndexByte(value, 0); end >= 0 {
				value = value[:end]
			} else {
				return wmiRepositoryIndexPage{}, fmt.Errorf("wmi repository: key %d token %d is unterminated", index, token)
			}
			segments[part] = string(value)
		}
		keys[index] = strings.Join(segments, `\`)
	}
	return wmiRepositoryIndexPage{id: binary.LittleEndian.Uint32(page[4:8]), children: children, keys: keys}, nil
}

func parseWMIRepositoryIndex(section wmiMappingSection, data []byte) ([]wmiRepositoryIndexPage, error) {
	physicalPages, err := resolveWMIIndexPages(section, data)
	if err != nil {
		return nil, err
	}
	pages := make([]wmiRepositoryIndexPage, 0, len(physicalPages))
	for logical, physical := range physicalPages {
		offset := uint64(physical) * wmiRepositoryPageSize
		if offset+wmiRepositoryPageSize > uint64(len(data)) {
			return nil, fmt.Errorf("wmi repository: index page %d is truncated", physical)
		}
		page := data[offset : offset+wmiRepositoryPageSize]
		signature := binary.LittleEndian.Uint32(page[:4])
		if signature == wmiIndexMetaSignature {
			continue
		}
		parsed, err := parseWMIRepositoryIndexPage(page)
		if err != nil {
			return nil, fmt.Errorf("wmi repository: parse logical index page %d: %w", logical, err)
		}
		if parsed.id != uint32(logical) {
			return nil, fmt.Errorf("wmi repository: logical index page %d identifies itself as %d", logical, parsed.id)
		}
		pages = append(pages, parsed)
	}
	return pages, nil
}

func buildWMIRepositoryIndexPage(id uint32, keys []string, children []uint32) ([]byte, error) {
	if len(children) == 0 {
		children = make([]uint32, len(keys)+1)
	}
	if len(children) != len(keys)+1 {
		return nil, fmt.Errorf("wmi repository: index page has %d keys and %d children", len(keys), len(children))
	}
	tokenIDs := make(map[string]uint16)
	var tokens []string
	var sequence, nodes []uint16
	for _, key := range keys {
		parts := strings.Split(key, `\`)
		if len(parts) == 0 || len(parts) > 0xffff {
			return nil, fmt.Errorf("wmi repository: invalid index key %q", key)
		}
		if len(nodes) > 0xffff {
			return nil, fmt.Errorf("wmi repository: index trie exceeds 16-bit node space")
		}
		sequence = append(sequence, uint16(len(nodes)))
		nodes = append(nodes, uint16(len(parts)))
		for _, part := range parts {
			if part == "" || strings.IndexByte(part, 0) >= 0 {
				return nil, fmt.Errorf("wmi repository: invalid empty or NUL index segment in %q", key)
			}
			token, ok := tokenIDs[part]
			if !ok {
				if len(tokens) >= 0xffff {
					return nil, fmt.Errorf("wmi repository: index token table exceeds 16-bit space")
				}
				token = uint16(len(tokens))
				tokenIDs[part] = token
				tokens = append(tokens, part)
			}
			nodes = append(nodes, token)
		}
	}
	var storage []byte
	offsets := make([]uint16, len(tokens))
	for index, token := range tokens {
		if len(storage) > 0xffff || len(token)+1 > 0x10000-len(storage) {
			return nil, fmt.Errorf("wmi repository: index string storage exceeds 16-bit space")
		}
		offsets[index] = uint16(len(storage))
		storage = append(storage, token...)
		storage = append(storage, 0)
	}
	page := make([]byte, wmiRepositoryPageSize)
	binary.LittleEndian.PutUint32(page[:4], wmiIndexPageSignature)
	binary.LittleEndian.PutUint32(page[4:8], id)
	binary.LittleEndian.PutUint32(page[16:20], uint32(len(keys)))
	position := 20
	position += len(keys) * 4
	for _, child := range children {
		binary.LittleEndian.PutUint32(page[position:position+4], child)
		position += 4
	}
	for _, value := range sequence {
		binary.LittleEndian.PutUint16(page[position:position+2], value)
		position += 2
	}
	if len(nodes) > 0xffff || len(offsets) > 0xffff || len(storage) > 0xffff {
		return nil, fmt.Errorf("wmi repository: index page exceeds a 16-bit section limit")
	}
	need := position + 2 + len(nodes)*2 + 2 + len(offsets)*2 + 2 + len(storage)
	if need > len(page) {
		return nil, fmt.Errorf("wmi repository: index page requires %d bytes", need)
	}
	binary.LittleEndian.PutUint16(page[position:position+2], uint16(len(nodes)))
	position += 2
	for _, value := range nodes {
		binary.LittleEndian.PutUint16(page[position:position+2], value)
		position += 2
	}
	binary.LittleEndian.PutUint16(page[position:position+2], uint16(len(offsets)))
	position += 2
	for _, value := range offsets {
		binary.LittleEndian.PutUint16(page[position:position+2], value)
		position += 2
	}
	binary.LittleEndian.PutUint16(page[position:position+2], uint16(len(storage)))
	position += 2
	copy(page[position:], storage)
	return page, nil
}

func buildWMIRepositoryObjects(records [][]byte) ([]byte, []wmiRepositoryRecord, error) {
	// Logical page zero is the object store's cache metadata page. Its first
	// word is the metadata format version and its second word terminates the
	// linked list of pending cache pages. Record descriptors begin on page one.
	output := make([]byte, wmiRepositoryPageSize)
	binary.LittleEndian.PutUint32(output[:4], 1)
	if len(records) == 0 {
		return output, nil, nil
	}
	var locations []wmiRepositoryRecord
	type cachePage struct {
		logical uint32
		free    uint32
	}
	var cachePages []cachePage
	globalID := uint32(1)
	for len(records) > 0 {
		pageStart := len(output)
		output = append(output, make([]byte, wmiRepositoryPageSize)...)
		page := output[pageStart : pageStart+wmiRepositoryPageSize]
		logical := uint32(pageStart / wmiRepositoryPageSize)
		count, dataSize := 0, 0
		for count < len(records) {
			candidateCount := count + 1
			headerSize := (candidateCount + 1) * 16
			if headerSize+dataSize+len(records[count]) > wmiRepositoryPageSize {
				break
			}
			dataSize += len(records[count])
			count++
		}
		packed := count != 0
		if !packed {
			// Large records are stored as a descriptor followed by a logical
			// byte stream that continues through subsequent pages. Descriptor
			// ID one identifies this single-record layout.
			count = 1
		}
		headerSize := (count + 1) * 16
		ids := make([]uint32, count)
		for index := range ids {
			if packed {
				ids[index] = globalID
				globalID++
			} else {
				ids[index] = 1
			}
		}
		position := headerSize
		for index := 0; index < count; index++ {
			record := records[index]
			descriptor := index * 16
			binary.LittleEndian.PutUint32(page[descriptor:descriptor+4], ids[index])
			binary.LittleEndian.PutUint32(page[descriptor+4:descriptor+8], uint32(position))
			binary.LittleEndian.PutUint32(page[descriptor+8:descriptor+12], uint32(len(record)))
			binary.LittleEndian.PutUint32(page[descriptor+12:descriptor+16], crc32.ChecksumIEEE(record))
			locations = append(locations, wmiRepositoryRecord{logicalPage: logical, id: ids[index], data: append([]byte(nil), record...)})
			remaining := record
			for len(remaining) > 0 {
				if position == wmiRepositoryPageSize {
					output = append(output, make([]byte, wmiRepositoryPageSize)...)
					position = 0
				}
				currentPage := output[len(output)-wmiRepositoryPageSize:]
				amount := min(len(remaining), wmiRepositoryPageSize-position)
				copy(currentPage[position:position+amount], remaining[:amount])
				position += amount
				remaining = remaining[amount:]
			}
		}
		if packed {
			cachePages = append(cachePages, cachePage{
				logical: logical,
				free:    uint32(wmiRepositoryPageSize - position),
			})
		}
		records = records[count:]
	}
	if len(cachePages) > (wmiRepositoryPageSize-12)/16 {
		return nil, nil, fmt.Errorf("wmi repository: object cache directory requires %d entries", len(cachePages))
	}
	metadata := output[:wmiRepositoryPageSize]
	binary.LittleEndian.PutUint32(metadata[8:12], uint32(len(cachePages)))
	for index, entry := range cachePages {
		offset := 12 + index*16
		binary.LittleEndian.PutUint32(metadata[offset:offset+4], entry.logical)
		binary.LittleEndian.PutUint32(metadata[offset+4:offset+8], entry.free)
		page := output[int(entry.logical)*wmiRepositoryPageSize : int(entry.logical+1)*wmiRepositoryPageSize]
		binary.LittleEndian.PutUint32(metadata[offset+8:offset+12], crc32.ChecksumIEEE(page))
	}
	return output, locations, nil
}

func buildWMIRepositoryIndex(keys []string) ([]byte, error) {
	keys = append([]string(nil), keys...)
	sort.Strings(keys)
	for index := 1; index < len(keys); index++ {
		if keys[index] == keys[index-1] {
			return nil, fmt.Errorf("wmi repository: duplicate index key %q", keys[index])
		}
	}

	type node struct {
		id   uint32
		page []byte
	}
	nextID := uint32(1)
	packLeaves := func() ([]node, []string, error) {
		var leaves []node
		var separators []string
		if len(keys) == 0 {
			page, err := buildWMIRepositoryIndexPage(nextID, nil, nil)
			if err != nil {
				return nil, nil, err
			}
			return []node{{id: nextID, page: page}}, nil, nil
		}
		for start := 0; start < len(keys); {
			end := start
			var page []byte
			for end < len(keys) {
				candidate, err := buildWMIRepositoryIndexPage(nextID, keys[start:end+1], nil)
				if err != nil {
					if end == start {
						return nil, nil, fmt.Errorf("wmi repository: index key %q cannot fit a page: %w", keys[start], err)
					}
					break
				}
				page = candidate
				end++
			}
			if end == start {
				return nil, nil, fmt.Errorf("wmi repository: failed to pack index page")
			}
			if end < len(keys) {
				if end-start < 2 {
					return nil, nil, fmt.Errorf("wmi repository: index page cannot hold a key plus a separator")
				}
				end--
				separators = append(separators, keys[end])
				var err error
				page, err = buildWMIRepositoryIndexPage(nextID, keys[start:end], nil)
				if err != nil {
					return nil, nil, err
				}
				end++
			}
			leaves = append(leaves, node{id: nextID, page: page})
			nextID++
			start = end
		}
		return leaves, separators, nil
	}

	level, separators, err := packLeaves()
	if err != nil {
		return nil, err
	}
	all := append([]node(nil), level...)
	for len(level) > 1 {
		type group struct{ start, end int }
		var groups []group
		for start := 0; start < len(level); {
			end := start + 1
			for end < len(level) {
				candidateEnd := end + 1
				children := make([]uint32, candidateEnd-start)
				for index, child := range level[start:candidateEnd] {
					children[index] = child.id
				}
				if _, candidateErr := buildWMIRepositoryIndexPage(nextID, separators[start:candidateEnd-1], children); candidateErr != nil {
					break
				}
				end = candidateEnd
			}
			if end == start+1 {
				return nil, fmt.Errorf("wmi repository: two index children cannot fit an internal page")
			}
			groups = append(groups, group{start: start, end: end})
			start = end
		}
		if len(groups) > 1 && groups[len(groups)-1].end-groups[len(groups)-1].start == 1 {
			previous := &groups[len(groups)-2]
			last := &groups[len(groups)-1]
			if previous.end-previous.start < 3 {
				return nil, fmt.Errorf("wmi repository: cannot balance internal index pages")
			}
			previous.end--
			last.start--
		}

		parents := make([]node, len(groups))
		nextSeparators := make([]string, 0, len(groups)-1)
		for groupIndex, group := range groups {
			children := make([]uint32, group.end-group.start)
			for index, child := range level[group.start:group.end] {
				children[index] = child.id
			}
			page, err := buildWMIRepositoryIndexPage(nextID, separators[group.start:group.end-1], children)
			if err != nil {
				return nil, err
			}
			parents[groupIndex] = node{id: nextID, page: page}
			nextID++
			if group.end < len(level) {
				nextSeparators = append(nextSeparators, separators[group.end-1])
			}
		}
		level = parents
		separators = nextSeparators
		all = append(all, level...)
	}
	root := level[0].id
	meta := make([]byte, wmiRepositoryPageSize)
	binary.LittleEndian.PutUint32(meta[:4], wmiIndexMetaSignature)
	binary.LittleEndian.PutUint32(meta[12:16], root)
	output := meta
	for _, current := range all {
		output = append(output, current.page...)
	}
	return output, nil
}

func readWMIRepositoryFile(file starfile.File, name string) ([]byte, error) {
	if file.Size() < 0 || file.Size() > 1<<31 {
		return nil, fmt.Errorf("wmi repository: invalid %s size %d", name, file.Size())
	}
	data := make([]byte, file.Size())
	if _, err := io.ReadFull(io.NewSectionReader(file, 0, file.Size()), data); err != nil {
		return nil, fmt.Errorf("wmi repository: read %s: %w", name, err)
	}
	return data, nil
}
