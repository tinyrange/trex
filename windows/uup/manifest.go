package uup

import (
	"encoding/xml"
	"fmt"
	"github.com/tinyrange/trex/internal/xmltoken"
	"io"
	"strings"
)

const (
	maximumManifestDepth      = 128
	maximumManifestElements   = 1 << 20
	maximumManifestReferences = 1 << 18
	maximumManifestFiles      = 1 << 18
)

type ManifestAttribute struct {
	Namespace string
	Name      string
	Value     string
}

type AssemblyIdentity struct {
	Name                  string
	Version               string
	ProcessorArchitecture string
	Language              string
	PublicKeyToken        string
	BuildType             string
	VersionScope          string
	Attributes            []ManifestAttribute
}

// StableKey identifies a CBS assembly independently from the version being
// superseded. It uses the dimensions encoded in package and WinSxS filenames;
// buildType and versionScope are manifest policy rather than path identity.
func (i AssemblyIdentity) StableKey() string {
	language := i.Language
	if language == "" {
		language = "neutral"
	}
	return strings.ToLower(strings.Join([]string{i.Name, i.PublicKeyToken, i.ProcessorArchitecture, language}, "\x00"))
}

type AssemblyBindingRedirect struct {
	OldVersion string
	NewVersion string
}

type AssemblyReference struct {
	BindingRedirects []AssemblyBindingRedirect
	// UpdateName identifies the containing CBS package update, not a component dependency.
	UpdateName string
	// ParentGroup is one-based in PackageParents; zero means not a root-package parent.
	ParentGroup    int
	Kind           string
	DependencyType string
	ResourceType   string
	Attributes     []ManifestAttribute
	Contained      bool
	Integrate      string
	Disposition    string
	Identity       AssemblyIdentity
}

type packageReferenceContext struct {
	attributes []ManifestAttribute
	contained  bool
	integrate  string
}

type parentReferenceContext struct {
	group       int
	attributes  []ManifestAttribute
	disposition string
	integrate   string
}

type dependencyReferenceContext struct {
	resourceType string
	attributes   []ManifestAttribute
}

type dependentReferenceContext struct {
	referenceIndex int
	dependencyType string
	attributes     []ManifestAttribute
}

// AssemblyFileDigest retains an XMLDSIG-style assembly file hash. Transforms
// describe the hashed bytes and must be interpreted before using it as content
// identity; a digest of a transformed PE is not a raw-file SHA-256.
type AssemblyFileDigest struct {
	Algorithm  string
	Transforms []string
	Value      string
}

type AssemblyFile struct {
	Digest          *AssemblyFileDigest
	Name            string
	SourceName      string
	SourcePath      string
	DestinationPath string
	Hash            string
	HashAlgorithm   string
	Attributes      []ManifestAttribute
	Links           []string
}

type AssemblyRegistryValue struct {
	KeyName       string
	Name          string
	ValueType     string
	Value         string
	OperationHint string
}

// AssemblyPackage retains the root package declaration separately from nested
// package references. Attributes include servicing policy such as permanence;
// they are declarations, not evidence of the package's installed state.
type AssemblyPackage struct {
	Attributes []ManifestAttribute
}

// AssemblyPackageParent preserves a single parent block. Its identity alternatives
// must not be confused with separate parent blocks when evaluating CBS policy.
type AssemblyPackageParent struct {
	// ParentGroup is a one-based enclosing block index, or zero for a root block.
	ParentGroup int
	Attributes  []ManifestAttribute
}

// AssemblyDeployment retains the component deployment declaration, including
// impact="install"/"patch". It is policy metadata, not installed-state proof.
type AssemblyDeployment struct {
	Attributes []ManifestAttribute
}

type AssemblyManifest struct {
	MOFs           []AssemblyMOF
	Deployment     *AssemblyDeployment
	PackageParents []AssemblyPackageParent
	Package        *AssemblyPackage
	PackageUpdates []AssemblyPackageUpdate
	Identity       AssemblyIdentity
	References     []AssemblyReference
	Files          []AssemblyFile
	// RegistryKeys retains declarations independently of values. CBS uses
	// empty child-key names as indexes, including UpdatedApplications.
	RegistryKeys   []string
	RegistryValues []AssemblyRegistryValue
	TopLevel       []string
}

// ParseAssemblyManifest parses CBS MUM and component manifests while keeping
// dependency kinds. It is streaming and bounds structural collections.
func ParseAssemblyManifest(reader io.Reader) (*AssemblyManifest, error) {
	return parseAssemblyManifest(xml.NewDecoder(reader))
}

// ParseAssemblyManifestBytes parses already buffered XML with the same structural
// validation as ParseAssemblyManifest. The caller must bound input size. Strings
// in the result own their backing data and never alias the mutable input slice.
func ParseAssemblyManifestBytes(data []byte) (*AssemblyManifest, error) {
	return parseAssemblyManifest(xml.NewTokenDecoder(xmltoken.New(data, false)))
}

func parseAssemblyManifest(decoder *xml.Decoder) (*AssemblyManifest, error) {
	var result AssemblyManifest
	var stack []string
	var registryKeys []string
	var fileIndexes []int
	var dependencyContexts []dependencyReferenceContext
	var dependentContexts []dependentReferenceContext
	var packageContexts []packageReferenceContext
	var parentContexts []parentReferenceContext
	var updateContexts []int
	var driverContexts [][]ManifestAttribute
	topLevel := make(map[string]struct{})
	elements := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("uup assembly manifest: %w", err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			elements++
			if elements > maximumManifestElements {
				return nil, fmt.Errorf("uup assembly manifest: element count exceeds %d", maximumManifestElements)
			}
			parent := ""
			if len(stack) != 0 {
				parent = stack[len(stack)-1]
			}
			if parent == "assembly" && token.Name.Local != "assemblyIdentity" {
				if _, exists := topLevel[token.Name.Local]; !exists {
					topLevel[token.Name.Local] = struct{}{}
					result.TopLevel = append(result.TopLevel, token.Name.Local)
				}
			}
			switch token.Name.Local {
			case "deployment":
				if len(stack) == 1 && parent == "assembly" && (token.Name.Space == "" || token.Name.Space == "urn:schemas-microsoft-com:asm.v3") {
					if result.Deployment != nil {
						return nil, fmt.Errorf("uup assembly manifest: duplicate root deployment declaration")
					}
					result.Deployment = &AssemblyDeployment{Attributes: manifestAttributes(token.Attr)}
				}
				stack = append(stack, token.Name.Local)
			case "assemblyIdentity":
				identity, err := parseAssemblyIdentity(token)
				if err != nil {
					return nil, err
				}
				if parent == "assembly" {
					if result.Identity.Name != "" {
						return nil, fmt.Errorf("uup assembly manifest: duplicate root identity")
					}
					result.Identity = identity
				} else {
					if len(result.References) >= maximumManifestReferences {
						return nil, fmt.Errorf("uup assembly manifest: reference count exceeds %d", maximumManifestReferences)
					}
					reference := AssemblyReference{Kind: parent, Identity: identity}
					if len(updateContexts) > 0 && updateContexts[len(updateContexts)-1] >= 0 {
						reference.UpdateName = result.PackageUpdates[updateContexts[len(updateContexts)-1]].Name
					}
					if parent == "dependentAssembly" {
						if len(dependentContexts) != 0 {
							context := dependentContexts[len(dependentContexts)-1]
							reference.DependencyType = context.dependencyType
							reference.Attributes = append(reference.Attributes, context.attributes...)
						}
						if len(dependencyContexts) != 0 {
							context := dependencyContexts[len(dependencyContexts)-1]
							reference.ResourceType = context.resourceType
							reference.Attributes = append(reference.Attributes, context.attributes...)
						}
					}
					if parent == "driver" && len(driverContexts) != 0 {
						reference.Attributes = append(reference.Attributes, driverContexts[len(driverContexts)-1]...)
					}
					if parent == "package" && len(packageContexts) != 0 {
						reference.Attributes = append(reference.Attributes, packageContexts[len(packageContexts)-1].attributes...)
						reference.Contained = packageContexts[len(packageContexts)-1].contained
						reference.Integrate = packageContexts[len(packageContexts)-1].integrate
					}
					if parent == "parent" && len(parentContexts) != 0 {
						reference.ParentGroup = parentContexts[len(parentContexts)-1].group
						reference.Attributes = append(reference.Attributes, parentContexts[len(parentContexts)-1].attributes...)
						reference.Disposition = parentContexts[len(parentContexts)-1].disposition
						reference.Integrate = parentContexts[len(parentContexts)-1].integrate
					}
					if parent == "dependentAssembly" && len(dependentContexts) != 0 {
						context := &dependentContexts[len(dependentContexts)-1]
						if context.referenceIndex >= 0 {
							return nil, fmt.Errorf("uup assembly manifest: multiple identities in dependentAssembly")
						}
						context.referenceIndex = len(result.References)
					}
					result.References = append(result.References, reference)
				}
				if err := decoder.Skip(); err != nil {
					return nil, fmt.Errorf("uup assembly manifest: identity: %w", err)
				}
			case "bindingRedirect":
				if parent != "dependentAssembly" || len(dependentContexts) == 0 || dependentContexts[len(dependentContexts)-1].referenceIndex < 0 {
					return nil, fmt.Errorf("uup assembly manifest: binding redirect has no dependency identity")
				}
				if token.Name.Space != "" && token.Name.Space != "urn:schemas-microsoft-com:asm.v1" {
					return nil, fmt.Errorf("uup assembly manifest: unsupported binding redirect namespace")
				}
				var redirect AssemblyBindingRedirect
				for _, a := range token.Attr {
					if a.Name.Space != "" {
						continue
					}
					switch a.Name.Local {
					case "oldVersion":
						redirect.OldVersion = a.Value
					case "newVersion":
						redirect.NewVersion = a.Value
					}
				}
				if _, ok := assemblyVersionParts(redirect.NewVersion); !ok {
					return nil, fmt.Errorf("uup assembly manifest: invalid binding redirect target")
				}
				bounds := strings.Split(redirect.OldVersion, "-")
				if len(bounds) < 1 || len(bounds) > 2 {
					return nil, fmt.Errorf("uup assembly manifest: invalid binding redirect range")
				}
				for _, bound := range bounds {
					if _, ok := assemblyVersionParts(bound); !ok {
						return nil, fmt.Errorf("uup assembly manifest: invalid binding redirect range")
					}
				}
				if len(bounds) == 2 && compareVersions(bounds[0], bounds[1]) > 0 {
					return nil, fmt.Errorf("uup assembly manifest: reversed binding redirect range")
				}
				index := dependentContexts[len(dependentContexts)-1].referenceIndex
				if result.References[index].DependencyType != "" {
					return nil, fmt.Errorf("uup assembly manifest: binding policy cannot be an explicit install/prerequisite edge")
				}
				result.References[index].BindingRedirects = append(result.References[index].BindingRedirects, redirect)
				if err := decoder.Skip(); err != nil {
					return nil, err
				}
			case "update":
				index := -1
				if parent == "package" {
					update := AssemblyPackageUpdate{Attributes: manifestAttributes(token.Attr)}
					for _, a := range token.Attr {
						if a.Name.Space == "" && a.Name.Local == "name" {
							update.Name = a.Value
						}
					}
					index = len(result.PackageUpdates)
					result.PackageUpdates = append(result.PackageUpdates, update)
				}
				updateContexts = append(updateContexts, index)
				stack = append(stack, token.Name.Local)
			case "applicable", "selectable":
				if parent == "update" && len(updateContexts) > 0 && updateContexts[len(updateContexts)-1] >= 0 {
					condition, err := readManifestCondition(decoder, token, len(stack)+1, &elements)
					if err != nil {
						return nil, fmt.Errorf("uup assembly manifest: package update condition: %w", err)
					}
					index := updateContexts[len(updateContexts)-1]
					result.PackageUpdates[index].Conditions = append(result.PackageUpdates[index].Conditions, condition)
				} else {
					stack = append(stack, token.Name.Local)
				}
			case "mof":
				if len(stack) == 1 && parent == "assembly" && token.Name.Space == "urn:schemas-microsoft-com:asm.v3" {
					if len(result.MOFs) >= maximumManifestReferences {
						return nil, fmt.Errorf("assembly MOF count exceeds bound")
					}
					mof, err := parseAssemblyMOF(decoder, token)
					if err != nil {
						return nil, err
					}
					result.MOFs = append(result.MOFs, mof)
				} else {
					stack = append(stack, token.Name.Local)
				}
			case "driver":
				// Preserve the declaration (inf, ranking, bootCritical, etc.)
				// separately from its assembly identity. Availability or a
				// dual_* filename must never substitute for this source data.
				driverContexts = append(driverContexts, manifestAttributes(token.Attr))
				stack = append(stack, token.Name.Local)
			case "file":
				if len(result.Files) >= maximumManifestFiles {
					return nil, fmt.Errorf("uup assembly manifest: file count exceeds %d", maximumManifestFiles)
				}
				file := AssemblyFile{Attributes: make([]ManifestAttribute, 0, len(token.Attr))}
				for _, attribute := range token.Attr {
					file.Attributes = append(file.Attributes, ManifestAttribute{Namespace: attribute.Name.Space, Name: attribute.Name.Local, Value: attribute.Value})
					switch attribute.Name.Local {
					case "name":
						file.Name = attribute.Value
					case "sourceName":
						file.SourceName = attribute.Value
					case "sourcePath":
						file.SourcePath = attribute.Value
					case "destinationPath":
						file.DestinationPath = attribute.Value
					case "hash":
						file.Hash = strings.ToLower(attribute.Value)
					case "hashalg":
						file.HashAlgorithm = attribute.Value
					}
				}
				if file.Name != "" {
					result.Files = append(result.Files, file)
					fileIndexes = append(fileIndexes, len(result.Files)-1)
				} else {
					fileIndexes = append(fileIndexes, -1)
				}
				stack = append(stack, token.Name.Local)
			case "hash":
				if parent != "file" || token.Name.Space != "urn:schemas-microsoft-com:asm.v2" {
					stack = append(stack, token.Name.Local)
					break
				}
				if len(fileIndexes) == 0 || fileIndexes[len(fileIndexes)-1] < 0 {
					return nil, fmt.Errorf("assembly file hash has no named file")
				}
				file := &result.Files[fileIndexes[len(fileIndexes)-1]]
				if file.Digest != nil {
					return nil, fmt.Errorf("duplicate assembly file hash")
				}
				digest, err := parseAssemblyFileDigest(decoder, token, &elements)
				if err != nil {
					return nil, err
				}
				file.Digest = digest
			case "link":
				if len(fileIndexes) == 0 || fileIndexes[len(fileIndexes)-1] < 0 {
					return nil, fmt.Errorf("uup assembly manifest: link has no file")
				}
				destination := ""
				for _, attribute := range token.Attr {
					if attribute.Name.Local == "destination" {
						destination = attribute.Value
					}
				}
				if destination == "" {
					return nil, fmt.Errorf("uup assembly manifest: link has no destination")
				}
				index := fileIndexes[len(fileIndexes)-1]
				result.Files[index].Links = append(result.Files[index].Links, destination)
				stack = append(stack, token.Name.Local)
			case "registryKey":
				keyName := ""
				for _, attribute := range token.Attr {
					if attribute.Name.Local == "keyName" {
						keyName = attribute.Value
					}
				}
				if keyName == "" {
					return nil, fmt.Errorf("uup assembly manifest: registryKey has no keyName")
				}
				result.RegistryKeys = append(result.RegistryKeys, keyName)
				registryKeys = append(registryKeys, keyName)
				stack = append(stack, token.Name.Local)
			case "registryValue":
				if len(registryKeys) == 0 || registryKeys[len(registryKeys)-1] == "" {
					return nil, fmt.Errorf("uup assembly manifest: registryValue has no registryKey")
				}
				value := AssemblyRegistryValue{KeyName: registryKeys[len(registryKeys)-1]}
				for _, attribute := range token.Attr {
					switch attribute.Name.Local {
					case "name":
						value.Name = attribute.Value
					case "valueType":
						value.ValueType = attribute.Value
					case "value":
						value.Value = attribute.Value
					case "operationHint":
						value.OperationHint = attribute.Value
					}
				}
				if value.ValueType == "" {
					return nil, fmt.Errorf("uup assembly manifest: registry value %q has no type", value.Name)
				}
				result.RegistryValues = append(result.RegistryValues, value)
				stack = append(stack, token.Name.Local)
			case "dependency":
				context := dependencyReferenceContext{}
				for _, attribute := range token.Attr {
					context.attributes = append(context.attributes, ManifestAttribute{Namespace: attribute.Name.Space, Name: attribute.Name.Local, Value: attribute.Value})
					if attribute.Name.Local == "resourceType" {
						context.resourceType = attribute.Value
					}
				}
				dependencyContexts = append(dependencyContexts, context)
				stack = append(stack, token.Name.Local)
			case "dependentAssembly":
				context := dependentReferenceContext{referenceIndex: -1}
				for _, attribute := range token.Attr {
					context.attributes = append(context.attributes, ManifestAttribute{Namespace: attribute.Name.Space, Name: attribute.Name.Local, Value: attribute.Value})
					if attribute.Name.Local == "dependencyType" {
						context.dependencyType = attribute.Value
					}
				}
				dependentContexts = append(dependentContexts, context)
				stack = append(stack, token.Name.Local)
			case "package":
				if len(stack) == 1 && parent == "assembly" && (token.Name.Space == "" || token.Name.Space == "urn:schemas-microsoft-com:asm.v3") {
					if result.Package != nil {
						return nil, fmt.Errorf("uup assembly manifest: duplicate root package declaration")
					}
					result.Package = &AssemblyPackage{Attributes: manifestAttributes(token.Attr)}
				}
				context := packageReferenceContext{attributes: manifestAttributes(token.Attr)}
				for _, attribute := range token.Attr {
					switch attribute.Name.Local {
					case "contained":
						switch strings.ToLower(strings.TrimSpace(attribute.Value)) {
						case "true":
							context.contained = true
						case "false", "":
						default:
							return nil, fmt.Errorf("uup assembly manifest: invalid package contained value %q", attribute.Value)
						}
					case "integrate":
						context.integrate = attribute.Value
					}
				}
				packageContexts = append(packageContexts, context)
				stack = append(stack, token.Name.Local)
			case "parent":
				context := parentReferenceContext{}
				rootParent := len(stack) == 2 && stack[0] == "assembly" && parent == "package" && result.Package != nil
				parentGroup := 0
				if parent == "parent" && len(parentContexts) > 0 {
					parentGroup = parentContexts[len(parentContexts)-1].group
				}
				if (rootParent || parentGroup > 0) && (token.Name.Space == "" || token.Name.Space == "urn:schemas-microsoft-com:asm.v3") {
					result.PackageParents = append(result.PackageParents, AssemblyPackageParent{ParentGroup: parentGroup, Attributes: manifestAttributes(token.Attr)})
					context.group = len(result.PackageParents)
				}
				for _, attribute := range token.Attr {
					context.attributes = append(context.attributes, ManifestAttribute{Namespace: attribute.Name.Space, Name: attribute.Name.Local, Value: attribute.Value})
					switch attribute.Name.Local {
					case "disposition":
						context.disposition = attribute.Value
					case "integrate":
						context.integrate = attribute.Value
					}
				}
				parentContexts = append(parentContexts, context)
				stack = append(stack, token.Name.Local)
			default:
				stack = append(stack, token.Name.Local)
			}
			if len(stack) > maximumManifestDepth {
				return nil, fmt.Errorf("uup assembly manifest: nesting exceeds %d", maximumManifestDepth)
			}
		case xml.EndElement:
			if token.Name.Local == "assemblyIdentity" {
				continue
			}
			if len(stack) == 0 || stack[len(stack)-1] != token.Name.Local {
				return nil, fmt.Errorf("uup assembly manifest: unbalanced %s element", token.Name.Local)
			}
			if token.Name.Local == "registryKey" {
				if len(registryKeys) == 0 {
					return nil, fmt.Errorf("uup assembly manifest: unbalanced registryKey element")
				}
				registryKeys = registryKeys[:len(registryKeys)-1]
			}
			if token.Name.Local == "update" {
				if len(updateContexts) == 0 {
					return nil, fmt.Errorf("unbalanced update element")
				}
				updateContexts = updateContexts[:len(updateContexts)-1]
			}
			if token.Name.Local == "driver" {
				if len(driverContexts) == 0 {
					return nil, fmt.Errorf("uup assembly manifest: unbalanced driver element")
				}
				driverContexts = driverContexts[:len(driverContexts)-1]
			}
			if token.Name.Local == "file" {
				if len(fileIndexes) == 0 {
					return nil, fmt.Errorf("uup assembly manifest: unbalanced file element")
				}
				fileIndexes = fileIndexes[:len(fileIndexes)-1]
			}
			if token.Name.Local == "dependentAssembly" {
				if len(dependentContexts) == 0 {
					return nil, fmt.Errorf("uup assembly manifest: unbalanced dependentAssembly element")
				}
				dependentContexts = dependentContexts[:len(dependentContexts)-1]
			}
			if token.Name.Local == "dependency" {
				if len(dependencyContexts) == 0 {
					return nil, fmt.Errorf("uup assembly manifest: unbalanced dependency element")
				}
				dependencyContexts = dependencyContexts[:len(dependencyContexts)-1]
			}
			if token.Name.Local == "package" {
				if len(packageContexts) == 0 {
					return nil, fmt.Errorf("uup assembly manifest: unbalanced package element")
				}
				packageContexts = packageContexts[:len(packageContexts)-1]
			}
			if token.Name.Local == "parent" {
				if len(parentContexts) == 0 {
					return nil, fmt.Errorf("uup assembly manifest: unbalanced parent element")
				}
				parentContexts = parentContexts[:len(parentContexts)-1]
			}
			stack = stack[:len(stack)-1]
		}
	}
	if result.Identity.Name == "" {
		return nil, fmt.Errorf("uup assembly manifest: missing root identity")
	}
	return &result, nil
}

func parseAssemblyIdentity(start xml.StartElement) (AssemblyIdentity, error) {
	var result AssemblyIdentity
	result.Attributes = make([]ManifestAttribute, 0, len(start.Attr))
	for _, attribute := range start.Attr {
		if attribute.Name.Space == "xmlns" || attribute.Name.Local == "xmlns" {
			continue
		}
		result.Attributes = append(result.Attributes, ManifestAttribute{Namespace: attribute.Name.Space, Name: attribute.Name.Local, Value: attribute.Value})
		switch attribute.Name.Local {
		case "name":
			result.Name = attribute.Value
		case "version":
			result.Version = attribute.Value
		case "processorArchitecture":
			result.ProcessorArchitecture = attribute.Value
		case "language":
			result.Language = attribute.Value
		case "publicKeyToken":
			result.PublicKeyToken = attribute.Value
		case "buildType":
			result.BuildType = attribute.Value
		case "versionScope":
			result.VersionScope = attribute.Value
		}
	}
	if result.Name == "" {
		return AssemblyIdentity{}, fmt.Errorf("uup assembly manifest: identity has no name")
	}
	return result, nil
}
