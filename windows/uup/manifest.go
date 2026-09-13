package uup

import (
	"encoding/xml"
	"fmt"
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

type AssemblyReference struct {
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
	contained bool
	integrate string
}

type parentReferenceContext struct {
	disposition string
	integrate   string
}

type dependencyReferenceContext struct {
	resourceType string
	attributes   []ManifestAttribute
}

type dependentReferenceContext struct {
	dependencyType string
	attributes     []ManifestAttribute
}

type AssemblyFile struct {
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

type AssemblyManifest struct {
	Identity   AssemblyIdentity
	References []AssemblyReference
	Files      []AssemblyFile
	// RegistryKeys retains declarations independently of values. CBS uses
	// empty child-key names as indexes, including UpdatedApplications.
	RegistryKeys   []string
	RegistryValues []AssemblyRegistryValue
	TopLevel       []string
}

// ParseAssemblyManifest parses CBS MUM and component manifests while keeping
// dependency kinds. It is streaming and bounds structural collections.
func ParseAssemblyManifest(reader io.Reader) (*AssemblyManifest, error) {
	decoder := xml.NewDecoder(reader)
	var result AssemblyManifest
	var stack []string
	var registryKeys []string
	var fileIndexes []int
	var dependencyContexts []dependencyReferenceContext
	var dependentContexts []dependentReferenceContext
	var packageContexts []packageReferenceContext
	var parentContexts []parentReferenceContext
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
					if parent == "package" && len(packageContexts) != 0 {
						reference.Contained = packageContexts[len(packageContexts)-1].contained
						reference.Integrate = packageContexts[len(packageContexts)-1].integrate
					}
					if parent == "parent" && len(parentContexts) != 0 {
						reference.Disposition = parentContexts[len(parentContexts)-1].disposition
						reference.Integrate = parentContexts[len(parentContexts)-1].integrate
					}
					result.References = append(result.References, reference)
				}
				if err := decoder.Skip(); err != nil {
					return nil, fmt.Errorf("uup assembly manifest: identity: %w", err)
				}
			case "file":
				if len(result.Files) >= maximumManifestFiles {
					return nil, fmt.Errorf("uup assembly manifest: file count exceeds %d", maximumManifestFiles)
				}
				var file AssemblyFile
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
				context := dependentReferenceContext{}
				for _, attribute := range token.Attr {
					context.attributes = append(context.attributes, ManifestAttribute{Namespace: attribute.Name.Space, Name: attribute.Name.Local, Value: attribute.Value})
					if attribute.Name.Local == "dependencyType" {
						context.dependencyType = attribute.Value
					}
				}
				dependentContexts = append(dependentContexts, context)
				stack = append(stack, token.Name.Local)
			case "package":
				context := packageReferenceContext{}
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
				for _, attribute := range token.Attr {
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
