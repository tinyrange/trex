package uup

import (
	"encoding/xml"
	"fmt"
)

// ManifestCondition preserves a package update's condition tree, including
// namespaces and attributes. Presence in a selected package is not evidence
// that a selectable feature should be installed at runtime.
type ManifestCondition struct {
	Namespace  string
	Name       string
	Attributes []ManifestAttribute
	Children   []ManifestCondition
}

type AssemblyPackageUpdate struct {
	Name       string
	Attributes []ManifestAttribute
	Conditions []ManifestCondition
}

func manifestAttributes(attrs []xml.Attr) []ManifestAttribute {
	result := make([]ManifestAttribute, 0, len(attrs))
	for _, a := range attrs {
		result = append(result, ManifestAttribute{Namespace: a.Name.Space, Name: a.Name.Local, Value: a.Value})
	}
	return result
}

func readManifestCondition(decoder *xml.Decoder, start xml.StartElement, depth int, elements *int) (ManifestCondition, error) {
	if depth > maximumManifestDepth {
		return ManifestCondition{}, fmt.Errorf("package update condition exceeds nesting bound")
	}
	result := ManifestCondition{Namespace: start.Name.Space, Name: start.Name.Local, Attributes: manifestAttributes(start.Attr)}
	for {
		token, err := decoder.Token()
		if err != nil {
			return ManifestCondition{}, err
		}
		switch token := token.(type) {
		case xml.StartElement:
			*elements++
			if *elements > maximumManifestElements {
				return ManifestCondition{}, fmt.Errorf("package update condition exceeds element bound")
			}
			child, err := readManifestCondition(decoder, token, depth+1, elements)
			if err != nil {
				return ManifestCondition{}, err
			}
			result.Children = append(result.Children, child)
		case xml.EndElement:
			if token.Name != start.Name {
				return ManifestCondition{}, fmt.Errorf("unbalanced package update condition")
			}
			return result, nil
		case xml.CharData:
			for _, b := range token {
				if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
					return ManifestCondition{}, fmt.Errorf("unsupported text in package update condition %q", start.Name.Local)
				}
			}
		}
	}
}

func packagePlanMetadata(manifest *AssemblyManifest) *AssemblyManifest {
	return &AssemblyManifest{Identity: manifest.Identity, Package: manifest.Package, PackageParents: manifest.PackageParents, References: manifest.References, PackageUpdates: manifest.PackageUpdates}
}
