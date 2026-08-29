package windows

import (
	"encoding/xml"
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"strings"

	"go.starlark.net/starlark"
)

type assemblyManifestAttribute struct {
	namespace string
	name      string
	value     string
}

type assemblyManifestIdentity struct{ attributes []assemblyManifestAttribute }

func (identity *assemblyManifestIdentity) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	identity.attributes = identity.attributes[:0]
	for _, attribute := range start.Attr {
		if attribute.Name.Space == "xmlns" || attribute.Name.Local == "xmlns" {
			continue
		}
		identity.attributes = append(identity.attributes, assemblyManifestAttribute{namespace: attribute.Name.Space, name: attribute.Name.Local, value: attribute.Value})
	}
	return decoder.Skip()
}

type assemblyManifestFile struct {
	Name          string `xml:"name,attr"`
	Hash          string `xml:"hash,attr"`
	HashAlgorithm string `xml:"hashalg,attr"`
}
type assemblyManifest struct {
	Identity assemblyManifestIdentity `xml:"assemblyIdentity"`
	Files    []assemblyManifestFile   `xml:"file"`
}

func assemblyManifestBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("assembly_manifest", args, kwargs, "value", &value); err != nil {
		return nil, err
	}
	data, err := bytesForValue(value)
	if err != nil {
		return nil, fmt.Errorf("assembly_manifest: %w", err)
	}
	var manifest assemblyManifest
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("assembly_manifest: parse XML: %w", err)
	}
	attributes := make([]starlark.Value, len(manifest.Identity.attributes))
	for index, attribute := range manifest.Identity.attributes {
		attributes[index] = starfile.NewRecord(starlark.StringDict{"namespace": starlark.String(attribute.namespace), "name": starlark.String(attribute.name), "value": starlark.String(attribute.value)})
	}
	files := make([]starlark.Value, len(manifest.Files))
	for index, file := range manifest.Files {
		files[index] = starfile.NewRecord(starlark.StringDict{"name": starlark.String(file.Name), "hash": starlark.String(strings.ToLower(file.Hash)), "hash_algorithm": starlark.String(file.HashAlgorithm)})
	}
	return starfile.NewRecord(starlark.StringDict{"identity": starlark.NewList(attributes), "files": starlark.NewList(files)}), nil
}
