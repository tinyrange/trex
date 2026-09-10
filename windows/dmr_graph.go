package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/windows/dmr"
	"go.starlark.net/starlark"
)

// dmrGraphBuiltin serializes an already selected and ordered graph. Dependency
// selection and Windows version/architecture policy do not live in this codec.
func dmrGraphBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var nodes *starlark.List
	if err := starlark.UnpackArgs("dmr_graph", args, kwargs, "nodes", &nodes); err != nil {
		return nil, err
	}
	if nodes.Len() < 1 || nodes.Len() > 641 {
		return nil, fmt.Errorf("dmr_graph: node count must be 1..641")
	}
	graph := make([]dmr.Node, nodes.Len())
	for i := range graph {
		d, ok := nodes.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("dmr_graph: node %d must be a dictionary", i)
		}
		n := &graph[i]
		var properties starlark.Value = starlark.None
		if err := starlark.UnpackArgs("dmr_graph node", nil, d.Items(),
			"name", &n.Identity.Name, "publisher_id", &n.Identity.PublisherID, "publisher", &n.Identity.Publisher,
			"full_name", &n.Identity.FullName, "version", &n.Identity.Version, "architecture", &n.Identity.Architecture,
			"flags", &n.Identity.Flags, "installation_path", &n.InstallationPath,
			"resource_id?", &n.Identity.ResourceID, "properties?", &properties); err != nil {
			return nil, err
		}
		if properties != starlark.None {
			p, ok := properties.(*starlark.Dict)
			if !ok {
				return nil, fmt.Errorf("dmr_graph: properties must be a dictionary or None")
			}
			n.Properties = &dmr.NodeProperties{}
			if err := starlark.UnpackArgs("dmr_graph properties", nil, p.Items(),
				"minimum_version", &n.Properties.Value8, "maximum_version_tested", &n.Properties.Value16,
				"display_name", &n.Properties.Strings[0], "publisher_display_name?", &n.Properties.Strings[1],
				"description?", &n.Properties.Strings[2], "logo?", &n.Properties.Strings[3]); err != nil {
				return nil, err
			}
		}
	}
	data, err := dmr.EncodeGraph(graph)
	if err != nil {
		return nil, err
	}
	return &starfile.Bytes{Data: data}, nil
}
