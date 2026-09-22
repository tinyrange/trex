package windows

import (
	"encoding/binary"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
)

// WinsockCatalogItem serializes an NT Winsock 2 Protocol_Catalog9 entry.
// protocol is a WSAPROTOCOL_INFOW record obtained from the transport helper;
// library identifies a guest provider DLL, not a host filesystem path.
// Windows 2000 ws2_32 persists an ANSI MAX_PATH buffer followed by the 628-byte
// record, assigning the provider GUID and catalog ID during installation.
func WinsockCatalogItem(library string, protocol, provider []byte, catalogID uint32) ([]byte, error) {
	if len(library) == 0 || len(library) >= 260 || strings.IndexByte(library, 0) >= 0 {
		return nil, fmt.Errorf("Winsock catalog: invalid provider library")
	}
	for _, c := range library {
		if c > 127 {
			return nil, fmt.Errorf("Winsock catalog: provider library requires ASCII")
		}
	}
	if len(protocol) != 628 || len(provider) != 16 || catalogID == 0 {
		return nil, fmt.Errorf("Winsock catalog: invalid protocol, provider GUID, or catalog ID")
	}
	if binary.LittleEndian.Uint32(protocol[40:]) > 7 {
		return nil, fmt.Errorf("Winsock catalog: protocol chain exceeds seven entries")
	}
	terminated := false
	for i := 116; i < len(protocol); i += 2 {
		if binary.LittleEndian.Uint16(protocol[i:]) == 0 {
			terminated = true
			break
		}
	}
	if !terminated {
		return nil, fmt.Errorf("Winsock catalog: unterminated protocol name")
	}
	data := make([]byte, 888)
	copy(data, library)
	copy(data[260:], protocol)
	copy(data[280:], provider)
	binary.LittleEndian.PutUint32(data[296:], catalogID)
	return data, nil
}

func winsockCatalogItemBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var library string
	var protocol, provider starlark.Bytes
	var catalogID uint32
	if err := starlark.UnpackArgs("winsock_catalog_item", args, kwargs, "library", &library, "protocol", &protocol, "provider", &provider, "catalog_id", &catalogID); err != nil {
		return nil, err
	}
	data, err := WinsockCatalogItem(library, []byte(protocol), []byte(provider), catalogID)
	return starlark.Bytes(data), err
}
