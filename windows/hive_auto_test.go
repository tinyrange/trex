package windows

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/tinyrange/trex/auto"
)

func TestHiveAutoBrowseGenerations(t *testing.T) {
	for _, minor := range []uint32{1, 3, 5} {
		root := newRegistryTree("SOFTWARE")
		setRegistryValue(root, "/Example/Nested", "Greeting", registryString(regSZ, "hello"))
		data, err := buildRegistryHiveWithFormat(root, registryHiveFormat{major: 1, minor: minor})
		if err != nil {
			t.Fatal(err)
		}
		node := auto.Open(bytes.NewReader(data), "SOFTWARE", auto.Options{})
		metadata, err := node.Metadata()
		if err != nil || metadata.Format != "hive" || !metadata.Container {
			t.Fatalf("generation %d: %+v %v", minor, metadata, err)
		}
		value, err := node.Resolve("Example/Nested/_values.json")
		if err != nil {
			t.Fatalf("generation %d: %v", minor, err)
		}
		reader := value.Reader()
		result, err := io.ReadAll(io.NewSectionReader(reader, 0, reader.Size()))
		if err != nil || !strings.Contains(string(result), "Greeting") || !strings.Contains(string(result), "hello") {
			t.Fatalf("generation %d values: %s %v", minor, result, err)
		}
		if _, err := node.Resolve("eXAMPLE/nESTED/_values.json"); err != nil {
			t.Fatalf("generation %d registry lookup lost case folding: %v", minor, err)
		}
	}
}
