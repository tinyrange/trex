package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"testing"
)

func TestWMIModernAppendHasSelectableCheckpoint(t *testing.T) {
	r := modernTestSeed(t, `class Proof { [key] string Name; }; instance of Proof {Name="native";};`)
	var maps [3]wmiModernMapping
	for i := range maps {
		name := fmt.Sprintf("MAPPING%d.MAP", i+1)
		raw, err := readWMIRepositoryFile(r.files[name].(starfile.File), name)
		if err != nil {
			t.Fatal(err)
		}
		maps[i], err = parseWMIModernMapping(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []wmiModernSection{maps[i].objects, maps[i].index} {
			if s.first != s.second+1 {
				t.Fatal("invalid checkpoint epoch pair")
			}
			for _, e := range s.entries {
				if e.first != s.first || e.second > s.first {
					t.Fatal("entry belongs to another epoch")
				}
			}
		}
	}
	// OpenRepositoryFiles scans the cyclic checkpoint list for a descending
	// epoch edge. A generation-only difference is insufficient: tied epoch pairs
	// are rejected before page validation, even when every page and CRC is valid.
	selected := -1
	for i, m := range maps {
		next := maps[(i+1)%len(maps)]
		if m.objects.first > next.objects.first && m.objects.second >= next.objects.second {
			if selected != -1 {
				t.Fatal("ambiguous checkpoint order")
			}
			selected = i
		}
	}
	if selected < 0 || maps[selected].clean != 1 || maps[selected].objects.generation != r.modern.objects.generation {
		t.Fatalf("no clean newest checkpoint: %d", selected)
	}
}
