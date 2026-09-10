package uup

import (
	"strings"
	"testing"
)

func TestBuildCanonicalGraphResolvesFileBasis(t *testing.T) {
	index, err := ParseContainerIndex(strings.NewReader(`<Container name="u.cab" type="CAB" length="3" version="1"><Files>
<File id="1" name="component\a" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" name="0"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File>
<File id="2" name="component\b" length="2"><Hash alg="SHA256" value="` + cixHashB + `"/><Delta><Source type="PA30" name="1"><Hash alg="SHA256" value="` + cixHashA + `"/></Source><Basis file="1"/></Delta></File>
</Files></Container>`))
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildCanonicalGraph(index, map[string]int64{"0": 1, "1": 7})
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Payloads) != 2 || graph.Payloads[1].RecordType != "PA30" || graph.Payloads[1].Record.Length != 7 || graph.Payloads[1].Basis == nil || graph.Payloads[1].Basis.Name != `component\a` {
		t.Fatalf("graph = %#v", graph)
	}
}

func TestBuildCanonicalGraphRejectsBasisCycle(t *testing.T) {
	index, err := ParseContainerIndex(strings.NewReader(`<Container name="u.cab" type="CAB" length="2" version="1"><Files>
<File id="1" name="a" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="PA30" name="0"><Hash alg="SHA256" value="` + cixHashA + `"/></Source><Basis file="2"/></Delta></File>
<File id="2" name="b" length="1"><Hash alg="SHA256" value="` + cixHashB + `"/><Delta><Source type="PA30" name="1"><Hash alg="SHA256" value="` + cixHashB + `"/></Source><Basis file="1"/></Delta></File>
</Files></Container>`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildCanonicalGraph(index, map[string]int64{"0": 1, "1": 1}); err == nil {
		t.Fatal("expected basis cycle rejection")
	}
}
