package uup

import (
	"strings"
	"testing"
)

func mustHash(t *testing.T, value string) [32]byte {
	t.Helper()
	hash, err := parseCIXHash(rawCIXHash{Algorithm: "SHA256", Value: value})
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func TestBuildCumulativeGraphJoinsExactBasisAndRecord(t *testing.T) {
	psf, err := ParseContainerIndex(strings.NewReader(`<Container name="u.psf" type="PSF" length="100" version="1"><Files><File id="1" name="component\f\a.dll" length="20"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" offset="40" length="20"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File></Files></Container>`))
	if err != nil {
		t.Fatal(err)
	}
	history, err := ParseContainerIndex(strings.NewReader(`<Container name="PSFX.CIX" type="PSFX" version="2"><Files>
<File id="1" name="component\a.dll" length="30"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="PA30" name="component\f\a.dll"><Hash alg="SHA256" value="` + cixHashA + `"/></Source><Basis length="10"><Hash alg="SHA256" value="` + cixHashB + `"/></Basis></Delta></File>
<File id="2" name="newcomponent\a.dll" length="10"><Hash alg="SHA256" value="` + cixHashB + `"/><Delta><Source type="RAW" name="oldcomponent\a.dll"><Hash alg="SHA256" value="` + cixHashB + `"/></Source></Delta></File>
</Files></Container>`))
	if err != nil {
		t.Fatal(err)
	}
	graph, err := BuildCumulativeGraph(psf, history)
	if err != nil {
		t.Fatal(err)
	}
	if len(graph.Payloads) != 1 || len(graph.Sources) != 1 || len(graph.Carries) != 1 || graph.Payloads[0].RecordOffset != 40 || graph.Payloads[0].Basis == nil || graph.Payloads[0].Basis.SHA256 != mustHash(t, cixHashB) {
		t.Fatalf("graph = %#v", graph)
	}
	if graph.Carries[0].Target.Name != `newcomponent\a.dll` || graph.Carries[0].Source.Name != `oldcomponent\a.dll` || graph.Carries[0].Target.SHA256 != graph.Carries[0].Source.SHA256 {
		t.Fatalf("carry = %#v", graph.Carries[0])
	}
}

func TestBuildCumulativeGraphRejectsUnboundedRecord(t *testing.T) {
	psf, _ := ParseContainerIndex(strings.NewReader(`<Container name="u.psf" type="PSF" length="50" version="1"><Files><File id="1" name="a" length="20"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" offset="40" length="20"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File></Files></Container>`))
	history, _ := ParseContainerIndex(strings.NewReader(`<Container name="PSFX.CIX" type="PSFX" version="2"><Files><File id="1" name="b" length="30"><Hash alg="SHA256" value="` + cixHashB + `"/><Delta><Source type="PA30" name="a"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File></Files></Container>`))
	if _, err := BuildCumulativeGraph(psf, history); err == nil {
		t.Fatal("expected out-of-range record rejection")
	}
}

func TestResolveEdgeBasisPreservesExplicitLength(t *testing.T) {
	hash := mustHash(t, cixHashB)
	graph := &CumulativeGraph{Sources: []ContentDescriptor{{
		Name: `component_1\data.bin`, Length: 30, SHA256: hash,
	}}}
	basis, err := graph.resolveEdgeBasis(CIXBasis{Length: 10, Hash: hash})
	if err != nil {
		t.Fatal(err)
	}
	if basis.Name != `component_1\data.bin` || basis.Length != 10 || basis.SHA256 != hash {
		t.Fatalf("basis = %#v", basis)
	}
}
