package uup

import (
	"strings"
	"testing"
)

const cixHashA = "36BE3CE3EFF046B2CDB7B6493027FEC2D92065F0B75F164C4D0C279A511A320E"
const cixHashB = "3C76859EE8DA0964BD297CB2199A2DD26B6145F8454A7EDC685B4F15BAA4AE04"

func TestParseContainerIndexPSFRecord(t *testing.T) {
	xml := `<?xml version="1.0"?><Container name="update.psf" type="PSF" length="2324733034" version="1" xmlns="urn:ContainerIndex">
<DeltaBasisSearch><Location id="0" path="{windir}\winsxs" flags="2000001" /></DeltaBasisSearch><Files>
<File id="78770" name="amd64_microsoft-windows-directcomposition_31bf3856ad364e35_10.0.26100.8972_none_3907531ff1ec3e71\f\dcomp.dll" length="156834" time="134292812840000000" attr="128">
<Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" offset="1275150657" length="156834"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File>
</Files></Container>`
	index, err := ParseContainerIndex(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if index.Type != "PSF" || index.Length != 2324733034 || len(index.Files) != 1 || len(index.Locations) != 1 {
		t.Fatalf("unexpected index: %+v", index)
	}
	file := index.Files[0]
	if file.ID != 78770 || file.Length != 156834 || len(file.Sources) != 1 || file.Sources[0].Offset != 1275150657 || file.Sources[0].Length != 156834 {
		t.Fatalf("unexpected file: %+v", file)
	}
}

func TestParseContainerIndexHistoryBasis(t *testing.T) {
	xml := `<Container name="PSFX.CIX" type="PSFX" version="2" xmlns="urn:ContainerIndex"><Files>
<File id="1" name="amd64_component_31bf3856ad364e35_10.0.26100.8972_none_hash\dcomp.dll" length="2257616" attr="32">
<Hash alg="SHA256" value="` + cixHashA + `"/><Delta>
<Source type="PA30" name="amd64_component_31bf3856ad364e35_10.0.26100.8972_none_hash\f\dcomp.dll"><Hash alg="SHA256" value="` + cixHashA + `"/></Source>
<Basis length="2236896"><Hash alg="SHA256" value="` + cixHashB + `"/></Basis>
</Delta></File></Files></Container>`
	index, err := ParseContainerIndex(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	file := index.Files[0]
	if index.Type != "PSFX" || file.Sources[0].Type != "PA30" || file.Sources[0].Offset != -1 || file.Bases[0].Length != 2236896 {
		t.Fatalf("unexpected history entry: %+v", file)
	}
}

func TestParseContainerIndexCabinetFileBasis(t *testing.T) {
	index, err := ParseContainerIndex(strings.NewReader(`<Container name="u.cab" type="CAB" length="100" version="1"><Files>
<File id="1" name="a" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" name="0"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File>
<File id="2" name="b" length="2"><Hash alg="SHA256" value="` + cixHashB + `"/><Delta><Source type="PA30" name="1"><Hash alg="SHA256" value="` + cixHashA + `"/></Source><Basis file="1"/></Delta></File>
</Files></Container>`))
	if err != nil {
		t.Fatal(err)
	}
	if index.Type != "CAB" || len(index.Files) != 2 || len(index.Files[1].Bases) != 1 || index.Files[1].Bases[0].FileID != 1 || index.Files[1].Bases[0].Length != -1 {
		t.Fatalf("index = %#v", index)
	}
}

func TestParseContainerIndexRejectsAmbiguousRecords(t *testing.T) {
	for _, xml := range []string{
		`<Container name="x" type="PSF" length="1" version="1"><Files><File id="1" name="a" length="1"><Hash alg="SHA1" value="00"/><Delta><Source type="RAW" offset="0" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File></Files></Container>`,
		`<Container name="x" type="PSF" length="1" version="1"><Files><File id="1" name="a" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" offset="0"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File></Files></Container>`,
		`<Container name="x" type="PSF" length="1" version="1"><Files><File id="1" name="a" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" offset="0" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File><File id="1" name="b" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/><Delta><Source type="RAW" offset="0" length="1"><Hash alg="SHA256" value="` + cixHashA + `"/></Source></Delta></File></Files></Container>`,
	} {
		if _, err := ParseContainerIndex(strings.NewReader(xml)); err == nil {
			t.Fatalf("expected malformed CIX rejection for %s", xml)
		}
	}
}
