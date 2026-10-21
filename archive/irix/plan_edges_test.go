package irix

import (
	"testing"
)

func TestPlanLatestVersionAfterOlderDuplicates(t *testing.T) {
	p := append(append(planProducts(1), planProducts(1)...), planProducts(2)...)
	result, err := Plan(p, basicOptions(t))
	if err != nil || result.Selected[0].Version != 2 {
		t.Fatal(result, err)
	}
}
func TestPlanOpaquePolicyAndOrderedLinks(t *testing.T) {
	p := planProducts(2)
	p[0].Images[0].Subsystems[0].Final = []Mark{{Product: "old", Image: "sw", Subsystem: "base", Low: 0, High: 9}}
	result, err := Plan(p, basicOptions(t))
	if err != nil || len(result.Issues) != 1 || result.Issues[0].Kind != "descriptor_extension" {
		t.Fatal(result, err)
	}
	p = planProducts(2)
	o := basicOptions(t)
	o.Indexes["main@2"][0].Attributes = append(o.Indexes["main@2"][0].Attributes, "links(b)")
	// Link declarations come from the index, not from payload pathname records.
	result, err = Plan(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Operations) != 2 || result.Operations[0].Kind != "file" || result.Operations[1].Kind != "hardlink" || result.Operations[1].Target != "/a" {
		t.Fatal(result)
	}
	o.Indexes["main@2"][0].Attributes = append(o.Indexes["main@2"][0].Attributes, "future_policy")
	result, err = Plan(p, o)
	if err != nil || len(result.Issues) != 1 || result.Issues[0].Kind != "unsupported_attribute" {
		t.Fatal(result, err)
	}
}
func TestPlanDeviceIdentityAndCollision(t *testing.T) {
	p := planProducts(2)
	o := basicOptions(t)
	item := o.Indexes["main@2"][0]
	item.Kind = "c"
	item.Attributes = []string{"main.sw.bin", "maj(8)", "min(0)"}
	o.Indexes["main@2"] = []Item{item}
	o.Images = nil
	result, err := Plan(p, o)
	if err != nil || len(result.Issues) != 0 || result.Operations[0].Major != 8 || result.Operations[0].Minor != 0 {
		t.Fatal(result, err)
	}
	item.Attributes = item.Attributes[:2]
	o.Indexes["main@2"] = []Item{item}
	result, err = Plan(p, o)
	if err != nil || len(result.Issues) != 1 || result.Issues[0].Kind != "missing_device_identity" {
		t.Fatal(result, err)
	}
	item.Kind = "l"
	item.Attributes = []string{"main.sw.bin", "symval(a)", "links(a)"}
	o.Indexes["main@2"] = []Item{item}
	result, err = Plan(p, o)
	if err != nil || len(result.Issues) != 1 || result.Issues[0].Kind != "destination_conflict" {
		t.Fatal(result, err)
	}
}

func TestPlanUnknownPolicyContainingDots(t *testing.T) {
	options := basicOptions(t)
	options.Indexes["main@2"][0].Attributes = append(options.Indexes["main@2"][0].Attributes, "future_policy(/etc/example.conf)")
	result, err := Plan(planProducts(2), options)
	if err != nil || len(result.Issues) != 1 || result.Issues[0].Kind != "unsupported_attribute" {
		t.Fatal(result, err)
	}
}
