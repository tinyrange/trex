package uup

import (
	"fmt"
	"strings"
)

// cbsEditionSelection implements the custom-information gate on IsSelectable,
// not an applicability predicate. Native offline CBS compares both resolved
// session edition names case-insensitively; neither is inferred from a SKU.
func cbsEditionSelection(c ManifestCondition, editions []string) (bool, error) {
	enabled := true
	seen := false
	for _, custom := range c.Children {
		if custom.Name != "customInformation" {
			continue
		}
		if seen {
			return false, fmt.Errorf("duplicate CBS selection customInformation")
		}
		seen = true
		if _, err := cbsConditionAttributes(custom); err != nil {
			return false, err
		}
		if len(custom.Children) != 1 || custom.Children[0].Name != "EnableSelectabilityForEditions" {
			return false, fmt.Errorf("unsupported CBS selection customInformation")
		}
		list := custom.Children[0]
		if _, err := cbsConditionAttributes(list); err != nil {
			return false, err
		}
		if len(editions) == 0 || len(editions) > 2 {
			return false, fmt.Errorf("CBS edition selection requires resolved current/target edition names")
		}
		for _, edition := range editions {
			if edition == "" {
				return false, fmt.Errorf("empty CBS session edition name")
			}
		}
		enabled = false
		for _, entry := range list.Children {
			a, err := cbsConditionAttributes(entry, "name")
			if err != nil {
				return false, err
			}
			if entry.Name != "EnableSelectabilityForEdition" || a["name"] == "" || len(entry.Children) != 0 {
				return false, fmt.Errorf("unsupported CBS edition selection entry")
			}
			for _, edition := range editions {
				enabled = enabled || strings.EqualFold(edition, a["name"])
			}
		}
	}
	return enabled, nil
}
