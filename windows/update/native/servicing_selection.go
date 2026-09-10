package native

import (
	"fmt"
	"strings"

	"github.com/tinyrange/trex/windows/uup"
)

// selectServicingFiles narrows an inspection, without changing the production
// plan or silently accepting a misspelled selector as a successful empty run.
func selectServicingFiles(files []uup.StageFileEffect, names []string) ([]uup.StageFileEffect, error) {
	if len(names) == 0 {
		return files, nil
	}
	key := func(name string) string { return strings.ToLower(strings.ReplaceAll(name, "/", `\`)) }
	wanted := make(map[string]bool, len(names))
	for _, name := range names {
		wanted[key(name)] = false
	}
	var selected []uup.StageFileEffect
	for _, file := range files {
		name := key(file.SourceName)
		if _, ok := wanted[name]; ok {
			selected = append(selected, file)
			wanted[name] = true
		}
	}
	for _, name := range names {
		if !wanted[key(name)] {
			return nil, fmt.Errorf("source name %q is absent from the selected plan", name)
		}
	}
	return selected, nil
}
