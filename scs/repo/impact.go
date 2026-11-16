package repo

import (
	"context"
	"fmt"
	"sort"
)

// TargetSpec is caller-supplied build policy, not an inferred dependency graph.
// A target is affected if any changed path matches any of its whole-path globs.
type TargetSpec struct {
	Name     string
	Patterns []string
}

func AffectedTargets(ctx context.Context, before, after *Workspace, targets []TargetSpec, limits DiffOptions) ([]string, error) {
	if limits.MaxMatches < 0 {
		return nil, fmt.Errorf("invalid target match limit")
	}
	if limits.MaxMatches == 0 {
		limits.MaxMatches = 100000
	}
	if len(targets) > 10000 {
		return nil, ErrQueryLimit
	}
	seen := map[string]bool{}
	for _, target := range targets {
		if target.Name == "" || len(target.Name) > 4096 || seen[target.Name] || len(target.Patterns) > 256 {
			return nil, fmt.Errorf("invalid target specification")
		}
		seen[target.Name] = true
		for _, pattern := range target.Patterns {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if _, err := Match(pattern, ""); err != nil {
				return nil, err
			}
		}
	}
	changes, err := DiffLimited(ctx, before, after, limits)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, target := range targets {
		affected := false
		for _, c := range changes {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			for _, pattern := range target.Patterns {
				if limits.MaxMatches == 0 {
					return nil, ErrQueryLimit
				}
				limits.MaxMatches--
				yes, _ := Match(pattern, c.Path)
				if yes {
					affected = true
					break
				}
			}
			if affected {
				break
			}
		}
		if affected {
			out = append(out, target.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}
