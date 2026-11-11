package repo

import (
	"context"
	"errors"
	"sort"
)

type gitQuery struct {
	ctx     context.Context
	r       *Repository
	max     int
	parents map[GitOID][]GitOID
}

func newGitQuery(ctx context.Context, r *Repository, limits GraphLimits) (*gitQuery, error) {
	if limits.MaxVisited < 0 {
		return nil, errors.New("invalid graph limits")
	}
	if limits.MaxVisited == 0 {
		limits.MaxVisited = 100000
	}
	return &gitQuery{ctx: ctx, r: r, max: limits.MaxVisited, parents: map[GitOID][]GitOID{}}, nil
}
func (g *gitQuery) get(id GitOID) ([]GitOID, error) {
	if err := g.ctx.Err(); err != nil {
		return nil, err
	}
	if ps, ok := g.parents[id]; ok {
		return ps, nil
	}
	if len(g.parents) == g.max {
		return nil, ErrQueryLimit
	}
	ps, err := g.r.GitCommitParents(id)
	if err != nil {
		return nil, err
	}
	g.parents[id] = ps
	return ps, nil
}
func (g *gitQuery) ancestors(id GitOID) (map[GitOID]bool, error) {
	todo := []GitOID{id}
	seen := map[GitOID]bool{}
	for len(todo) > 0 {
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[id] {
			continue
		}
		ps, err := g.get(id)
		if err != nil {
			return nil, err
		}
		seen[id] = true
		todo = append(todo, ps...)
	}
	return seen, nil
}
func (r *Repository) GitIsAncestor(ctx context.Context, ancestor, descendant GitOID, limits GraphLimits) (bool, error) {
	g, err := newGitQuery(ctx, r, limits)
	if err != nil {
		return false, err
	}
	if _, err = g.get(ancestor); err != nil {
		return false, err
	}
	todo := []GitOID{descendant}
	seen := map[GitOID]bool{}
	for len(todo) > 0 {
		id := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if seen[id] {
			continue
		}
		ps, err := g.get(id)
		if err != nil {
			return false, err
		}
		if id == ancestor {
			return true, nil
		}
		seen[id] = true
		todo = append(todo, ps...)
	}
	return false, nil
}
func (r *Repository) GitMergeBases(ctx context.Context, a, b GitOID, limits GraphLimits) ([]GitOID, error) {
	g, err := newGitQuery(ctx, r, limits)
	if err != nil {
		return nil, err
	}
	left, err := g.ancestors(a)
	if err != nil {
		return nil, err
	}
	right, err := g.ancestors(b)
	if err != nil {
		return nil, err
	}
	common := map[GitOID]bool{}
	for id := range left {
		if right[id] {
			common[id] = true
		}
	}
	nonBest := map[GitOID]bool{}
	for id := range common {
		ps, err := g.get(id)
		if err != nil {
			return nil, err
		}
		for _, p := range ps {
			nonBest[p] = true
		}
	}
	out := []GitOID{}
	for id := range common {
		if !nonBest[id] {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}
