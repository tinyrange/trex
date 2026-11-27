package lab

import (
	"embed"
	"io/fs"
	"strings"
)

const recipeNamespace = "_trex_lab/"

//go:embed recipes/*.star
var embeddedRecipes embed.FS

type recipeFiles struct{ workspace fs.FS }

func (r recipeFiles) Open(name string) (fs.File, error) {
	if file, builtin := strings.CutPrefix(name, recipeNamespace); builtin {
		return embeddedRecipes.Open("recipes/" + file)
	}
	if r.workspace == nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}
	return r.workspace.Open(name)
}
