package starlarkfrontend

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	stdlib "github.com/tinyrange/trex/starlark"
	"go.starlark.net/starlark"
)

// standardLibrary contains the Starlark modules shipped with trex. Keeping
// these modules embedded makes production execution independent of the source
// checkout and ensures module processing remains in memory.
var standardLibrary = stdlib.StandardLibrary

type moduleResult struct {
	globals starlark.StringDict
	err     error
	loading bool
}

// moduleLoader resolves a closed embedded standard library plus modules beneath
// one configured workspace root. It caches both successful and failed loads as
// required by starlark.Thread.Load.
type moduleLoader struct {
	workspace   fs.FS
	predeclared starlark.StringDict
	modules     map[string]*moduleResult
	stack       []string
}

func newModuleLoader(root string, predeclared starlark.StringDict) (*moduleLoader, error) {
	if root == "" {
		root = "."
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("module root: %w", err)
	}
	return newModuleLoaderFS(os.DirFS(filepath.Clean(abs)), predeclared), nil
}

func newModuleLoaderFS(workspace fs.FS, predeclared starlark.StringDict) *moduleLoader {
	return &moduleLoader{
		workspace:   workspace,
		predeclared: predeclared,
		modules:     make(map[string]*moduleResult),
	}
}

func (l *moduleLoader) Load(thread *starlark.Thread, name string) (starlark.StringDict, error) {
	canonical, sourcePath, embedded, err := l.resolve(thread, name)
	if err != nil {
		return nil, err
	}
	if result, ok := l.modules[canonical]; ok {
		if result.loading {
			chain := append(append([]string(nil), l.stack...), canonical)
			return nil, fmt.Errorf("module cycle: %s", strings.Join(chain, " -> "))
		}
		return result.globals, result.err
	}

	result := &moduleResult{loading: true}
	l.modules[canonical] = result
	l.stack = append(l.stack, canonical)
	defer func() { l.stack = l.stack[:len(l.stack)-1] }()

	var source []byte
	if embedded {
		source, err = fs.ReadFile(standardLibrary, sourcePath)
	} else {
		source, err = fs.ReadFile(l.workspace, sourcePath)
	}
	if err != nil {
		result.loading = false
		result.err = fmt.Errorf("load %s: %w", canonical, err)
		return nil, result.err
	}

	globals, execErr := starlark.ExecFileOptions(starlarkFileOptions(), thread, canonical, source, l.predeclared)
	result.loading = false
	if execErr != nil {
		result.err = execErr
		return nil, execErr
	}
	for _, value := range globals {
		value.Freeze()
	}
	result.globals = globals
	return globals, nil
}

func (l *moduleLoader) resolve(thread *starlark.Thread, name string) (canonical, sourcePath string, embedded bool, err error) {
	if name == "" {
		return "", "", false, fmt.Errorf("load: empty module name")
	}
	if strings.ContainsRune(name, '\\') {
		return "", "", false, fmt.Errorf("load %q: use forward slashes in module names", name)
	}

	if strings.HasPrefix(name, "@stdlib//") {
		modulePath, err := canonicalLabelPath(strings.TrimPrefix(name, "@stdlib//"))
		if err != nil {
			return "", "", false, fmt.Errorf("load %q: %w", name, err)
		}
		return stdlibLabel(modulePath), path.Join("stdlib", modulePath), true, nil
	}

	if strings.HasPrefix(name, "//") {
		modulePath, err := canonicalLabelPath(strings.TrimPrefix(name, "//"))
		if err != nil {
			return "", "", false, fmt.Errorf("load %q: %w", name, err)
		}
		hostPath, err := l.workspacePath(modulePath)
		if err != nil {
			return "", "", false, err
		}
		return workspaceLabel(modulePath), hostPath, false, nil
	}

	caller := ""
	if thread != nil && thread.CallStackDepth() > 0 {
		caller = thread.CallFrame(0).Pos.Filename()
	}
	if strings.HasPrefix(caller, "@stdlib//") {
		callerPath, err := canonicalLabelPath(strings.TrimPrefix(caller, "@stdlib//"))
		if err != nil {
			return "", "", false, err
		}
		modulePath, err := cleanModulePath(path.Join(path.Dir(callerPath), labelFile(name)))
		if err != nil {
			return "", "", false, fmt.Errorf("load %q from %s: %w", name, caller, err)
		}
		return stdlibLabel(modulePath), path.Join("stdlib", modulePath), true, nil
	}

	base := ""
	if strings.HasPrefix(caller, "//") {
		callerPath, err := canonicalLabelPath(strings.TrimPrefix(caller, "//"))
		if err != nil {
			return "", "", false, err
		}
		base = path.Dir(callerPath)
	}
	modulePath, err := cleanModulePath(path.Join(base, labelFile(name)))
	if err != nil {
		return "", "", false, fmt.Errorf("load %q: %w", name, err)
	}
	hostPath, err := l.workspacePath(modulePath)
	if err != nil {
		return "", "", false, err
	}
	return workspaceLabel(modulePath), hostPath, false, nil
}

func canonicalLabelPath(label string) (string, error) {
	if strings.Count(label, ":") > 1 {
		return "", fmt.Errorf("invalid module label")
	}
	if before, after, ok := strings.Cut(label, ":"); ok {
		if after == "" || strings.Contains(after, "/") {
			return "", fmt.Errorf("invalid module target")
		}
		label = path.Join(before, after)
	}
	return cleanModulePath(label)
}

func labelFile(name string) string {
	if strings.HasPrefix(name, ":") {
		return strings.TrimPrefix(name, ":")
	}
	return name
}

func cleanModulePath(name string) (string, error) {
	if name == "" || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("invalid module path")
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("module path escapes its root")
	}
	if path.Ext(clean) != ".star" {
		return "", fmt.Errorf("module must have a .star extension")
	}
	return clean, nil
}

func (l *moduleLoader) workspacePath(modulePath string) (string, error) {
	return cleanModulePath(modulePath)
}

func stdlibLabel(modulePath string) string {
	dir, file := path.Split(modulePath)
	return "@stdlib//" + strings.TrimSuffix(dir, "/") + ":" + file
}

func workspaceLabel(modulePath string) string {
	dir, file := path.Split(modulePath)
	return "//" + strings.TrimSuffix(dir, "/") + ":" + file
}

func newStarlarkRuntime(script string) (*starlark.Thread, starlark.StringDict, error) {
	root := "."
	if script != "" && script != "-" && filepath.IsAbs(script) {
		root = filepath.Dir(script)
	}
	predeclared := predeclared()
	loader, err := newModuleLoader(root, predeclared)
	if err != nil {
		return nil, nil, err
	}
	thread := &starlark.Thread{Name: "main", Load: loader.Load}
	installRuntimeResources(thread)
	installRuntimeClock(thread)
	if err := installPredeclaredModules(thread, loader, predeclared); err != nil {
		return nil, nil, err
	}
	thread.SetLocal(starlarkEnvironmentKey, predeclared)
	return thread, predeclared, nil
}

func installPredeclaredModules(thread *starlark.Thread, loader *moduleLoader, environment starlark.StringDict) error {
	globals, err := loader.Load(thread, "@stdlib//:predeclared.star")
	if err != nil {
		return fmt.Errorf("load standard library predeclared modules: %w", err)
	}
	value, ok := globals["PREDECLARED"]
	if !ok {
		return fmt.Errorf("standard library predeclared module does not define PREDECLARED")
	}
	modules, ok := value.(*starlark.Dict)
	if !ok {
		return fmt.Errorf("standard library PREDECLARED is %s, want dict", value.Type())
	}
	for _, item := range modules.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok {
			return fmt.Errorf("standard library namespace name is %s, want string", item[0].Type())
		}
		exports, ok := item[1].(*starlark.Dict)
		if !ok {
			return fmt.Errorf("standard library namespace %q is %s, want dict", name, item[1].Type())
		}
		module, exists := environment[name]
		var target namespace
		if exists {
			var namespaceOK bool
			target, namespaceOK = module.(namespace)
			if !namespaceOK {
				return fmt.Errorf("standard library cannot extend predeclared %q of type %s", name, module.Type())
			}
		} else {
			target = namespace{name: name, attrs: make(starlark.StringDict)}
			environment[name] = target
		}
		for _, export := range exports.Items() {
			exportName, ok := starlark.AsString(export[0])
			if !ok {
				return fmt.Errorf("standard library %q export name is %s, want string", name, export[0].Type())
			}
			target.attrs[exportName] = export[1]
		}
	}
	return nil
}
