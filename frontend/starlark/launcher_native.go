package starlarkfrontend

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tinyrange/trex/emulator/s390"
	"github.com/tinyrange/trex/emulator/s390/tn3270"
	"github.com/tinyrange/trex/emulator/s390/web3270"
	"go.starlark.net/starlark"
)

// launcher(systems) describes machines a launcher page can start and stop.
// Each system is a dict: name, title, description, script, args and an
// optional root (the directory "//" module labels resolve in); the
// script's main(args) must return emulator machine terminals
// (m.web_terminals). A "state=PATH" argument makes Stop able to save the
// machine and Start resume it; "tn3270=ADDRESS" is shown on the page.
// Returned from main under "trex -serve", it serves the launcher.

type systemSpec struct {
	Name, Title, Description, Script string
	Root                             string // module root for "//" labels
	Args                             []string
}

type launcherSpec struct{ systems []systemSpec }

func (*launcherSpec) String() string        { return "<launcher>" }
func (*launcherSpec) Type() string          { return "launcher" }
func (*launcherSpec) Freeze()               {}
func (*launcherSpec) Truth() starlark.Bool  { return starlark.True }
func (*launcherSpec) Hash() (uint32, error) { return 0, fmt.Errorf("unhashable: launcher") }

var systemName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

func launcherBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var list *starlark.List
	if err := starlark.UnpackArgs("launcher", args, kwargs, "systems", &list); err != nil {
		return nil, err
	}
	spec := &launcherSpec{}
	seen := map[string]bool{}
	for i := 0; i < list.Len(); i++ {
		d, ok := list.Index(i).(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("launcher: system %d is %s, want dict", i, list.Index(i).Type())
		}
		str := func(key string, required bool) (string, error) {
			v, found, _ := d.Get(starlark.String(key))
			if !found {
				if required {
					return "", fmt.Errorf("launcher: system %d has no %s", i, key)
				}
				return "", nil
			}
			s, ok := starlark.AsString(v)
			if !ok {
				return "", fmt.Errorf("launcher: system %d %s is %s, want string", i, key, v.Type())
			}
			return s, nil
		}
		var s systemSpec
		var err error
		if s.Name, err = str("name", true); err != nil {
			return nil, err
		}
		if !systemName.MatchString(s.Name) || seen[s.Name] {
			return nil, fmt.Errorf("launcher: system name %q must be unique lowercase letters, digits and dashes", s.Name)
		}
		seen[s.Name] = true
		if s.Script, err = str("script", true); err != nil {
			return nil, err
		}
		if s.Title, err = str("title", false); err != nil {
			return nil, err
		}
		if s.Description, err = str("description", false); err != nil {
			return nil, err
		}
		if s.Root, err = str("root", false); err != nil {
			return nil, err
		}
		if v, found, _ := d.Get(starlark.String("args")); found {
			l, ok := v.(*starlark.List)
			if !ok {
				return nil, fmt.Errorf("launcher: system %s args must be a list", s.Name)
			}
			for j := 0; j < l.Len(); j++ {
				a, ok := starlark.AsString(l.Index(j))
				if !ok {
					return nil, fmt.Errorf("launcher: system %s args must be strings", s.Name)
				}
				s.Args = append(s.Args, a)
			}
		}
		spec.systems = append(spec.systems, s)
	}
	return spec, nil
}

// argValue returns the value of a "key=value" argument.
func argValue(args []string, key string) string {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, key+"="); ok {
			return v
		}
	}
	return ""
}

// systemRunner runs one system's script in its own Starlark runtime.
type systemRunner struct {
	spec          systemSpec
	allowInternet bool
	token         string

	mu        sync.Mutex
	state     string
	err       string
	log       []string
	since     time.Time
	thread    *starlark.Thread
	resources interface{ Close() error }
	terms     *s390.WebTerminals
	console   http.Handler
	cancel    context.CancelFunc
	done      chan struct{} // closed when the machine stops running
	listener  net.Listener
}

func (r *systemRunner) logf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	r.mu.Lock()
	for _, l := range strings.Split(strings.TrimRight(line, "\n"), "\n") {
		r.log = append(r.log, l)
	}
	if len(r.log) > 400 {
		r.log = append(r.log[:0], r.log[len(r.log)-300:]...)
	}
	r.mu.Unlock()
	fmt.Fprintf(os.Stderr, "[%s] %s\n", r.spec.Name, strings.TrimRight(line, "\n"))
}

type logWriter struct{ r *systemRunner }

func (w logWriter) Write(p []byte) (int, error) { w.r.logf("%s", p); return len(p), nil }

func (r *systemRunner) Info() web3270.SystemInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	state := argValue(r.spec.Args, "state")
	has := false
	if state != "" {
		if info, err := os.Stat(state); err == nil && info.Mode().IsRegular() {
			has = true
		}
	}
	info := web3270.SystemInfo{Name: r.spec.Name, Title: r.spec.Title, Description: r.spec.Description,
		State: r.state, Error: r.err, Log: append([]string(nil), r.log...), TN3270: argValue(r.spec.Args, "tn3270"),
		Saves: state != "", HasState: has}
	if r.state == "running" {
		info.Since = r.since.Format(time.RFC3339)
	}
	if state != "" {
		if list, err := (fileSnapshots{&s390.WebTerminals{State: state}}).List(); err == nil {
			for _, sn := range list {
				info.Snapshots = append(info.Snapshots, sn.Name)
			}
		}
	}
	return info
}

func (r *systemRunner) Consoles() http.Handler {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != "running" {
		return nil
	}
	return r.console
}

func (r *systemRunner) Start(snapshot string) error {
	r.mu.Lock()
	if r.state != "stopped" && r.state != "failed" {
		defer r.mu.Unlock()
		return fmt.Errorf("%s is %s", r.spec.Name, r.state)
	}
	if snapshot != "" {
		// Resume from the snapshot: it becomes the resume state.
		state := argValue(r.spec.Args, "state")
		if state == "" {
			r.mu.Unlock()
			return fmt.Errorf("%s keeps no snapshots", r.spec.Name)
		}
		src, err := (fileSnapshots{&s390.WebTerminals{State: state}}).path(snapshot)
		if err == nil {
			err = copyFile(src, state)
		}
		if err != nil {
			r.mu.Unlock()
			return err
		}
	}
	r.state, r.err, r.log = "starting", "", nil
	r.mu.Unlock()
	go r.run()
	return nil
}

func (r *systemRunner) fail(err error) {
	r.mu.Lock()
	stopping := r.state == "stopping"
	r.mu.Unlock()
	if stopping {
		r.logf("stopped before it was running")
	} else {
		r.logf("failed: %v", err)
	}
	r.mu.Lock()
	if stopping {
		r.state, r.err = "stopped", ""
	} else {
		r.state, r.err = "failed", err.Error()
	}
	res := r.resources
	r.resources, r.thread = nil, nil
	r.mu.Unlock()
	if res != nil {
		res.Close()
	}
}

func (r *systemRunner) run() {
	r.logf("starting %s %s", r.spec.Script, strings.Join(r.spec.Args, " "))
	var thread *starlark.Thread
	var environment starlark.StringDict
	var err error
	if r.spec.Root != "" {
		thread, environment, err = newStarlarkRuntimeAt(r.spec.Root)
	} else {
		thread, environment, err = newStarlarkRuntime(r.spec.Script)
	}
	if err != nil {
		r.fail(err)
		return
	}
	installInternet(thread, r.allowInternet)
	out := logWriter{r}
	installStarlarkConsole(thread, newStreamStarlarkConsole(strings.NewReader(""), out, out))
	thread.Print = func(_ *starlark.Thread, msg string) { r.logf("%s", msg) }
	resources, err := resourcesForThread(thread)
	if err != nil {
		r.fail(err)
		return
	}
	r.mu.Lock()
	r.thread, r.resources = thread, resources
	r.mu.Unlock()
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, r.spec.Script, nil, environment)
	if err != nil {
		r.fail(err)
		return
	}
	mainFn, ok := globals["main"].(starlark.Callable)
	if !ok {
		r.fail(fmt.Errorf("%s has no main function", r.spec.Script))
		return
	}
	values := make(starlark.Tuple, len(r.spec.Args))
	for i, a := range r.spec.Args {
		values[i] = starlark.String(a)
	}
	result, err := starlark.Call(thread, mainFn, starlark.Tuple{values}, nil)
	if err != nil {
		r.fail(err)
		return
	}
	terms, ok := result.(*s390.WebTerminals)
	if !ok {
		r.fail(fmt.Errorf("%s main returned %s, want machine terminals (m.web_terminals)", r.spec.Script, result.Type()))
		return
	}
	console, err := web3270.New(terms.Live, terms.Terminals)
	if err != nil {
		r.fail(err)
		return
	}
	console.Token = r.token
	ctx, cancel := context.WithCancel(context.Background())
	if terms.State != "" {
		console.Save = func() (string, error) { return saveMachineState(terms) }
		console.Snaps = fileSnapshots{terms}
		if terms.AutoSave > 0 {
			go autosave(ctx, terms, terms.AutoSave, r.logf)
		}
	}
	var listener net.Listener
	if terms.TN3270 != "" {
		if err := validateScriptedWebAddress(terms.TN3270); err != nil {
			cancel()
			r.fail(fmt.Errorf("tn3270: %w", err))
			return
		}
		tn, err := tn3270.New(terms.Live, terms.Terminals)
		if err != nil {
			cancel()
			r.fail(err)
			return
		}
		tn.Log = func(line string) { r.logf("tn3270 %s", line) }
		if listener, err = net.Listen("tcp", terms.TN3270); err != nil {
			cancel()
			r.fail(err)
			return
		}
		go func() { _ = tn.Serve(ctx, listener) }()
	}
	if terms.Network != nil {
		if err := startNetwork(ctx, terms.Live, terms.Network, r.logf); err != nil {
			cancel()
			if listener != nil {
				listener.Close()
			}
			r.fail(err)
			return
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = terms.Live.Run(ctx)
	}()
	r.mu.Lock()
	if r.state == "stopping" { // stopped while main returned
		r.mu.Unlock()
		cancel()
		<-done
		if listener != nil {
			listener.Close()
		}
		r.fail(fmt.Errorf("stopped"))
		return
	}
	r.state, r.since = "running", time.Now()
	r.terms, r.console, r.cancel, r.done, r.listener = terms, console, cancel, done, listener
	r.mu.Unlock()
	r.logf("running")
}

func (r *systemRunner) Stop(save bool) error {
	r.mu.Lock()
	switch r.state {
	case "starting":
		r.state = "stopping"
		if r.thread != nil {
			r.thread.Cancel("stopped by the launcher")
		}
		r.mu.Unlock()
		return nil
	case "running":
	default:
		defer r.mu.Unlock()
		return fmt.Errorf("%s is %s", r.spec.Name, r.state)
	}
	r.state = "stopping"
	terms, cancel, done, listener, res := r.terms, r.cancel, r.done, r.listener, r.resources
	r.mu.Unlock()
	var saveErr error
	if save {
		if terms.State == "" {
			saveErr = fmt.Errorf("%s has no state file", r.spec.Name)
		} else if where, err := saveMachineState(terms); err != nil {
			saveErr = err
		} else {
			r.logf("saved %s", where)
		}
	}
	if saveErr != nil {
		r.mu.Lock()
		r.state = "running"
		r.mu.Unlock()
		return saveErr
	}
	cancel()
	<-done
	if listener != nil {
		listener.Close()
	}
	if res != nil {
		res.Close()
	}
	r.mu.Lock()
	r.state = "stopped"
	r.terms, r.console, r.cancel, r.done, r.listener, r.resources, r.thread = nil, nil, nil, nil, nil, nil, nil
	r.mu.Unlock()
	r.logf("stopped")
	return nil
}

// serveLauncher serves the launcher page and its systems' consoles. On
// Ctrl-C or SIGTERM every running system with a state file is saved.
func serveLauncher(addr string, spec *launcherSpec, allowInternet bool) error {
	if err := validateScriptedWebAddress(addr); err != nil {
		return err
	}
	var runners []*systemRunner
	var systems []web3270.System
	for _, s := range spec.systems {
		r := &systemRunner{spec: s, allowInternet: allowInternet, state: "stopped"}
		runners = append(runners, r)
		systems = append(systems, r)
	}
	l, err := web3270.NewLauncher(systems)
	if err != nil {
		return err
	}
	for _, r := range runners {
		r.token = l.Token
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-signals
		fmt.Fprintf(os.Stderr, "%v: stopping systems\n", sig)
		var wg sync.WaitGroup
		for _, r := range runners {
			if r.Info().State != "running" {
				continue
			}
			wg.Add(1)
			go func(r *systemRunner) {
				defer wg.Done()
				if err := r.Stop(r.Info().Saves); err != nil {
					fmt.Fprintf(os.Stderr, "[%s] %v\n", r.spec.Name, err)
				}
			}(r)
		}
		wg.Wait()
		os.Exit(0)
	}()
	fmt.Fprintf(os.Stderr, "Open the launcher in your browser: %s#%s\n", webDisplayURL(listener.Addr().String()), l.Token)
	return http.Serve(listener, l)
}

// copyFile replaces dst with a copy of src once the copy is complete.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".partial"
	out, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}
