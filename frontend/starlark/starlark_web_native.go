package starlarkfrontend

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/tinyrange/trex/emulator/s390"
	"github.com/tinyrange/trex/emulator/s390/tn3270"
	"github.com/tinyrange/trex/emulator/s390/web3270"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/vncweb"
	webstar "github.com/tinyrange/trex/web/star"
	"go.starlark.net/starlark"
)

// serveStarlarkWeb is the native listener adapter. The request/response
// framework itself lives in web/star and is independent of process setup.
func serveStarlarkWeb(addr, script string, arguments []string, allowInternet bool) error {
	thread, environment, err := newStarlarkRuntime(script)
	if err != nil {
		return err
	}
	installInternet(thread, allowInternet)
	installStarlarkConsole(thread, newStreamStarlarkConsole(os.Stdin, os.Stdout, os.Stderr))
	resources, err := resourcesForThread(thread)
	if err != nil {
		return err
	}
	defer resources.Close()
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, script, nil, environment)
	if err != nil {
		return err
	}
	mainValue, ok := globals["main"]
	if !ok {
		return fmt.Errorf("%s has no main function", script)
	}
	mainCallable, ok := mainValue.(starlark.Callable)
	if !ok {
		return fmt.Errorf("%s main is not callable", script)
	}
	values := make([]starlark.Value, len(arguments))
	for index, argument := range arguments {
		values[index] = starlark.String(argument)
	}
	result, err := starlark.Call(thread, mainCallable, starlark.Tuple{starlark.Tuple(values)}, nil)
	if err != nil {
		return err
	}
	if scripted, ok := result.(*webstar.ScriptedApplication); ok {
		if err := validateScriptedWebAddress(addr); err != nil {
			return err
		}
		var consoles vmm.Workspace
		var mu *sync.Mutex
		if scripted.Consoles != starlark.None {
			provider, ok := scripted.Consoles.(interface{ VMMWorkspace() vmm.Workspace })
			if !ok {
				return fmt.Errorf("web.application consoles must be a vmm.workspace")
			}
			consoles = provider.VMMWorkspace()
			if provider, ok := scripted.Consoles.(interface{ VMMExecutionMutex() *sync.Mutex }); ok {
				mu = provider.VMMExecutionMutex()
			}
		} else {
			consoles = emptyWebWorkspace{}
		}
		handler := webstar.NewApplicationWithMutex(thread, scripted.Handler, mu)
		handler.RequestLogger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
		app, err := vncweb.NewApplication(consoles, handler, scripted.PublicPaths, scripted.Origin)
		if err != nil {
			return err
		}
		displayURL := webDisplayURL(addr)
		if scripted.Origin != "" {
			displayURL = scripted.Origin
		}
		fmt.Fprintf(os.Stderr, "Open application in your browser: %s/#%s\n", strings.TrimRight(displayURL, "/"), app.Console.Token)
		return http.ListenAndServe(addr, app)
	}
	if terminals, ok := result.(*s390.WebTerminals); ok {
		return serveWebTerminals(addr, terminals)
	}
	if spec, ok := result.(*launcherSpec); ok {
		return serveLauncher(addr, spec, allowInternet)
	}
	if workspace, ok := result.(interface{ VMMWorkspace() vmm.Workspace }); ok {
		app, err := vncweb.NewWorkspace(workspace.VMMWorkspace())
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Open VM workspace in your browser: %s/#%s\n", strings.TrimRight(webDisplayURL(addr), "/"), app.Token)
		return http.ListenAndServe(addr, app)
	}
	if vm, ok := result.(interface {
		VMMDisplay() (vmm.DisplaySource, error)
	}); ok {
		display, err := vm.VMMDisplay()
		if err != nil {
			return err
		}
		app, err := vncweb.New(display)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Open VM in your browser: %s/#%s\n", strings.TrimRight(webDisplayURL(addr), "/"), app.Token)
		return http.ListenAndServe(addr, app)
	}
	handler, ok := result.(starlark.Callable)
	if !ok {
		return fmt.Errorf("%s main returned %s, want a request handler", script, result.Type())
	}
	fmt.Fprintf(os.Stderr, "Serving Starlark application %s at %s\n", script, webDisplayURL(addr))
	app := webstar.NewApplication(thread, handler)
	app.RequestLogger = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	return http.ListenAndServe(addr, app)
}

// serveWebTerminals runs an s390 machine continuously, streams its consoles
// to browsers and, when requested, accepts tn3270 clients for its 3270
// displays. Like scripted applications both listeners are limited to
// loopback or the local Tailscale address.
func serveWebTerminals(addr string, terminals *s390.WebTerminals) error {
	if err := validateScriptedWebAddress(addr); err != nil {
		return err
	}
	server, err := web3270.New(terminals.Live, terminals.Terminals)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if terminals.TN3270 != "" {
		if err := validateScriptedWebAddress(terminals.TN3270); err != nil {
			return fmt.Errorf("tn3270: %w", err)
		}
		tn, err := tn3270.New(terminals.Live, terminals.Terminals)
		if err != nil {
			return err
		}
		tn.Log = func(line string) { fmt.Fprintln(os.Stderr, "tn3270", line) }
		tl, err := net.Listen("tcp", terminals.TN3270)
		if err != nil {
			return err
		}
		defer tl.Close()
		go func() { _ = tn.Serve(ctx, tl) }()
		fmt.Fprintf(os.Stderr, "tn3270 clients may connect to %s\n", tl.Addr())
	}
	if terminals.State != "" {
		save := func() (string, error) { return saveMachineState(terminals) }
		server.Save = save
		server.Snaps = fileSnapshots{terminals}
		if terminals.AutoSave > 0 {
			go autosave(ctx, terminals, terminals.AutoSave, func(format string, args ...any) {
				fmt.Fprintf(os.Stderr, format+"\n", args...)
			})
		}
		// Ctrl-C and SIGTERM save the state before exiting.
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
		go func() {
			sig := <-signals
			fmt.Fprintf(os.Stderr, "%v: saving machine state to %s\n", sig, terminals.State)
			if where, err := save(); err != nil {
				fmt.Fprintf(os.Stderr, "saving machine state: %v\n", err)
				os.Exit(1)
			} else {
				fmt.Fprintf(os.Stderr, "saved %s\n", where)
			}
			os.Exit(0)
		}()
	}
	if terminals.Network != nil {
		if err := startNetwork(ctx, terminals.Live, terminals.Network, func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		}); err != nil {
			return err
		}
	}
	go func() {
		_ = terminals.Live.Run(ctx)
	}()
	fmt.Fprintf(os.Stderr, "Open 3270 terminals in your browser: %s#%s\n", webDisplayURL(listener.Addr().String()), server.Token)
	return http.Serve(listener, server)
}

var stateMu sync.Mutex

// saveMachineState checkpoints a live machine to its state file.
func saveMachineState(terminals *s390.WebTerminals) (string, error) {
	return writeMachineState(terminals.Live, terminals.State)
}

// writeMachineState checkpoints a live machine to path, replacing any
// previous file only once the new one is complete.
func writeMachineState(live *s390.Live, path string) (string, error) {
	stateMu.Lock()
	defer stateMu.Unlock()
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
	}
	tmp := path + ".partial"
	f, err := os.Create(tmp)
	if err != nil {
		return "", err
	}
	if err := live.Save(f); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return "", err
	}
	info, _ := f.Stat()
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s (%d MB)", path, info.Size()>>20), nil
}

type emptyWebWorkspace struct{}

func (emptyWebWorkspace) VMs() []vmm.DisplayVM { return []vmm.DisplayVM{} }
func (emptyWebWorkspace) CanCreate() bool      { return false }
func (emptyWebWorkspace) Create(context.Context) (vmm.DisplayVM, error) {
	return vmm.DisplayVM{}, fmt.Errorf("creation unavailable")
}

// The native adapter admits loopback and exact addresses assigned to the
// local Tailscale tunnel. It never widens a tailnet request to a LAN/wildcard
// listener. An HTTPS proxy remains available for other deployment layouts.
type scriptedWebInterfaceAddress struct {
	name string
	ip   net.IP
}

func validateScriptedWebAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("web.application listener: %w", err)
	}
	if host == "localhost" || net.ParseIP(host).IsLoopback() {
		return nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("inspect local listener addresses: %w", err)
	}
	var assigned []scriptedWebInterfaceAddress
	for _, iface := range interfaces {
		if iface.Name != "tailscale0" || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("inspect Tailscale interface: %w", err)
		}
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil {
				assigned = append(assigned, scriptedWebInterfaceAddress{iface.Name, ip})
			}
		}
	}
	return validateScriptedWebAddressAssigned(address, assigned)
}

func validateScriptedWebAddressAssigned(address string, assigned []scriptedWebInterfaceAddress) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("web.application listener: %w", err)
	}
	ip := net.ParseIP(host)
	if host == "localhost" || ip.IsLoopback() {
		return nil
	}
	// Tailscale's reserved IPv4 and IPv6 ranges are necessary but not sufficient:
	// require exact ownership by the running local tunnel interface as well.
	ipv4 := &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
	ipv6 := &net.IPNet{IP: net.ParseIP("fd7a:115c:a1e0::"), Mask: net.CIDRMask(48, 128)}
	if ip != nil && (ipv4.Contains(ip) || ipv6.Contains(ip)) {
		for _, address := range assigned {
			if address.name == "tailscale0" && address.ip.Equal(ip) {
				return nil
			}
		}
	}
	return fmt.Errorf("web.application requires loopback or an exact IP assigned to the local Tailscale tunnel; wildcard and LAN listeners are not allowed")
}
