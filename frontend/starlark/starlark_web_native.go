package starlarkfrontend

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

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
