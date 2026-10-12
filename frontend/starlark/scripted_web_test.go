package starlarkfrontend

import (
	"context"
	"image"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/vncweb"
	webstar "github.com/tinyrange/trex/web/star"
	"go.starlark.net/starlark"
)

// Test-only display handle for scripted HTTP fixtures. No VM or host process.
type scriptedTestVM struct{ closed bool }

func (*scriptedTestVM) String() string                           { return "<test-vm>" }
func (*scriptedTestVM) Type() string                             { return "vm" }
func (*scriptedTestVM) Freeze()                                  {}
func (*scriptedTestVM) Truth() starlark.Bool                     { return true }
func (*scriptedTestVM) Hash() (uint32, error)                    { return 0, nil }
func (v *scriptedTestVM) VMMDisplay() (vmm.DisplaySource, error) { return v, nil }
func (*scriptedTestVM) Capture(context.Context) (*image.RGBA, error) {
	return image.NewRGBA(image.Rect(0, 0, 2, 2)), nil
}
func (*scriptedTestVM) Input(context.Context, vmm.Input) error { return nil }
func (*scriptedTestVM) AttrNames() []string                    { return []string{"running", "close", "has_capability"} }
func (v *scriptedTestVM) Attr(name string) (starlark.Value, error) {
	switch name {
	case "running":
		return starlark.Bool(!v.closed), nil
	case "close":
		return starlark.NewBuiltin("close", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			v.closed = true
			return starlark.None, nil
		}), nil
	case "has_capability":
		return starlark.NewBuiltin("has_capability", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
			return starlark.False, nil
		}), nil
	}
	return nil, nil
}

// A consumer may supply a scripted HTTP fixture without coupling engine tests
// to its private repository. TEST_CASES are ordered (method, path, status,
// required substring, forbidden substring) tuples. Fixture execution is bounded.
func TestScriptedWebApplicationFixture(t *testing.T) {
	filename := os.Getenv("TREX_WEB_FIXTURE")
	source := `
def handle(request):
    return web.response("scripted application", status=201)
def main(args):
    return web.application(handle, consoles=vmm.workspace({}), public=["/"])
TEST_CASES = [("GET", "/", 201, "scripted application", "")]
`
	var root string
	if filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		source = string(data)
		root = os.Getenv("TREX_WEB_ROOT")
		if root == "" {
			t.Fatal("TREX_WEB_ROOT required for consumer fixture")
		}
	} else {
		filename = "scripted_web_fixture.star"
	}
	thread, environment, err := newStarlarkRuntime(filename)
	if err != nil {
		t.Fatal(err)
	}
	resources, err := resourcesForThread(thread)
	if err != nil {
		t.Fatal(err)
	}
	defer resources.Close()
	starts := 0
	var machines []*scriptedTestVM
	environment["test_vm"] = starlark.NewBuiltin("test_vm", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		starts++
		vm := &scriptedTestVM{}
		machines = append(machines, vm)
		return vm, nil
	})
	environment["test_vm_counts"] = starlark.NewBuiltin("test_vm_counts", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		closed := 0
		for _, vm := range machines {
			if vm.closed {
				closed++
			}
		}
		return starlark.Tuple{starlark.MakeInt(starts), starlark.MakeInt(closed)}, nil
	})
	if root != "" {
		loader, err := newModuleLoader(root, environment)
		if err != nil {
			t.Fatal(err)
		}
		thread.Load = loader.Load
	}
	thread.SetMaxExecutionSteps(1000000)
	globals, err := starlark.ExecFileOptions(starlarkFileOptions(), thread, filename, source, environment)
	if err != nil {
		t.Fatal(err)
	}
	result, err := starlark.Call(thread, globals["main"].(starlark.Callable), starlark.Tuple{starlark.Tuple{}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	scripted := result.(*webstar.ScriptedApplication)
	provider := scripted.Consoles.(interface {
		VMMWorkspace() vmm.Workspace
		VMMExecutionMutex() *sync.Mutex
	})
	handler := webstar.NewApplicationWithMutex(thread, scripted.Handler, provider.VMMExecutionMutex())
	app, err := vncweb.NewApplication(provider.VMMWorkspace(), handler, scripted.PublicPaths, scripted.Origin)
	if err != nil {
		t.Fatal(err)
	}
	iterator := globals["TEST_CASES"].(starlark.Iterable).Iterate()
	defer iterator.Done()
	var row starlark.Value
	for iterator.Next(&row) {
		tuple := row.(starlark.Tuple)
		method, _ := starlark.AsString(tuple[0])
		path, _ := starlark.AsString(tuple[1])
		want, _ := tuple[2].(starlark.Int).Int64()
		contains, _ := starlark.AsString(tuple[3])
		excludes, _ := starlark.AsString(tuple[4])
		request := httptest.NewRequest(method, "http://app.test"+path, nil)
		request.Header.Set("Authorization", "Bearer "+app.Console.Token)
		if method != "GET" && method != "HEAD" {
			request.Header.Set("Origin", "http://app.test")
		}
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, request)
		if rec.Code != int(want) || !strings.Contains(rec.Body.String(), contains) || excludes != "" && strings.Contains(rec.Body.String(), excludes) {
			t.Fatalf("%s %s: status=%d body=%s; want status=%d contains=%q excludes=%q", method, path, rec.Code, rec.Body.String(), want, contains, excludes)
		}
	}
}

func TestScriptedWebJavaScript(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate JavaScript tests")
	}
	base := filepath.Join(filepath.Dir(source), "..", "..", "vmm", "vncweb")
	scripts := []string{filepath.Join(base, "client_test.mjs"), filepath.Join(base, "app_test.mjs")}
	if extra := os.Getenv("TREX_WEB_JS_TEST"); extra != "" {
		scripts = append(scripts, extra)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, script := range scripts {
		if _, err := os.Stat(script); err != nil {
			t.Fatal(err)
		}
		output, err := exec.CommandContext(ctx, node, "--test", script).CombinedOutput()
		if err != nil {
			t.Fatalf("JavaScript checks (%s): %v\n%s", script, err, output)
		}
		t.Logf("%s:\n%s", script, output)
	}
}

// The live test script is consumer-owned and opt-in. It exercises the actual
// native listener and uses Node's browser WebSocket, not a protocol substitute.
func TestScriptedWebLiveSmoke(t *testing.T) {
	script := os.Getenv("TREX_WEB_LIVE_TEST")
	if script == "" {
		t.Skip("no consumer live smoke selected")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Fatal("node required for selected live smoke")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, node, "--test", script).CombinedOutput()
	if err != nil {
		t.Fatalf("live web smoke: %v\n%s", err, output)
	}
	t.Logf("%s", output)
}

func TestScriptedWebListenerIsLoopbackOrAssignedTailnet(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		if err := validateScriptedWebAddressAssigned(address, nil); err != nil {
			t.Fatal(address, err)
		}
	}
	for _, address := range []string{":8080", "0.0.0.0:8080", "[::]:8080", "100.64.0.1:8080", "remote.test:8080", "not-an-address"} {
		if err := validateScriptedWebAddressAssigned(address, nil); err == nil {
			t.Fatal("insecure listener accepted", address)
		}
	}
}

func TestScriptedWebTailnetBindingRequiresTunnelOwnership(t *testing.T) {
	assignments := []scriptedWebInterfaceAddress{
		{name: "tailscale0", ip: net.ParseIP("100.66.0.124")},
		{name: "tailscale0", ip: net.ParseIP("fd7a:115c:a1e0::1234")},
		{name: "eth0", ip: net.ParseIP("100.66.0.125")},
		{name: "tailscale0", ip: net.ParseIP("10.0.0.1")},
	}
	for _, address := range []string{"100.66.0.124:8080", "[fd7a:115c:a1e0::1234]:8080", "127.0.0.1:8080"} {
		if err := validateScriptedWebAddressAssigned(address, assignments); err != nil {
			t.Fatal(address, err)
		}
	}
	for _, address := range []string{"100.66.0.125:8080", "100.66.0.126:8080", "10.0.0.1:8080", "0.0.0.0:8080", "[::]:8080", "[fd7a:115c:a1e0::1235]:8080"} {
		if err := validateScriptedWebAddressAssigned(address, assignments); err == nil {
			t.Fatal("non-tailnet or unassigned listener accepted", address)
		}
	}
}
