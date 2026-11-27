// Package labfrontend hosts the Trex Virtual Lab Editor.
package labfrontend

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"
	"time"

	"github.com/tinyrange/trex/frontend/lab/ui"
	"github.com/tinyrange/trex/lab"
)

// Extension supplies additional guest policies from the workspace selected by
// -root. A guest recipe can specialize a built-in guest by reusing its ID.
type Extension struct {
	Recipes            []lab.Recipe
	Templates          []lab.Template
	SoftwareAliases    []lab.SoftwareAlias
	SoftwareReferences []lab.SoftwareTitle
}

func (e Extension) catalog() ([]lab.Recipe, error) {
	catalog := lab.Catalog()
	added := make(map[string]bool)
	for _, recipe := range e.Recipes {
		if recipe.ID == "" || recipe.ID == "switch" || recipe.ID == "router" || added[recipe.ID] ||
			recipe.Module == "" || recipe.Function == "" {
			return nil, fmt.Errorf("invalid extension recipe %q", recipe.ID)
		}
		added[recipe.ID] = true
		if i := slices.IndexFunc(catalog, func(r lab.Recipe) bool { return r.ID == recipe.ID }); i >= 0 {
			catalog[i] = recipe
		} else {
			catalog = append(catalog, recipe)
		}
	}
	// The media manifest adds local defaults. Never mutate recipe data owned by
	// the caller, which may register the same collection for another workspace.
	for i := range catalog {
		catalog[i].Media = slices.Clone(catalog[i].Media)
	}
	return catalog, nil
}

// Run serves one lab with the built-in recipes and optional extension.
func Run(args []string, extension Extension) error {
	var media mediaLibrary
	defer func() { media.close() }()
	flags := flag.NewFlagSet("trex lab", flag.ContinueOnError)
	root := flags.String("root", ".", "Workspace for the lab definition, local media and extension scripts")
	listen := flags.String("listen", "127.0.0.1:7373", "Loopback listener")
	origin := flags.String("tailnet-origin", "", "HTTPS origin of the Tailscale Serve proxy")
	user := flags.String("tailnet-user", "", "Tailscale login allowed to use this workspace")
	stateFile := flags.String("state", "local/virtual-lab.json", "Saved editable lab definition")
	mediaConfig := flags.String("media-config", "", "Media configuration file (default local/lab-media.json)")
	prepareIndy := flags.Bool("prepare-irix", false, "Prepare an in-memory login template from the default six IRIX discs")
	flags.Func("media-root", "Original media library as name=directory (repeatable)", func(value string) error { return media.add(value) })
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("the lab accepts flags only")
	}
	workspace, err := os.OpenRoot(*root)
	if err != nil {
		return fmt.Errorf("open lab workspace: %w", err)
	}
	defer workspace.Close()
	externalHost := ""
	if *origin != "" {
		parsed, err := url.Parse(*origin)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			return errors.New("tailnet-origin must be a bare HTTPS origin")
		}
		externalHost = parsed.Host
		if *user == "" {
			return errors.New("tailnet-origin requires the authorized tailnet-user login")
		}
	}
	guestRec, err := extension.catalog()
	if err != nil {
		return err
	}
	if err := media.configure(*root, *mediaConfig, guestRec); err != nil {
		return err
	}
	missing := backendCheck()
	for i := range guestRec {
		if guestRec[i].Backend == "cc" || guestRec[i].UsesQEMU() {
			guestRec[i].Blocked = missing
			if guestRec[i].UsesQEMU() && missing == "" {
				if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
					guestRec[i].Blocked = "Install qemu-system-x86_64 on the lab host."
				}
			}
		}
	}

	store := jsonStore(workspacePath(*root, *stateFile))
	draft, err := store.load()
	if err != nil {
		return err
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("listen requires a numeric loopback host")
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	alpine, err := lab.NewAlpineRepository()
	if err != nil {
		return err
	}
	factory := lab.StarFactory{Context: ctx, Recipes: workspace.FS(), Media: media.open, QEMUEthernet: qemuEthernet, Alpine: alpine}
	prepared := make(chan struct{})
	if *prepareIndy {
		i := slices.IndexFunc(guestRec, func(recipe lab.Recipe) bool { return recipe.ID == "irix-indy" })
		if i < 0 {
			return fmt.Errorf("the Lab catalog has no IRIX Indy recipe")
		}
		factory.Indy = &lab.IndyTemplates{}
		go func() {
			defer close(prepared)
			log := func(message string) { fmt.Println("IRIX template —", message) }
			if err := factory.PrepareIndy(ctx, guestRec[i], log); err != nil {
				if ctx.Err() == nil {
					log(err.Error())
				}
				return
			}
			log("Ready")
		}()
	} else {
		close(prepared)
	}
	manager := lab.NewManager(ctx, draft, guestRec, factory, store, media.check)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: httpApp{
		ctx: ctx, manager: manager, media: media, catalog: guestRec, alpine: alpine,
		templates: append([]lab.Template{}, extension.Templates...),
		software:  lab.SoftwareLibrary(guestRec, extension.SoftwareAliases, extension.SoftwareReferences),
		localHost: listener.Addr().String(), tailnetHost: externalHost, tailnetUser: *user,
	}.handler(ui.Files)}

	clean := make(chan struct{})
	go func() {
		defer close(clean)
		<-ctx.Done()
		_ = server.Close()
		manager.Shutdown()
	}()
	fmt.Printf("Virtual Lab Editor ready at http://%s\n", listener.Addr())
	err = server.Serve(listener)
	stop()
	<-clean
	<-prepared
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func workspacePath(root, name string) string {
	if name == "" || filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(root, name)
}

func backendCheck() string {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return "This preview needs an x64 Linux host with KVM."
	}
	f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		return "Give the lab server access to /dev/kvm and restart it."
	}
	f.Close()
	return ""
}

type jsonStore string

func (s jsonStore) load() (lab.Definition, error) {
	body, err := os.ReadFile(string(s))
	if errors.Is(err, os.ErrNotExist) {
		return lab.Blank(), nil
	}
	if err != nil {
		return lab.Definition{}, err
	}
	var d lab.Definition
	if err := json.Unmarshal(body, &d); err != nil || d.Version != 1 {
		return lab.Definition{}, errors.New("saved workspace is not a version 1 lab")
	}
	return d, nil
}

func (s jsonStore) Save(d lab.Definition) error {
	if s == "" {
		return nil
	}
	body, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	filename := string(s)
	dest := filepath.Dir(filename)
	if err := os.MkdirAll(dest, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dest, ".lab-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, err = f.Write(append(body, '\n'))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(f.Name(), filename)
}
