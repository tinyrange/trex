package lab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/tinyrange/trex/channel"
	starfrontend "github.com/tinyrange/trex/frontend/starlark"
	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ethernet"
	vmmstar "github.com/tinyrange/trex/vmm/star"
	"go.starlark.net/starlark"
)

// MediaSource hands the caller an owned read-only original-media file.
type MediaSource func(ref string) (starfile.File, func() error, error)

type StarFactory struct {
	Context      context.Context
	Recipes      fs.FS
	Media        MediaSource
	QEMUEthernet func(context.Context, *ethernet.Switch) (string, func() error, error)
}

type labCommand struct {
	seq, op  int
	name     string
	password string
	result   chan error
}

type machineTrust struct {
	computer, password, address string
	sid, guid                   starlark.Value
	provisioned                 bool
	sequence                    int
}

type starGuest struct {
	cancel    context.CancelFunc
	done      chan struct{}
	surfaces  []Surface
	message   string
	address   string
	commands  chan labCommand
	sid, guid starlark.Value
	// Only the lab's serialized apply operation allocates through a guest.
	accounts map[string]*machineTrust
	sequence int
	err      error // Read only after done closes.
}

func (g *starGuest) Surfaces() []Surface   { return g.surfaces }
func (g *starGuest) Message() string       { return g.message }
func (g *starGuest) Address() string       { return g.address }
func (g *starGuest) Done() <-chan struct{} { return g.done }
func (g *starGuest) Err() error            { return displayError(g.err) }

func (g *starGuest) Close() error {
	g.cancel()
	<-g.done
	if errors.Is(g.err, context.Canceled) {
		return nil
	}
	return g.err
}

func computerID(request StartRequest) string {
	if name := request.Node.String(request.Recipe, "computerName"); name != "" {
		return strings.ToUpper(name)
	}
	sum := sha256.Sum256([]byte(request.Node.ID))
	return "LAB" + strings.ToUpper(hex.EncodeToString(sum[:4]))
}

func (g *starGuest) trustFor(id, computer string) (*machineTrust, error) {
	if current := g.accounts[id]; current != nil && (current.computer == computer || g.guid != nil) {
		return current, nil
	}
	t := &machineTrust{computer: computer, password: strings.ToLower(computer), sid: g.sid, guid: g.guid}
	for other, account := range g.accounts {
		if other != id && account.computer == computer {
			return nil, fmt.Errorf("computer name %s already belongs to another lab node", computer)
		}
	}
	if g.guid != nil {
		if len(g.accounts) >= 32 {
			return nil, errors.New("this controller’s preprovisioned workstation pool is full")
		}
		t.computer = fmt.Sprintf("CLIENT%d", 2000+len(g.accounts))
		t.address = fmt.Sprintf("10.20.0.%d", len(g.accounts)+2)
		t.provisioned = true
	}
	g.accounts[id] = t
	return t, nil
}

func (g *starGuest) command(ctx context.Context, trust *machineTrust, op int) error {
	if trust.sequence == 0 {
		g.sequence++
		trust.sequence = g.sequence
	}
	command := labCommand{trust.sequence, op, trust.computer, trust.password, make(chan error, 1)}
	select {
	case g.commands <- command:
	case <-g.done:
		return errors.New("the domain controller stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-command.result:
		return err
	case <-g.done:
		return errors.New("the domain controller stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *starGuest) reserve(ctx context.Context, trust *machineTrust) error {
	if trust.provisioned {
		return nil
	}
	if err := g.command(ctx, trust, 1); err != nil {
		return err
	}
	trust.provisioned = true
	return nil
}

func (f StarFactory) Start(ctx context.Context, request StartRequest) (Guest, error) {
	life, cancel := context.WithCancel(f.Context)
	g := &starGuest{cancel: cancel, done: make(chan struct{}), commands: make(chan labCommand), accounts: make(map[string]*machineTrust)}
	ready := make(chan struct{})
	go func() {
		defer close(g.done)
		g.err = f.run(life, ctx, request, g, ready)
	}()
	select {
	case <-ready:
		if ctx.Err() == nil {
			return g, nil
		}
	case <-g.done:
		err := displayError(g.err)
		if err == nil {
			err = errors.New("recipe exited before the machine was available")
		}
		cancel()
		return nil, err
	case <-ctx.Done():
	}
	cancel()
	<-g.done
	return nil, ctx.Err()
}

func displayError(err error) error {
	var eval *starlark.EvalError
	if errors.As(err, &eval) {
		return errors.New(strings.TrimPrefix(eval.Msg, "fail: "))
	}
	return err
}

func configValue(v any) starlark.Value {
	switch v := v.(type) {
	case string:
		return starlark.String(v)
	case bool:
		return starlark.Bool(v)
	case int:
		return starlark.MakeInt(v)
	case float64:
		return starlark.MakeInt(int(v))
	case []string:
		values := make(starlark.Tuple, len(v))
		for i, id := range v {
			values[i] = starlark.String(id)
		}
		return values
	}
	return starlark.None
}

func dictionary(fields map[string]starlark.Value) *starlark.Dict {
	d := starlark.NewDict(len(fields))
	for k, v := range fields {
		if v != nil {
			_ = d.SetKey(starlark.String(k), v)
		}
	}
	return d
}

func value(d *starlark.Dict, key string) starlark.Value {
	out, ok, _ := d.Get(starlark.String(key))
	if !ok || out == starlark.None {
		return nil
	}
	return out
}

func (f StarFactory) run(life, apply context.Context, req StartRequest, guest *starGuest, ready chan struct{}) error {
	cfg := make(map[string]starlark.Value)
	for _, field := range req.Recipe.Fields {
		cfg[field.Key] = configValue(req.Node.Value(req.Recipe, field.Key))
	}
	computer := computerID(req)
	var domain *starGuest
	var trust *machineTrust
	if req.Domain != nil {
		var ok bool
		domain, ok = req.Domain.(*starGuest)
		if !ok || domain.sid == nil {
			return errors.New("the selected domain controller is unavailable")
		}
		var err error
		trust, err = domain.trustFor(req.Node.ID, computer)
		if err != nil {
			return err
		}
		computer = trust.computer
	}
	cfg["machineName"] = starlark.String(computer)
	cfg["programGroup"] = starlark.NewBuiltin("program_group", programGroupBuiltin)
	hash := sha256.Sum256([]byte(req.Node.ID))
	hardware := hardwareAddress(req.Node.ID)
	mac := net.HardwareAddr(hardware[:]).String()
	address := fmt.Sprintf("10.20.0.%d", 64+int(hash[4])%160)
	cfg["netAddress"] = starlark.String(address)

	media := make(map[string]starlark.Value)
	var closes []func() error
	defer func() {
		for _, close := range closes {
			_ = close()
		}
	}()
	for _, slot := range req.Recipe.Media {
		if slot.Active(req.Node, req.Recipe) {
			if req.Log != nil {
				req.Log(slot.Label + " — " + slot.Reference(req.Node))
			}
			file, close, err := f.Media(slot.Reference(req.Node))
			if err != nil {
				return fmt.Errorf("open %s: %w", slot.Label, err)
			}
			closes = append(closes, close)
			media[slot.Key] = file
		}
	}
	switchVal := starlark.Value(starlark.None)
	if req.Switch != nil {
		switchVal = vmmstar.NewSwitchValue(req.Switch)
	}
	if req.Recipe.UsesQEMU() && req.Switch != nil {
		if f.QEMUEthernet == nil {
			return errors.New("the QEMU Ethernet adapter is unavailable")
		}
		address, close, err := f.QEMUEthernet(life, req.Switch)
		if err != nil {
			return err
		}
		defer close()
		cfg["qemuPeer"] = starlark.String(address)
	}
	trustVal := starlark.Value(starlark.None)
	if trust != nil {
		trustVal = dictionary(map[string]starlark.Value{
			"sid": trust.sid, "guid": trust.guid, "address": starlark.String(trust.address), "password": starlark.String(trust.password),
		})
	}

	builtins := starlark.StringDict{}
	builtins["lab_phase"] = starlark.NewBuiltin("lab_phase", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		var phase, message string
		if err := starlark.UnpackArgs("lab_phase", args, kwargs, "phase", &phase, "message", &message); err != nil {
			return nil, err
		}
		req.Phase(phase, message)
		return starlark.None, nil
	})
	builtins["lab_reserve_account"] = starlark.NewBuiltin("lab_reserve_account", func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		if trust == nil || domain.guid != nil {
			return nil, errors.New("this guest has no live account provisioning operation")
		}
		return starlark.None, domain.reserve(apply, trust)
	})
	builtins["lab_node"] = starlark.NewBuiltin("lab_node", func(thread *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		globals, err := thread.Load(thread, req.Recipe.Module)
		if err != nil {
			return nil, err
		}
		run := globals[req.Recipe.Function]
		if run == nil {
			return nil, fmt.Errorf("recipe %s has no implementation", req.Recipe.ID)
		}
		result, err := starlark.Call(thread, run, starlark.Tuple{starlark.String(req.Recipe.ID), dictionary(cfg), dictionary(media), switchVal, starlark.String(mac), trustVal}, nil)
		if err != nil {
			return nil, err
		}
		info, ok := result.(*starlark.Dict)
		if !ok {
			return nil, errors.New("recipe did not return a machine record")
		}
		vm, ok := value(info, "vm").(interface {
			VMMDisplay() (vmm.DisplaySource, error)
		})
		if !ok {
			return nil, errors.New("recipe did not return a display-capable machine")
		}
		display, err := vm.VMMDisplay()
		if err != nil {
			if !req.Recipe.UsesQEMU() {
				return nil, err
			}
			attrs, ok := vm.(starlark.HasAttrs)
			if !ok {
				return nil, err
			}
			display = qemuDisplay{machine: attrs, absolute: req.Recipe.AbsolutePointer}
		}
		if value(info, "display") != starlark.False {
			guest.surfaces = []Surface{{ID: "desktop", Name: "Display", Kind: "display", Display: display}}
		}
		if console, ok := value(info, "console").(channel.ByteChannel); ok {
			serial := &serialConsole{link: console, changed: make(chan struct{})}
			guest.surfaces = append(guest.surfaces, Surface{ID: "serial", Name: "Serial console", Kind: "terminal", Terminal: serial})
			go serial.read()
			defer serial.link.Close()
		}
		guest.message, _ = starlark.AsString(value(info, "message"))
		guest.address, _ = starlark.AsString(value(info, "address"))
		if guest.message == "" {
			guest.message = req.Recipe.Hint
		}
		guest.sid, guest.guid = value(info, "domain_sid"), value(info, "domain_guid")
		if guest.sid != nil {
			guest.sid.Freeze()
		}
		if guest.guid != nil {
			guest.guid.Freeze()
		}
		close(ready)

		provision := value(info, "provision")
		machine, _ := value(info, "vm").(starlark.HasAttrs)
		statusCheck := time.NewTicker(time.Second)
		defer statusCheck.Stop()
		for {
			select {
			case <-life.Done():
				return starlark.None, nil
			case <-statusCheck.C:
				if machine != nil {
					status, err := machine.Attr("status")
					if err != nil {
						return nil, err
					}
					if status == starlark.String("stopped") {
						return starlark.None, nil
					}
				}
			case op := <-guest.commands:
				_, err := starlark.Call(thread, provision, starlark.Tuple{
					starlark.MakeInt(op.seq), starlark.String(op.name), starlark.String(op.password), starlark.MakeInt(op.op),
				}, nil)
				op.result <- displayError(err)
			}
		}
	})
	err := starfrontend.RunProgram(life, starfrontend.Program{
		Files: recipeFiles{f.Recipes}, Entry: recipeNamespace + "serve.star", Builtins: builtins, Print: req.Log,
	})
	var evaluation *starlark.EvalError
	if req.Log != nil && errors.As(err, &evaluation) {
		for _, line := range strings.Split(strings.TrimSpace(evaluation.Backtrace()), "\n") {
			req.Log(line)
		}
	}
	return err
}

type serialConsole struct {
	link    channel.ByteChannel
	mu      sync.Mutex
	writeMu sync.Mutex
	text    []byte
	end     uint64
	changed chan struct{}
	closed  bool
}

func (s *serialConsole) read() {
	defer func() {
		s.mu.Lock()
		s.closed = true
		close(s.changed)
		s.mu.Unlock()
	}()
	buf := make([]byte, 8192)
	for {
		n, err := s.link.Read(buf)
		if n != 0 {
			s.mu.Lock()
			s.text = append(s.text, buf[:n]...)
			s.end += uint64(n)
			if len(s.text) > 64<<10 {
				s.text = append(s.text[:0], s.text[len(s.text)-(64<<10):]...)
			}
			close(s.changed)
			s.changed = make(chan struct{})
			s.mu.Unlock()
		}
		if err != nil {
			return
		}
		if n == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (s *serialConsole) Output(ctx context.Context, after uint64) ([]byte, uint64, error) {
	for {
		s.mu.Lock()
		end, changed, closed := s.end, s.changed, s.closed
		base := end - uint64(len(s.text))
		if after < end {
			data := append([]byte(nil), s.text[max(after, base)-base:]...)
			s.mu.Unlock()
			return data, end, nil
		}
		s.mu.Unlock()
		if closed {
			return nil, after, io.EOF
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, after, ctx.Err()
		}
	}
}

func (s *serialConsole) Text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.text)
}

func (s *serialConsole) Input(ctx context.Context, text string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return channel.WriteAll(s.link, []byte(text))
}
