package lab

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sync"

	"github.com/tinyrange/trex/vmm"
	"github.com/tinyrange/trex/vmm/ethernet"
)

type Surface struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Display  vmm.DisplaySource `json:"-"`
	Terminal Terminal          `json:"-"`
	Web      *WebSurface       `json:"-"`
}

// WebSurface grants HTTP only to the selected running guest.
type WebSurface struct {
	Key       string
	Host      string
	Transport http.RoundTripper
}

type Terminal interface {
	Text() string
	Output(context.Context, uint64) ([]byte, uint64, error)
	Input(context.Context, string) error
}

type NodeView struct {
	Phase    string    `json:"phase"`
	Message  string    `json:"message,omitempty"`
	Surfaces []Surface `json:"surfaces"`
	Address  string    `json:"address,omitempty"`
	Observed bool      `json:"addressObserved,omitempty"`
	Log      []string  `json:"log,omitempty"`
}

type View struct {
	Definition Definition          `json:"definition"`
	Applied    *Definition         `json:"applied,omitempty"`
	State      string              `json:"state"`
	Nodes      map[string]NodeView `json:"nodes"`
	Operation  []Change            `json:"operation"`
	Error      string              `json:"error,omitempty"`
}

type Guest interface {
	Surfaces() []Surface
	Close() error
}

type StartRequest struct {
	Node    Node
	Recipe  Recipe
	Switch  *ethernet.Switch
	Domain  Guest
	Phase   func(string, string)
	Log     func(string)
	Address func(string)
}

type Factory interface {
	Start(context.Context, StartRequest) (Guest, error)
}

type DraftStore interface {
	Save(Definition) error
}

// Manager serializes mutations of a running lab. The active definition tracks
// resources that exist after each completed step, including partial failures.
type Manager struct {
	ctx     context.Context
	factory Factory
	store   DraftStore
	check   MediaCheck
	recipes map[string]Recipe

	mu        sync.RWMutex
	draft     Definition
	active    Definition
	state     string
	err       string
	nodeViews map[string]NodeView
	changes   []Change
	switches  map[string]*networkSegment
	guests    map[string]Guest
	cancel    context.CancelFunc
	done      chan struct{}
}

func NewManager(ctx context.Context, initial Definition, recipes []Recipe, f Factory, store DraftStore, check MediaCheck) *Manager {
	types := make(map[string]Recipe, len(recipes))
	for _, recipe := range recipes {
		types[recipe.ID] = recipe
	}
	return &Manager{ctx: ctx, factory: f, store: store, check: check, recipes: types,
		draft: initial.normalized(types), active: Blank(), state: "idle", nodeViews: make(map[string]NodeView),
		switches: make(map[string]*networkSegment), guests: make(map[string]Guest)}
}

func (m *Manager) View() View {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.view()
}

func (m *Manager) NodeAddress(id string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.nodeAddress(id, m.switches[m.active.Network(id)]).Address
}

func (m *Manager) nodeAddress(id string, segment *networkSegment) NodeView {
	info := m.nodeViews[id]
	if segment != nil && info.Phase == "running" && m.guests[id] != nil {
		if address := segment.address(id); address.IsValid() {
			info.Address, info.Observed = address.String(), true
		}
	}
	return info
}

func (m *Manager) view() View {
	v := View{Definition: m.draft.Clone(), State: m.state, Error: m.err, Nodes: make(map[string]NodeView),
		Operation: append([]Change{}, m.changes...)}
	if len(m.active.Nodes) != 0 {
		active := m.active.Clone()
		v.Applied = &active
	}
	for id := range m.nodeViews {
		info := m.nodeAddress(id, m.switches[m.active.Network(id)])
		info.Log = append([]string(nil), info.Log...)
		v.Nodes[id] = info
	}
	return v
}

func (m *Manager) lanAddress(network string, segment *networkSegment, label string) netip.Addr {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.switches[network] != segment {
		return netip.Addr{}
	}
	var idMatch, nameMatch string
	var idCount, nameCount int
	for _, node := range m.active.Nodes {
		if node.ID == network || m.active.Network(node.ID) != network || m.nodeViews[node.ID].Phase != "running" {
			continue
		}
		if dnsLabel(node.ID) == label {
			idMatch = node.ID
			idCount++
		}
		if dnsLabel(node.Name) == label {
			nameMatch = node.ID
			nameCount++
		}
	}
	if idCount != 0 {
		if idCount != 1 {
			return netip.Addr{}
		}
		nameMatch, nameCount = idMatch, 1
	}
	if nameCount != 1 {
		return netip.Addr{}
	}
	ip, _ := netip.ParseAddr(m.nodeAddress(nameMatch, segment).Address)
	return ip
}

func (m *Manager) Plan(d Definition) Plan {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return Diff(d.normalized(m.recipes), m.active, m.recipes, m.check)
}

func (m *Manager) Save(d Definition) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d.Version != 1 || len(d.Nodes) > 64 || len(d.Links) > 128 {
		return View{}, errors.New("invalid lab definition version or size")
	}
	if err := m.save(d.normalized(m.recipes)); err != nil {
		return View{}, err
	}
	return m.view(), nil
}

func (m *Manager) save(d Definition) error {
	if m.store != nil {
		if err := m.store.Save(d); err != nil {
			return err
		}
	}
	m.draft = d.Clone()
	return nil
}

func (m *Manager) Apply(d Definition) (View, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done != nil {
		return View{}, errors.New("wait for the current lab operation to finish")
	}
	if err := m.ctx.Err(); err != nil {
		return View{}, err
	}
	d = d.normalized(m.recipes)
	plan := Diff(d, m.active, m.recipes, m.check)
	if len(plan.Issues) != 0 {
		return View{}, fmt.Errorf("%s %s", plan.Issues[0].Node, plan.Issues[0].Message)
	}
	if err := m.save(d); err != nil {
		return View{}, err
	}
	ctx, cancel := context.WithCancel(m.ctx)
	done := make(chan struct{})
	m.cancel, m.done, m.changes = cancel, done, plan.Changes
	m.state, m.err = "applying", ""
	go func() {
		defer cancel()
		err := m.apply(ctx, d, plan)
		m.finish(done, err)
	}()
	return m.view(), nil
}

func (m *Manager) finish(done chan struct{}, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done != done {
		close(done)
		return
	}
	if err != nil {
		m.state, m.err = "failed", err.Error()
	} else if len(m.active.Nodes) == 0 {
		m.state, m.err = "idle", ""
	} else {
		m.state, m.err = "running", ""
	}
	m.cancel, m.done = nil, nil
	close(done)
}

func (m *Manager) Stop() View {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == "stopping" || (m.done == nil && len(m.active.Nodes) == 0) {
		return m.view()
	}
	previous := m.done
	if m.cancel != nil {
		m.cancel()
	}
	done := make(chan struct{})
	m.state, m.done, m.cancel = "stopping", done, nil
	// Stop waits for the in-flight apply to release any uncommitted resources.
	go func() {
		if previous != nil {
			<-previous
		}
		m.mu.Lock()
		m.err = ""
		nodes := append([]Node(nil), m.active.Nodes...)
		m.mu.Unlock()
		m.finish(done, m.stopNodes(nodes))
	}()
	return m.view()
}

func (m *Manager) Shutdown() {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	done := m.done
	m.mu.Unlock()
	if done != nil {
		<-done
	}
	m.mu.RLock()
	nodes := append([]Node(nil), m.active.Nodes...)
	m.mu.RUnlock()
	_ = m.stopNodes(nodes)
}

func (m *Manager) Surface(id, surface string) (Surface, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.nodeViews[id].Surfaces {
		if s.ID == surface {
			return s, true
		}
	}
	return Surface{}, false
}

func (m *Manager) setNode(id, phase, message string, surfaces []Surface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	info := m.nodeViews[id]
	info.Phase, info.Message, info.Surfaces = phase, message, append([]Surface{}, surfaces...)
	m.nodeViews[id] = info
	m.appendLog(id, phase+" — "+message)
}

func (m *Manager) appendLog(id, entry string) {
	info := m.nodeViews[id]
	if len(entry) > 500 {
		entry = entry[:500] + "…"
	}
	if len(info.Log) >= 24 {
		copy(info.Log, info.Log[1:])
		info.Log = info.Log[:23]
	}
	info.Log = append(info.Log, entry)
	m.nodeViews[id] = info
}

func (m *Manager) priority(n Node) int {
	r := m.recipes[n.Recipe]
	if isSwitch(r) {
		return 0
	}
	if isRouter(r) {
		return 1
	}
	if n.String(r, "domain") != "" {
		return 3
	}
	return 2
}

func (m *Manager) stopNodes(nodes []Node) error {
	slices.SortStableFunc(nodes, func(a, b Node) int { return m.priority(b) - m.priority(a) })
	var result error
	for _, n := range nodes {
		m.mu.Lock()
		guest := m.guests[n.ID]
		if segment := m.switches[n.ID]; segment != nil {
			_ = segment.observer.Close()
		}
		segment := m.switches[m.active.Network(n.ID)]
		delete(m.guests, n.ID)
		delete(m.switches, n.ID)
		if view, exists := m.nodeViews[n.ID]; exists {
			view.Phase, view.Message, view.Address, view.Observed = "stopped", "Node stopped", "", false
			view.Surfaces = []Surface{}
			m.nodeViews[n.ID] = view
			m.appendLog(n.ID, "stopped — Node stopped")
		}
		m.active.Nodes = slices.DeleteFunc(m.active.Nodes, func(node Node) bool { return node.ID == n.ID })
		m.active.Links = slices.DeleteFunc(m.active.Links, func(link Link) bool { return link.A.Node == n.ID || link.B.Node == n.ID })
		m.mu.Unlock()
		if guest != nil {
			if err := guest.Close(); err != nil {
				result = errors.Join(result, fmt.Errorf("stop %s: %w", n.Name, err))
			}
		}
		if segment != nil {
			segment.forget(n.ID)
		}
	}
	return result
}

func (m *Manager) apply(ctx context.Context, draft Definition, plan Plan) error {
	discard := make(map[string]bool)
	for _, change := range plan.Changes {
		if change.Action == "stop" || change.Action == "rebuild" {
			discard[change.Node] = true
		}
	}
	m.mu.Lock()
	for id := range m.nodeViews {
		if _, live := m.active.Node(id); !live {
			delete(m.nodeViews, id)
		}
	}
	stopping := make([]Node, 0, len(discard))
	for _, n := range m.active.Nodes {
		if discard[n.ID] {
			stopping = append(stopping, n)
		}
	}
	m.mu.Unlock()
	if err := m.stopNodes(stopping); err != nil {
		return err
	}

	nodes := append([]Node(nil), draft.Nodes...)
	slices.SortStableFunc(nodes, func(a, b Node) int { return m.priority(a) - m.priority(b) })
	for _, n := range nodes {
		if err := ctx.Err(); err != nil {
			return err
		}
		r := m.recipes[n.Recipe]
		m.mu.RLock()
		_, alreadyRunning := m.active.Node(n.ID)
		var switcher *ethernet.Switch
		network := draft.Network(n.ID)
		segment := m.switches[network]
		if segment != nil {
			switcher = segment.switcher
		}
		domain := m.guests[n.String(r, "domain")]
		m.mu.RUnlock()
		var started Guest
		if !alreadyRunning {
			if isSwitch(r) {
				m.mu.Lock()
				m.switches[n.ID] = newNetworkSegment()
				m.mu.Unlock()
				m.setNode(n.ID, "running", "Isolated Ethernet switch available", nil)
			} else {
				var guest Guest
				var err error
				if isRouter(r) {
					guest, err = startDHCPRouter(m.ctx, n, r, segment, func(label string) netip.Addr {
						return m.lanAddress(network, segment, label)
					})
				} else {
					message := "Preparing original media"
					if isWebServer(r) {
						message = "Preparing HTTP service"
					}
					m.setNode(n.ID, "preparing", message, nil)
					guest, err = m.factory.Start(ctx, StartRequest{Node: n, Recipe: r, Switch: switcher, Domain: domain,
						Phase: func(phase, message string) { m.setNode(n.ID, phase, message, nil) },
						Log: func(entry string) {
							m.mu.Lock()
							defer m.mu.Unlock()
							if info, ok := m.nodeViews[n.ID]; ok && info.Phase != "stopped" {
								m.appendLog(n.ID, entry)
							}
						},
						Address: func(address string) {
							m.mu.Lock()
							defer m.mu.Unlock()
							if info, ok := m.nodeViews[n.ID]; ok && info.Phase != "stopped" {
								if address == "" && segment != nil {
									segment.forget(n.ID)
								}
								info.Address = address
								m.nodeViews[n.ID] = info
							}
						},
					})
				}
				if err != nil {
					m.setNode(n.ID, "failed", err.Error(), nil)
					return fmt.Errorf("%s: %w", n.Name, err)
				}
				m.mu.Lock()
				m.guests[n.ID] = guest
				started = guest
				m.mu.Unlock()
				message := "Machine started"
				if status, ok := guest.(interface{ Message() string }); ok && status.Message() != "" {
					message = status.Message()
				}
				m.setNode(n.ID, "running", message, guest.Surfaces())
				if source, ok := guest.(interface{ Address() string }); ok && switcher != nil && source.Address() != "" {
					m.mu.Lock()
					info := m.nodeViews[n.ID]
					info.Address = source.Address()
					m.nodeViews[n.ID] = info
					m.mu.Unlock()
				}
			}
		}
		m.mu.Lock()
		index := slices.IndexFunc(m.active.Nodes, func(other Node) bool { return other.ID == n.ID })
		if index >= 0 {
			m.active.Nodes[index] = n
		} else {
			m.active.Nodes = append(m.active.Nodes, n)
		}
		m.active.Links = m.active.Links[:0]
		for _, link := range draft.Links {
			_, a := m.active.Node(link.A.Node)
			_, b := m.active.Node(link.B.Node)
			if a && b {
				m.active.Links = append(m.active.Links, link)
			}
		}
		m.active.Name = draft.Name
		m.mu.Unlock()
		if status, ok := started.(interface {
			Done() <-chan struct{}
			Err() error
		}); ok {
			go func() {
				<-status.Done()
				m.mu.Lock()
				defer m.mu.Unlock()
				if m.guests[n.ID] != started {
					return
				}
				delete(m.guests, n.ID)
				m.active.Nodes = slices.DeleteFunc(m.active.Nodes, func(other Node) bool { return other.ID == n.ID })
				m.active.Links = slices.DeleteFunc(m.active.Links, func(link Link) bool { return link.A.Node == n.ID || link.B.Node == n.ID })
				info := m.nodeViews[n.ID]
				info.Phase, info.Message, info.Surfaces, info.Address = "stopped", "The guest shut down", []Surface{}, ""
				if err := status.Err(); err != nil {
					info.Phase, info.Message = "failed", err.Error()
				}
				m.nodeViews[n.ID] = info
				m.appendLog(n.ID, info.Phase+" — "+info.Message)
				if len(m.active.Nodes) == 0 && m.done == nil {
					m.state = "idle"
				}
			}()
		}
	}
	return nil
}
