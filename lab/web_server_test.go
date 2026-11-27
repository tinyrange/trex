package lab

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"github.com/tinyrange/trex/vmm/ethernet"
	"golang.org/x/net/dns/dnsmessage"
	ccnetwork "j5.nz/cc/network"
)

func TestNativeWebServiceRoutesBrowserAndLabEthernet(t *testing.T) {
	const webID = "site"
	const routes = `[{"path":"/health","status":201,"headers":{"X-Lab-Test":"native"},"body":"healthy"}]`
	draft := Blank()
	draft.Nodes = []Node{
		{ID: "switch", Name: "Switch", Recipe: "switch"},
		{ID: "router", Name: "Router", Recipe: "router"},
		{ID: webID, Name: "Web Server", Recipe: "web-server", Config: map[string]any{"memoryMiB": 256, "port": 8080, "content": "routes", "routes": routes}},
	}
	draft.Links = []Link{{End{"switch", "port1"}, End{"router", "lan"}}, {End{"switch", "port2"}, End{webID, "lan"}}}
	m := NewManager(t.Context(), Blank(), Catalog(), StarFactory{Context: t.Context()}, nil, nil)
	t.Cleanup(m.Shutdown)
	if _, err := m.Apply(draft); err != nil {
		t.Fatal(err)
	}
	view := waitState(t, m, "running")
	if _, legacy := view.Definition.Nodes[2].Config["memoryMiB"]; legacy {
		t.Fatal("legacy memory setting was retained")
	}
	surface, ok := m.Surface(webID, "web")
	if !ok || surface.Web == nil {
		t.Fatal("native web service did not advertise a browser")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, "GET", "http://"+surface.Web.Host+"/health", nil)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(resp *http.Response, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusCreated || resp.Header.Get("X-Lab-Test") != "native" || string(body) != "healthy" || err != nil {
			t.Fatalf("unexpected custom response: %d %q %v %v", resp.StatusCode, body, resp.Header, err)
		}
	}
	verify(surface.Web.Transport.RoundTrip(request))
	unknown, err := http.NewRequestWithContext(ctx, "GET", "http://"+surface.Web.Host+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	unknownReply, err := surface.Web.Transport.RoundTrip(unknown)
	if err != nil {
		t.Fatal(err)
	}
	_ = unknownReply.Body.Close()
	if unknownReply.StatusCode != http.StatusNotFound {
		t.Fatalf("routes-only service unexpectedly served its root: %d", unknownReply.StatusCode)
	}

	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var ip netip.Addr
	for !ip.IsValid() {
		ip, _ = netip.ParseAddr(m.View().Nodes[webID].Address)
		if !ip.IsValid() {
			select {
			case <-ctx.Done():
				t.Fatal("Web Server did not acquire an address from lab DHCP")
			case <-tick.C:
			}
		}
	}
	m.mu.RLock()
	switcher := m.switches["switch"].switcher
	m.mu.RUnlock()
	resolver := lanTestPeer(ctx, t, switcher, hardwareAddress("10.20.0.29"), hardwareAddress("router"),
		netip.MustParseAddr("10.20.0.29"), netip.MustParseAddr("10.20.0.1"))
	conn, err := resolver.DialGuest(ctx, 53)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"web-server.lab.test.", "site.lab.test."} {
		reply := dnsExchangeTCP(t, conn, dnsQuery(t, name, dnsmessage.TypeA))
		if reply.RCode != dnsmessage.RCodeSuccess || !reply.Authoritative || len(reply.Answers) != 1 ||
			reply.Answers[0].Body.(*dnsmessage.AResource).A != ip.As4() {
			t.Fatalf("DNS over Ethernet did not resolve %s to %s: %+v", name, ip, reply)
		}
	}
	conn.Close()
	for _, address := range []string{"10.20.0.30", "10.20.0.31"} {
		transport := nativeWebTestClient(ctx, t, switcher, hardwareAddress(address), hardwareAddress(webID), netip.MustParseAddr(address), ip)
		req, err := http.NewRequestWithContext(ctx, "GET", "http://"+ip.String()+":8080/health", nil)
		if err != nil {
			t.Fatal(err)
		}
		verify(transport.RoundTrip(req))
	}
	m.Stop()
	view = waitState(t, m, "idle")
	if _, ok := m.Surface(webID, "web"); ok {
		t.Fatal("stopped service still exposes a browser")
	}
	log := view.Nodes[webID].Log
	if !slices.Contains(log, "HTTP GET /health — 201") || !slices.Contains(log, "stopped — Node stopped") {
		t.Fatalf("stopping removed runtime logs: %v", log)
	}
}

func TestNativeWebServiceReadsHTMLMedia(t *testing.T) {
	var recipe Recipe
	for _, r := range Catalog() {
		if isWebServer(r) {
			recipe = r
			break
		}
	}
	const document = "<html><p>Lab site media</p></html>"
	closed := false
	f := StarFactory{Media: func(ref string) (starfile.File, func() error, error) {
		if ref != "original/site.html" {
			t.Fatalf("unexpected site media: %q", ref)
		}
		return &starfile.Bytes{Data: []byte(document)}, func() error { closed = true; return nil }, nil
	}}
	n := Node{Config: map[string]any{"content": "html"}, Media: map[string]string{"document": "original/site.html"}}
	routes, err := f.website(StartRequest{Recipe: recipe, Node: n})
	if err != nil || !closed || len(routes) != 2 ||
		routes[webRouteKey{"GET", "/"}].Body != document || routes[webRouteKey{"GET", "/index.html"}].Body != document {
		t.Fatalf("site HTML was not loaded and closed: %v %t %v", routes, closed, err)
	}
}

func nativeWebTestClient(ctx context.Context, t *testing.T, switcher *ethernet.Switch, client, server [6]byte, clientIP, serverIP netip.Addr) *http.Transport {
	t.Helper()
	peer := lanTestPeer(ctx, t, switcher, client, server, clientIP, serverIP)
	tr := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return peer.DialGuest(ctx, 8080)
	}}
	t.Cleanup(tr.CloseIdleConnections)
	return tr
}

func lanTestPeer(ctx context.Context, t *testing.T, switcher *ethernet.Switch, client, server [6]byte, clientIP, serverIP netip.Addr) *ccnetwork.Isolated {
	t.Helper()
	peer, err := ccnetwork.NewStaticPeer(server, client, serverIP, clientIP)
	if err != nil {
		t.Fatal(err)
	}
	port := switcher.Connect()
	life, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-tick.C:
				for frame := port.Receive(); frame != nil; frame = port.Receive() {
					_ = peer.Receive(frame)
				}
				for frame := peer.Poll(); frame != nil; frame = peer.Poll() {
					_ = port.Send(frame)
				}
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = port.Close()
		_ = peer.Close()
	})
	return peer
}

func TestNativeWebRoutesRejectInvalidDefinitions(t *testing.T) {
	cases := map[string]string{
		`[{"path":"https://elsewhere.test/"}]`:            "absolute path",
		`[{"path":"/health","status":204,"body":"yes"}]`:  "invalid status or body",
		`[{"path":"/","headers":{"Content-Length":"1"}}]`: "reserved response header",
		`[{"path":"/health"},{"path":"/health"}]`:         "repeats GET /health",
	}
	for input, want := range cases {
		if _, err := parseWebRoutes(input); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("parse %s returned %v; wanted %q", input, err, want)
		}
	}
}
