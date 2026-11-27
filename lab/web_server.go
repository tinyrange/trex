package lab

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	starfile "github.com/tinyrange/trex/storage/star"
	"golang.org/x/net/http/httpguts"
)

const maxWebRoutesJSON = 32768
const maxWebDocument = 4 << 20

// WebMethods lists the HTTP methods available on lab web surfaces.
const WebMethods = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"

func WebAllowsMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

type webRoute struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type webRouteKey struct{ method, path string }

func parseWebRoutes(raw string) (map[webRouteKey]webRoute, error) {
	routes := make(map[webRouteKey]webRoute)
	if strings.TrimSpace(raw) == "" {
		return routes, nil
	}
	if len(raw) > maxWebRoutesJSON || !strings.HasPrefix(strings.TrimSpace(raw), "[") {
		return nil, fmt.Errorf("Enter a JSON array of HTTP routes, up to %d bytes.", maxWebRoutesJSON)
	}
	var entries []webRoute
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&entries); err != nil {
		return nil, fmt.Errorf("Invalid HTTP routes JSON: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF || len(entries) > 64 {
		return nil, errors.New("Enter one JSON array containing at most 64 HTTP routes.")
	}
	for i, entry := range entries {
		if entry.Method == "" {
			entry.Method = http.MethodGet
		}
		if entry.Status == 0 {
			entry.Status = http.StatusOK
		}
		if !WebAllowsMethod(entry.Method) {
			return nil, fmt.Errorf("HTTP route %d has an unsupported method.", i+1)
		}
		ref, err := url.ParseRequestURI(entry.Path)
		clean := path.Clean(entry.Path)
		if err != nil || !strings.HasPrefix(entry.Path, "/") || entry.Path != ref.Path || ref.RawQuery != "" ||
			strings.ContainsAny(entry.Path, "\\?#") || (entry.Path != clean && entry.Path != clean+"/") {
			return nil, fmt.Errorf("HTTP route %d must use an absolute path without a query string or fragment.", i+1)
		}
		if entry.Status < 200 || entry.Status > 599 ||
			entry.Body != "" && (entry.Status == 204 || entry.Status == 205 || entry.Status == 304) {
			return nil, fmt.Errorf("HTTP route %d has an invalid status or body for that status.", i+1)
		}
		headers := make(map[string]string, len(entry.Headers))
		for name, value := range entry.Headers {
			if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidHeaderFieldValue(value) {
				return nil, fmt.Errorf("HTTP route %d has an invalid response header.", i+1)
			}
			key := http.CanonicalHeaderKey(name)
			switch key {
			case "Connection", "Content-Length", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
				return nil, fmt.Errorf("HTTP route %d uses the reserved response header %s.", i+1, key)
			}
			if _, duplicate := headers[key]; duplicate {
				return nil, fmt.Errorf("HTTP route %d repeats response header %s.", i+1, key)
			}
			headers[key] = value
		}
		entry.Headers = headers
		key := webRouteKey{entry.Method, entry.Path}
		if _, exists := routes[key]; exists {
			return nil, fmt.Errorf("HTTP route %d repeats %s %s.", i+1, key.method, key.path)
		}
		routes[key] = entry
	}
	return routes, nil
}

const webExampleIndex = `<!doctype html>
<html lang="en"><meta charset="utf-8"><title>Lab Web Server</title>
<link rel="stylesheet" href="/style.css">
<main><h1>Lab Web Server</h1><p>This page is served by the lab HTTP service.</p>
<p><a href="/about.html">About this server</a></p></main></html>
`
const webExampleStyle = "body { font: 1rem system-ui; margin: 3rem; color: #172331; background: #f1f5f9; } main { max-width: 38rem; } a { color: #164c92; }"
const webExampleAbout = `<!doctype html><html lang="en"><meta charset="utf-8"><title>About the Lab Web Server</title>
<link rel="stylesheet" href="/style.css"><main><h1>About the Lab Web Server</h1><p>Native HTTP on the isolated lab network.</p>
<p><a href="/">Home</a></p></main></html>`

func (f StarFactory) website(req StartRequest) (map[webRouteKey]webRoute, error) {
	routes, err := parseWebRoutes(req.Node.String(req.Recipe, "routes"))
	if err != nil {
		return nil, err
	}
	add := func(route, contentType, body string) {
		key := webRouteKey{"GET", route}
		if _, exists := routes[key]; !exists {
			routes[key] = webRoute{Status: http.StatusOK, Headers: map[string]string{"Content-Type": contentType}, Body: body}
		}
	}
	switch req.Node.String(req.Recipe, "content") {
	case "html":
		if f.Media == nil {
			return nil, errors.New("Website media is unavailable.")
		}
		slot := req.Recipe.Media[0]
		if req.Log != nil {
			req.Log(slot.Label + " — " + slot.Reference(req.Node))
		}
		file, close, err := f.Media(slot.Reference(req.Node))
		if err != nil {
			return nil, fmt.Errorf("open website HTML: %w", err)
		}
		defer close()
		if file.Size() < 0 || file.Size() > maxWebDocument {
			return nil, errors.New("The website HTML file exceeds 4 MiB.")
		}
		data, err := starfile.ReadAll(file)
		if err != nil {
			return nil, fmt.Errorf("read website HTML: %w", err)
		}
		add("/", "text/html; charset=utf-8", string(data))
		add("/index.html", "text/html; charset=utf-8", string(data))
	case "example":
		add("/", "text/html; charset=utf-8", webExampleIndex)
		add("/index.html", "text/html; charset=utf-8", webExampleIndex)
		add("/style.css", "text/css; charset=utf-8", webExampleStyle)
		add("/about.html", "text/html; charset=utf-8", webExampleAbout)
	}
	return routes, nil
}

type webServer struct {
	cancel    context.CancelFunc
	server    *http.Server
	transport *http.Transport
	lanDone   <-chan struct{}
	done      chan struct{}
	err       error
	address   netip.Addr
	port      uint16
	surfaces  []Surface
}

func (s *webServer) Surfaces() []Surface   { return s.surfaces }
func (s *webServer) Done() <-chan struct{} { return s.done }
func (s *webServer) Err() error            { return s.err }
func (s *webServer) Address() string {
	if s.address.IsValid() {
		return s.address.String()
	}
	return ""
}
func (s *webServer) Message() string {
	return fmt.Sprintf("HTTP service listening on port %d", s.port)
}
func (s *webServer) Close() error {
	s.cancel()
	err := s.server.Close()
	s.transport.CloseIdleConnections()
	<-s.done
	if s.lanDone != nil {
		<-s.lanDone
	}
	return err
}

func (f StarFactory) startWebServer(ctx context.Context, req StartRequest) (Guest, error) {
	routes, err := f.website(req)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var port uint16
	switch value := req.Node.Value(req.Recipe, "port").(type) {
	case int:
		port = uint16(value)
	case float64:
		port = uint16(value)
	}
	if port == 0 {
		return nil, errors.New("HTTP service requires a valid port.")
	}
	var address netip.Addr
	if configured := req.Node.String(req.Recipe, "address"); configured != "" {
		prefix, err := netip.ParsePrefix(configured)
		if err != nil || !usableLANIP(prefix.Addr()) {
			return nil, errors.New("HTTP service requires a unicast IPv4 address.")
		}
		address = prefix.Addr()
	}
	host := "web.lab"
	if address.IsValid() {
		host = address.String()
	}
	if port != 80 {
		host = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	life, cancel := context.WithCancel(f.Context)
	listener := newWebListener()
	transport := &http.Transport{
		DialContext: listener.dial, DisableCompression: true, DisableKeepAlives: true,
		MaxConnsPerHost: 16, MaxResponseHeaderBytes: 64 << 10,
	}
	s := &webServer{cancel: cancel, transport: transport, done: make(chan struct{}), address: address, port: port,
		surfaces: []Surface{{ID: "web", Name: "Open website", Kind: "web", Web: &WebSurface{
			Key: rand.Text(), Host: host, Transport: transport,
		}}},
	}
	s.server = &http.Server{
		Handler:           webHandler(routes, req.Log),
		BaseContext:       func(net.Listener) context.Context { return life },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	if req.Switch != nil {
		s.lanDone = startWebEthernet(life, req, listener, address, port)
	}
	go func() {
		defer close(s.done)
		if err := s.server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			s.err = err
			cancel()
		}
	}()
	return s, nil
}

func webHandler(routes map[webRouteKey]webRoute, log func(string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry, ok := routes[webRouteKey{r.Method, r.URL.Path}]
		if !ok && r.Method == http.MethodHead {
			entry, ok = routes[webRouteKey{http.MethodGet, r.URL.Path}]
		}
		if log != nil {
			status := entry.Status
			if !ok {
				status = http.StatusNotFound
			}
			log(fmt.Sprintf("HTTP %s %s — %d", r.Method, r.URL.EscapedPath(), status))
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		for name, value := range entry.Headers {
			w.Header().Set(name, value)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		if r.Method == http.MethodHead && entry.Status != 204 && entry.Status != 205 && entry.Status != 304 {
			w.Header().Set("Content-Length", strconv.Itoa(len(entry.Body)))
		}
		w.WriteHeader(entry.Status)
		if r.Method != http.MethodHead && entry.Body != "" {
			_, _ = io.WriteString(w, entry.Body)
		}
	})
}

// webListener merges lab Ethernet connections and private editor connections.
// Both arrive as Go byte streams and never need a host socket.
type webListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func newWebListener() *webListener {
	return &webListener{connections: make(chan net.Conn), done: make(chan struct{})}
}

func (l *webListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *webListener) deliver(ctx context.Context, conn net.Conn) error {
	select {
	case l.connections <- conn:
		return nil
	case <-l.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *webListener) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	client, server := net.Pipe()
	if err := l.deliver(ctx, server); err != nil {
		client.Close()
		server.Close()
		return nil, err
	}
	return client, nil
}

func (l *webListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

type webListenerAddress struct{}

func (webListenerAddress) Network() string { return "lab" }
func (webListenerAddress) String() string  { return "lab HTTP" }
func (*webListener) Addr() net.Addr        { return webListenerAddress{} }
