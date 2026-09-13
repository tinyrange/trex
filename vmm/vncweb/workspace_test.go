package vncweb

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinyrange/trex/vmm"
)

type workspaceStub struct {
	mu               sync.Mutex
	vms              []vmm.DisplayVM
	entered, proceed chan struct{}
}

func (s *workspaceStub) VMs() []vmm.DisplayVM {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]vmm.DisplayVM(nil), s.vms...)
}
func (*workspaceStub) CanCreate() bool { return true }
func (s *workspaceStub) Create(context.Context) (vmm.DisplayVM, error) {
	close(s.entered)
	<-s.proceed
	s.mu.Lock()
	defer s.mu.Unlock()
	vm := vmm.DisplayVM{ID: "3", Name: "CLIENT32", Display: displayStub{}}
	s.vms = append(s.vms, vm)
	return vm, nil
}
func TestWorkspaceCatalogAndCreationGuards(t *testing.T) {
	workspace := &workspaceStub{vms: []vmm.DisplayVM{{ID: "1", Name: "DOMAIN31", Display: displayStub{}}, {ID: "2", Name: "CLIENT31", Display: displayStub{}}}, entered: make(chan struct{}), proceed: make(chan struct{})}
	app, _ := NewWorkspace(workspace)
	request := func(method, token, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://example.com/api/vms", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		app.ServeHTTP(w, r)
		return w
	}
	if got := request("GET", "wrong", "").Code; got != 403 {
		t.Fatal(got)
	}
	if got := request("POST", app.Token, "http://other.invalid").Code; got != 403 {
		t.Fatal(got)
	}
	if got := request("POST", app.Token, "").Code; got != 403 {
		t.Fatal(got)
	}
	catalog := request("GET", app.Token, "")
	var result struct {
		VMs       []vmm.DisplayVM
		CanCreate bool
	}
	if err := json.Unmarshal(catalog.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.VMs) != 2 || !result.CanCreate {
		t.Fatalf("%s", catalog.Body)
	}
	done := make(chan int, 1)
	go func() { done <- request("POST", app.Token, "http://example.com").Code }()
	<-workspace.entered
	if got := request("POST", app.Token, "http://example.com").Code; got != http.StatusConflict {
		t.Fatal(got)
	}
	// Listing and using other VMs is independent of a slow guest build.
	if got := request("GET", app.Token, "").Code; got != 200 {
		t.Fatal(got)
	}
	close(workspace.proceed)
	if got := <-done; got != 201 {
		t.Fatal(got)
	}
	if len(workspace.VMs()) != 3 {
		t.Fatal("created VM missing")
	}
}

func TestWorkspaceControllersAreIndependent(t *testing.T) {
	workspace := &workspaceStub{vms: []vmm.DisplayVM{{ID: "1", Name: "first", Display: displayStub{}}, {ID: "2", Name: "second", Display: displayStub{}}}}
	app, _ := NewWorkspace(workspace)
	server := httptest.NewServer(app)
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	connect := func(id string, want int) net.Conn {
		t.Helper()
		conn, err := net.Dial("tcp", host)
		if err != nil {
			t.Fatal(err)
		}
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "GET /rfb?token=%s&vm=%s HTTP/1.1\r\nHost: %s\r\nOrigin: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", app.Token, id, host, server.URL)
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil || !strings.Contains(line, fmt.Sprint(want)) {
			conn.Close()
			t.Fatalf("VM %s: %q %v", id, line, err)
		}
		return conn
	}
	first := connect("1", 101)
	defer first.Close()
	second := connect("2", 101)
	defer second.Close()
	duplicate := connect("1", 409)
	duplicate.Close()
	missing := connect("missing", 404)
	missing.Close()
}
