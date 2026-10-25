package native

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.starlark.net/starlark"
)

func testCA(t *testing.T) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return der, cert, key
}

func TestHTTPExplicitTLSRoots(t *testing.T) {
	root, ca, key := testCA(t)
	other, _, _ := testCA(t)
	for _, tc := range []struct {
		name               string
		wrongName, expired bool
	}{
		{name: "valid"}, {name: "wrong_hostname", wrongName: true}, {name: "expired", expired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, leafKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Server"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
			if tc.wrongName {
				template.IPAddresses = nil
				template.DNSNames = []string{"wrong.invalid"}
			}
			if tc.expired {
				template.NotBefore = time.Now().Add(-2 * time.Hour)
				template.NotAfter = time.Now().Add(-time.Hour)
			}
			leaf, err := x509.CreateCertificate(rand.Reader, template, ca, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte("{}")) }))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: leafKey}}}
			server.StartTLS()
			defer server.Close()
			for _, encoding := range []string{"der", "pem"} {
				data := root
				if encoding == "pem" {
					data = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root})
				}
				client, err := httpClientWithRoots(starlark.Tuple{starlark.Bytes(data)})
				if err != nil {
					t.Fatal(err)
				}
				_, err = HTTPPostJSON(context.Background(), client, server.URL, []byte("{}"), 64)
				client.CloseIdleConnections()
				if tc.expired || tc.wrongName {
					if err == nil || !strings.Contains(err.Error(), "certificate") {
						t.Fatalf("verification bypassed: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			// The explicit root must neither affect default clients nor authorize an
			// unrelated root. Invalid TLS must fail before any HTTP request is sent.
			before := calls.Load()
			for _, roots := range []starlark.Value{starlark.None, starlark.Tuple{starlark.Bytes(other)}} {
				client, err := httpClientWithRoots(roots)
				if err != nil {
					t.Fatal(err)
				}
				_, err = HTTPPostJSON(context.Background(), client, server.URL, []byte("{}"), 64)
				client.CloseIdleConnections()
				if err == nil {
					t.Fatal("untrusted root accepted")
				}
			}
			if calls.Load() != before {
				t.Fatal("HTTP sent after failed TLS")
			}
			if _, err := httpClientWithRoots(starlark.Tuple{starlark.Bytes(leaf)}); err == nil {
				t.Fatal("accepted leaf as CA")
			}
		})
	}
	for _, roots := range []starlark.Value{starlark.Tuple{}, starlark.Tuple{starlark.Bytes("invalid")}, starlark.MakeInt(42)} {
		if _, err := httpClientWithRoots(roots); err == nil {
			t.Fatal("accepted invalid roots")
		}
	}
}
