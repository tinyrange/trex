// Package native provides the native HTTP backend for the portable Windows
// Update protocol package.
package native

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

const defaultMaximumResponse = 64 << 20

const (
	microsoftDialAddressTimeout = 3 * time.Second
	microsoftDialCacheEntries   = 64
)

const microsoftUpdateRootSHA1 = "8f43288ad272f3103b6fb1428485ea3014c0bcfe"
const microsoftUpdateECCRootSHA1 = "06f1aa330b927b753a40e68cdf22e34bcbef3352"

// Microsoft Update uses a dedicated public root which is present in Windows'
// trusted root program but is not included by every non-Windows system trust
// store. Keep the endpoint fully verified by adding that one pinned root to the
// host roots. Certificate and fingerprint source:
// https://www.microsoft.com/pkiops/docs/repository.htm
const microsoftUpdateRootPEM = `-----BEGIN CERTIFICATE-----
MIIF7TCCA9WgAwIBAgIQP4vItfyfspZDtWnWbELhRDANBgkqhkiG9w0BAQsFADCB
iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEw
MzIyMjIwNTI4WhcNMzYwMzIyMjIxMzA0WjCBiDELMAkGA1UEBhMCVVMxEzARBgNV
BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
aWNhdGUgQXV0aG9yaXR5IDIwMTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQCygEGqNThNE3IyaCJNuLLx/9VSvGzH9dJKjDbu0cJcfoyKrq8TKG/Ac+M6
ztAlqFo6be+ouFmrEyNozQwph9FvgFyPRH9dkAFSWKxRxV8qh9zc2AodwQO5e7BW
6KPeZGHCnvjzfLnsDbVU/ky2ZU+I8JxImQxCCwl8MVkXeQZ4KI2JOkwDJb5xalwL
54RgpJki49KvhKSn+9GY7Qyp3pSJ4Q6g3MDOmT3qCFK7VnnkH4S6Hri0xElcTzFL
h93dBWcmmYDgcRGjuKVB4qRTufcyKYMME782XgSzS0NHL2vikR7TmE/dQgfI6B0S
/Jmpaz6SfsjWaTr8ZL22CZ3K/QwLopt3YEsDlKQwaRLWQi3BQUzK3Kr9j1uDRprZ
/LHR47PJf0h6zSTwQY9cdNCssBAgBkm3xy0hyFfj0IbzA2j70M5xwYmZSmQBbP3s
MJHPQTySx+W6hh1hhMdfgzlirrSSL0fzC/hV66AfWdC7dJse0Hbm8ukG1xDo+mTe
acY1logC8Ea4PyeZb8txiSk190gWAjWP1Xl8TQLPX+uKg09FcYj5qQ1OcunCnAfP
SRtOBA5jUYxe2ADBVSy2xuDCZU7JNDn1nLPEfuhhbhNfFcRf2X7tHc7uROzLLoax
7Dj2cO2rXBPB2Q8Nx4CyVe0096yb5MPa50c8prWPMd/FS6/r8QIDAQABo1EwTzAL
BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUci06AjGQQ7kU
BU7h6qfHMdEjiTQwEAYJKwYBBAGCNxUBBAMCAQAwDQYJKoZIhvcNAQELBQADggIB
AH9yzw+3xRXbm8BJyiZb/p4T5tPw0tuXX/JLP02zrhmu7deXoKzvqTqjwkGw5biR
nhOBJAPmCf0/V0A5ISRW0RAvS0CpNoZLtFNXmvvxfomPEf4YbFGq6O0JlbXlccmh
6Yd1phV/yX43VF50k8XDZ8wNT2uoFwxtCJJ+i92Bqi1wIcM9BhS7vyRep4TXPw8h
Ir1LAAbblxzYXtTFC1yHblCk6MM4pPvLLMWSZpuFXst6bJN8gClYW1e1QGm6CHmm
ZGIVnYeWRbVmIyADixxzoNOieTPgUFmG2y/lAiXqcyqfABTINseSO+lOAOzYVgm5
M0kS0lQLAausR7aRKX1MtHWAUgHoyoL2n8ysnI8X6i8msKtyrAv+nlEex0NVZ09R
s1fWtuzuUrc66U7h14GIvE+OdbtLqPA1qibUZ2dJsnBMO5PcHd94kIZysjik0dyS
TclY6ysSXNQ7roxrsIPlAT/4CTL2kzU0Iq/dNw13CYArzUgA8YyZGUcFAenRv9FO
0OYoQzeZpApKCNmacXPSqs0xE2N2oTdvkjgefRI8ZjLny23h/FKJ3crWZgWalmG+
oijHHKOnNlA8OqTfSm7mhzvO6/DggTedEzxSjr25HTTGHdUKaj2YKXCMiSrRq4IQ
SB/c9O+lxbtVGjhjhE63bK2VVOxlIhBJF7jAHscPrFRH
-----END CERTIFICATE-----`

const microsoftUpdateECCRootPEM = `-----BEGIN CERTIFICATE-----
MIIDIzCCAqigAwIBAgIQFJgmZtx8zY9AU2d7uZnshTAKBggqhkjOPQQDAzCBlDEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE+MDwGA1UEAxM1TWlj
cm9zb2Z0IEVDQyBQcm9kdWN0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIw
MTgwHhcNMTgwMjI3MjA0MjA4WhcNNDMwMjI3MjA1MDQ2WjCBlDELMAkGA1UEBhMC
VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjE+MDwGA1UEAxM1TWljcm9zb2Z0IEVD
QyBQcm9kdWN0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTgwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAATHERYqdh1Wjr65YmXUw8608MMw7I9t1245vMhJq6u4
40N41YEGXe/HfZ/O1rOQdd4MsJDeI7rI0T5n4BmpG4YxHl80Le4X/RX7fieKMqHq
yY/JfhjLLzssSHp9pvQBB6yjgbwwgbkwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB
/wQFMAMBAf8wHQYDVR0OBBYEFEPvcIe4nb/siBncxsRrdQ11NDMIMBAGCSsGAQQB
gjcVAQQDAgEAMGUGA1UdIAReMFwwBgYEVR0gADBSBgwrBgEEAYI3TIN9AQEwQjBA
BggrBgEFBQcCARY0aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2Nz
L1JlcG9zaXRvcnkuaHRtADAKBggqhkjOPQQDAwNpADBmAjEAocBJRF0yVSfMPpBu
JSKdJFubUTXHkUlJKqP5b08czd2c4bVXyZ7CIkWbBhVwHEW/AjEAxdMo63LHPrCs
Jwl/Yj1geeWS8UUquaUC5GC7/nornGCntZkU8rC+8LsFllZWj8Fo
-----END CERTIFICATE-----`

// Transport sends requests through net/http. Client may be replaced by tests
// or applications that require custom proxy and TLS policy.
type Transport struct {
	Client          *http.Client
	MaximumResponse int64
}

func (t Transport) Do(ctx context.Context, request windowsupdate.Request) (windowsupdate.Response, error) {
	endpoint, err := endpointURL(request.Endpoint)
	if err != nil {
		return windowsupdate.Response{}, err
	}
	client := t.Client
	if client == nil {
		client, err = microsoftUpdateHTTPClient()
		if err != nil {
			return windowsupdate.Response{}, err
		}
	}
	maximum := t.MaximumResponse
	if maximum == 0 {
		maximum = defaultMaximumResponse
	}
	if maximum <= 0 {
		return windowsupdate.Response{}, fmt.Errorf("windows update HTTP maximum response must be positive")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(request.Body))
	if err != nil {
		return windowsupdate.Response{}, fmt.Errorf("create request: %w", err)
	}
	httpRequest.Header.Set("Content-Type", "application/soap+xml; charset=utf-8")
	httpRequest.Header.Set("User-Agent", request.UserAgent)
	httpRequest.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(httpRequest)
	if err != nil {
		return windowsupdate.Response{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return windowsupdate.Response{}, fmt.Errorf("read response: %w", err)
	}
	if int64(len(body)) > maximum {
		return windowsupdate.Response{}, fmt.Errorf("response exceeds %d-byte limit", maximum)
	}
	return windowsupdate.Response{StatusCode: response.StatusCode, Body: body}, nil
}

func microsoftUpdateHTTPClient() (*http.Client, error) {
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	for _, root := range []struct {
		name        string
		pem         string
		fingerprint string
	}{
		{"Microsoft Update Root CA 2011", microsoftUpdateRootPEM, microsoftUpdateRootSHA1},
		{"Microsoft ECC Product Root CA 2018", microsoftUpdateECCRootPEM, microsoftUpdateECCRootSHA1},
	} {
		certificate, err := parsePinnedRoot(root.name, root.pem, root.fingerprint)
		if err != nil {
			return nil, err
		}
		roots.AddCert(certificate)
	}
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := newResolvedAddressDialer()
	httpTransport.DialContext = dialer.DialContext
	httpTransport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
	}
	return &http.Client{Transport: httpTransport}, nil
}

type resolvedAddressDialer struct {
	mu        sync.Mutex
	preferred map[string]string
	lookup    func(context.Context, string) ([]net.IPAddr, error)
	dial      func(context.Context, string, string) (net.Conn, error)
}

func newResolvedAddressDialer() *resolvedAddressDialer {
	native := &net.Dialer{Timeout: microsoftDialAddressTimeout, KeepAlive: 30 * time.Second}
	return &resolvedAddressDialer{
		preferred: make(map[string]string),
		lookup:    net.DefaultResolver.LookupIPAddr,
		dial:      native.DialContext,
	}
}

// DialContext tries every address returned for one host. net.Dialer's fallback
// races address families but may stop at the first address within one family;
// Microsoft CDN names commonly return multiple IPv4 edges with independent
// reachability. A successful edge is retained only in this client's bounded
// in-memory preference map.
func (d *resolvedAddressDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) != nil {
		return d.dial(ctx, network, address)
	}
	addresses, lookupErr := d.lookup(ctx, host)
	if lookupErr != nil || len(addresses) == 0 {
		return d.dial(ctx, network, address)
	}
	d.mu.Lock()
	preferred := d.preferred[host]
	d.mu.Unlock()
	ordered := make([]string, 0, len(addresses))
	if preferred != "" {
		ordered = append(ordered, net.JoinHostPort(preferred, port))
	}
	for _, candidate := range addresses {
		if network == "tcp4" && candidate.IP.To4() == nil {
			continue
		}
		if network == "tcp6" && candidate.IP.To4() != nil {
			continue
		}
		candidateIP := candidate.IP.String()
		if candidateIP == "" || candidateIP == preferred {
			continue
		}
		ordered = append(ordered, net.JoinHostPort(candidateIP, port))
	}
	var failures []error
	for _, candidate := range ordered {
		attemptContext, cancel := context.WithTimeout(ctx, microsoftDialAddressTimeout)
		connection, dialErr := d.dial(attemptContext, network, candidate)
		cancel()
		if dialErr == nil {
			candidateHost, _, _ := net.SplitHostPort(candidate)
			d.remember(host, candidateHost)
			return connection, nil
		}
		failures = append(failures, fmt.Errorf("%s: %w", candidate, dialErr))
		if ctx.Err() != nil {
			break
		}
	}
	if len(failures) == 0 {
		return d.dial(ctx, network, address)
	}
	return nil, fmt.Errorf("dial %s through %d resolved address(es): %w", address, len(failures), errors.Join(failures...))
}

func (d *resolvedAddressDialer) remember(host, address string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.preferred) >= microsoftDialCacheEntries {
		clear(d.preferred)
	}
	d.preferred[host] = address
}

func parsePinnedRoot(name, certificatePEM, expectedSHA1 string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return nil, fmt.Errorf("decode pinned %s certificate", name)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pinned %s certificate: %w", name, err)
	}
	fingerprint := sha1.Sum(certificate.Raw)
	if hex.EncodeToString(fingerprint[:]) != expectedSHA1 {
		return nil, fmt.Errorf("pinned %s certificate fingerprint mismatch", name)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return nil, fmt.Errorf("verify pinned %s certificate: %w", name, err)
	}
	return certificate, nil
}

func endpointURL(endpoint windowsupdate.Endpoint) (string, error) {
	switch endpoint {
	case windowsupdate.Client:
		return "https://fe3.delivery.mp.microsoft.com/ClientWebService/client.asmx", nil
	case windowsupdate.ClientSecured:
		return "https://fe3cr.delivery.mp.microsoft.com/ClientWebService/client.asmx/secured", nil
	default:
		return "", fmt.Errorf("unknown Windows Update endpoint %d", endpoint)
	}
}
