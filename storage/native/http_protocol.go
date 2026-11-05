package native

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

// Pin HTTP/1.1 on a private transport. Trust, hostname verification, proxy
// policy and the requested host remain unchanged. No fallback or retry occurs
// at this layer, and the caller must close the cloned transport's idle pool.
func httpClientVersion(client *http.Client, version string) (*http.Client, error) {
	if version == "auto" {
		return client, nil
	}
	if version != "1.1" {
		return nil, fmt.Errorf("http_post_json: http_version must be auto or 1.1")
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("http_post_json: transport cannot pin HTTP version")
	}
	cloned := transport.Clone()
	cloned.ForceAttemptHTTP2 = false
	cloned.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	if cloned.TLSClientConfig == nil {
		cloned.TLSClientConfig = &tls.Config{}
	} else {
		cloned.TLSClientConfig = cloned.TLSClientConfig.Clone()
	}
	cloned.TLSClientConfig.NextProtos = []string{"http/1.1"}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	cloned.Protocols = protocols
	result := *client
	result.Transport = cloned
	return &result, nil
}
