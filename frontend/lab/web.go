package labfrontend

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tinyrange/trex/lab"
	"golang.org/x/net/html"
)

const maxGuestHTML = 8 << 20

func webPrefix(r *http.Request, s lab.Surface) string {
	return "/api/nodes/" + url.PathEscape(r.PathValue("id")) + "/surfaces/" +
		url.PathEscape(r.PathValue("surface")) + "/browse/" + s.Web.Key + "/"
}

func usableWebSurface(s *lab.WebSurface) bool {
	return s != nil && s.Transport != nil && s.Key != "" && s.Host != ""
}

func (a httpApp) openWeb(w http.ResponseWriter, r *http.Request, s lab.Surface) {
	if !usableWebSurface(s.Web) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, webPrefix(r, s), http.StatusTemporaryRedirect)
}

func (a httpApp) webSession(w http.ResponseWriter, r *http.Request, s lab.Surface) {
	if !usableWebSurface(s.Web) {
		http.NotFound(w, r)
		return
	}
	address := url.URL{Scheme: "http", Host: s.Web.Host, Path: "/"}
	if ip := a.manager.NodeAddress(r.PathValue("id")); ip != "" {
		address.Host = ip
		if port := (&url.URL{Host: s.Web.Host}).Port(); port != "" {
			address.Host += ":" + port
		}
	}
	reply(w, struct {
		Base    string `json:"base"`
		Address string `json:"address"`
	}{webPrefix(r, s), address.String()})
}

func (a httpApp) browseWeb(w http.ResponseWriter, r *http.Request, s lab.Surface) {
	if !usableWebSurface(s.Web) ||
		subtle.ConstantTimeCompare([]byte(r.PathValue("key")), []byte(s.Web.Key)) != 1 {
		http.NotFound(w, r)
		return
	}
	origin := "http://" + a.localHost
	if r.Host == a.tailnetHost {
		origin = "https://" + a.tailnetHost
	}
	if given := r.Header.Get("Origin"); given != "" && given != "null" && given != origin {
		http.Error(w, "Open the website from the lab editor.", http.StatusForbidden)
		return
	}
	prefix := webPrefix(r, s)
	rawPath, ok := strings.CutPrefix(r.URL.EscapedPath(), strings.TrimSuffix(prefix, "/"))
	if !ok || !strings.HasPrefix(rawPath, "/") {
		http.NotFound(w, r)
		return
	}
	path, err := url.PathUnescape(rawPath)
	if err != nil {
		http.Error(w, "Invalid website path.", http.StatusBadRequest)
		return
	}
	target := url.URL{Scheme: "http", Host: s.Web.Host, Path: path, RawPath: rawPath, RawQuery: r.URL.RawQuery}

	// The opaque-origin iframe can load resources and submit forms to its
	// own unguessable runtime URL. These headers also sandbox direct visits.
	source := origin + prefix
	h := w.Header()
	h.Set("Content-Security-Policy", "sandbox allow-scripts allow-forms; default-src 'none'; "+
		"frame-ancestors "+origin+"; base-uri 'none'; form-action "+source+"; "+
		"script-src 'unsafe-inline' "+source+"; style-src 'unsafe-inline' "+source+"; "+
		"img-src data: blob: "+source+"; font-src data: "+source+"; media-src "+source+"; connect-src "+source)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("Access-Control-Allow-Origin", "null")
	h.Set("Access-Control-Allow-Methods", lab.WebMethods)
	h.Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !lab.WebAllowsMethod(r.Method) {
		w.Header().Set("Allow", lab.WebMethods)
		http.Error(w, "Unsupported website method.", http.StatusMethodNotAllowed)
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	proxy := httputil.ReverseProxy{
		Transport: s.Web.Transport,
		Rewrite: func(p *httputil.ProxyRequest) {
			p.Out.URL = &target
			p.Out.Host = target.Host
			p.Out.Header = copyWebHeaders(p.Out.Header, []string{"Accept", "Accept-Language", "Content-Type", "Range"})
			p.Out.Header.Set("Accept-Encoding", "identity")
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header = copyWebHeaders(resp.Header, []string{"Content-Type", "Content-Encoding", "Content-Length", "Accept-Ranges", "Content-Range", "Location"})
			if location := resp.Header.Get("Location"); location != "" {
				local, ok := localWebURL(&target, prefix, location)
				if !ok {
					return fmt.Errorf("guest redirected outside the website")
				}
				resp.Header.Set("Location", local)
			}
			mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
			if r.Method != http.MethodHead && mediaType == "text/html" && resp.ContentLength != 0 {
				if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
					return fmt.Errorf("compressed guest HTML")
				}
				data, err := io.ReadAll(io.LimitReader(resp.Body, maxGuestHTML+1))
				if err != nil {
					return err
				}
				if len(data) > maxGuestHTML {
					return fmt.Errorf("guest HTML exceeds size limit")
				}
				content, err := rewriteWebHTML(data, &target, prefix)
				if err != nil {
					return err
				}
				resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(content))
				resp.ContentLength = int64(len(content))
				resp.Header.Set("Content-Length", strconv.Itoa(len(content)))
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "The website is unavailable. Reload when its HTTP service is ready.", http.StatusBadGateway)
		},
	}
	proxy.ServeHTTP(w, r.WithContext(ctx))
}

func copyWebHeaders(from http.Header, names []string) http.Header {
	to := make(http.Header, len(names))
	for _, name := range names {
		for _, value := range from.Values(name) {
			to.Add(name, value)
		}
	}
	return to
}

func localWebURL(base *url.URL, prefix, value string) (string, bool) {
	ref, err := url.Parse(strings.TrimSpace(value))
	if err != nil || strings.Contains(value, "\\") {
		return "", false
	}
	if ref.Fragment != "" && ref.Path == "" && ref.Host == "" && ref.Scheme == "" && ref.RawQuery == "" {
		return ref.String(), true
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme != base.Scheme || resolved.Host != base.Host || resolved.User != nil {
		return "", false
	}
	return strings.TrimSuffix(prefix, "/") + resolved.RequestURI() + (&url.URL{Fragment: resolved.Fragment}).String(), true
}

func rewriteWebHTML(data []byte, base *url.URL, prefix string) ([]byte, error) {
	var out bytes.Buffer
	tokens := html.NewTokenizer(bytes.NewReader(data))
	bridge := false
	for {
		kind := tokens.Next()
		switch kind {
		case html.ErrorToken:
			if tokens.Err() == io.EOF {
				if !bridge {
					writeWebBridge(&out, prefix)
				}
				return out.Bytes(), nil
			}
			return nil, tokens.Err()
		case html.StartTagToken, html.SelfClosingTagToken:
			raw := bytes.Clone(tokens.Raw())
			tag := tokens.Token()
			if !bridge && tag.Data != "html" {
				bridge = true
				if tag.Data == "head" {
					out.Write(raw)
					writeWebBridge(&out, prefix)
					continue
				}
				writeWebBridge(&out, prefix)
			}
			if tag.Data == "base" || tag.Data == "meta" && isWebRefresh(tag.Attr) {
				continue
			}
			changed := false
			for i, attr := range tag.Attr {
				switch attr.Key {
				case "href", "src", "action", "formaction", "poster", "data":
					if attr.Val != "" && !strings.HasPrefix(attr.Val, "data:") && !strings.HasPrefix(attr.Val, "#") {
						changed = true
						tag.Attr[i].Val = "#"
						if next, ok := localWebURL(base, prefix, attr.Val); ok {
							tag.Attr[i].Val = next
						}
					}
				}
			}
			if changed {
				out.WriteString(tag.String())
			} else {
				out.Write(raw)
			}
		default:
			out.Write(tokens.Raw())
		}
	}
}

// The parent uses these advisory messages to track navigation in the opaque frame.
func writeWebBridge(out *bytes.Buffer, prefix string) {
	scope, _ := json.Marshal(prefix)
	out.WriteString(`<script>(() => {
  if (window === parent) return;
  const scope = `)
	out.Write(scope)
	out.WriteString(`;
  const report = (type, url) => {
    if (url.origin !== location.origin || !url.pathname.startsWith(scope)) return;
    const path = url.pathname.slice(scope.length - 1) + url.search + url.hash;
    parent.postMessage({type, path}, url.origin);
  };
  const update = () => report("lab-web-location", location);
  addEventListener("pageshow", update);
  addEventListener("hashchange", update);
  window.navigation?.addEventListener("currententrychange", update);
  addEventListener("click", event => {
    if (event.defaultPrevented || event.button !== 0 || event.altKey || event.metaKey || event.ctrlKey || event.shiftKey) return;
    const link = event.target.closest?.("a[href]");
    const target = link?.getAttribute("target")?.toLowerCase();
    if (!link || link.hasAttribute("download") || (target && target !== "_self")) return;
    try { report("lab-web-navigation", new URL(link.getAttribute("href"), location.href)); } catch {}
  });
})();</script>`)
}

func isWebRefresh(attributes []html.Attribute) bool {
	for _, attr := range attributes {
		if attr.Key == "http-equiv" && strings.EqualFold(strings.TrimSpace(attr.Val), "refresh") {
			return true
		}
	}
	return false
}
