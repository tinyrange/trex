package star

import (
	"archive/zip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	starvalue "github.com/tinyrange/trex/script/value"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func Builtins() starlark.StringDict {
	return starlark.StringDict{
		"file":     starlark.NewBuiltin("file", webFileBuiltin),
		"redirect": starlark.NewBuiltin("redirect", webRedirectBuiltin),
		"response": starlark.NewBuiltin("response", webResponseBuiltin),
		"zip":      starlark.NewBuiltin("zip", webZIPBuiltin),
	}
}

type starlarkWebResponse struct {
	kind       string
	status     int
	headers    map[string]string
	body       starlark.Value
	file       starfile.File
	name       string
	filesystem starlark.Mapping
	path       string
}

func (r *starlarkWebResponse) String() string {
	return fmt.Sprintf("<web.response %d %s>", r.status, r.kind)
}
func (r *starlarkWebResponse) Type() string         { return "web.response" }
func (r *starlarkWebResponse) Freeze()              {}
func (r *starlarkWebResponse) Truth() starlark.Bool { return starlark.True }
func (r *starlarkWebResponse) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable: %s", r.Type())
}

func webResponseBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	body := starlark.Value(starlark.String(""))
	status := http.StatusOK
	var headers *starlark.Dict
	if err := starlark.UnpackArgs("web.response", args, kwargs, "body?", &body, "status?", &status, "headers?", &headers); err != nil {
		return nil, err
	}
	if status < 100 || status > 999 {
		return nil, fmt.Errorf("web.response: invalid HTTP status %d", status)
	}
	nativeHeaders, err := starlarkWebHeaders(headers)
	if err != nil {
		return nil, fmt.Errorf("web.response: %w", err)
	}
	if _, ok := body.(starfile.File); !ok {
		if _, err := starfile.BytesForValue(body, int64(^uint64(0)>>1)); err != nil {
			return nil, fmt.Errorf("web.response: body got %s, want string, bytes, or file", body.Type())
		}
	}
	return &starlarkWebResponse{kind: "body", status: status, headers: nativeHeaders, body: body}, nil
}

func webFileBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var file starfile.File
	name := "download"
	status := http.StatusOK
	var headers *starlark.Dict
	if err := starlark.UnpackArgs("web.file", args, kwargs, "file", &file, "name?", &name, "status?", &status, "headers?", &headers); err != nil {
		return nil, err
	}
	nativeHeaders, err := starlarkWebHeaders(headers)
	if err != nil {
		return nil, fmt.Errorf("web.file: %w", err)
	}
	return &starlarkWebResponse{kind: "file", status: status, headers: nativeHeaders, file: file, name: name}, nil
}

func webRedirectBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var location string
	status := http.StatusSeeOther
	if err := starlark.UnpackArgs("web.redirect", args, kwargs, "location", &location, "status?", &status); err != nil {
		return nil, err
	}
	return &starlarkWebResponse{kind: "redirect", status: status, headers: map[string]string{"Location": location}}, nil
}

func webZIPBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var filesystem starlark.Mapping
	var directory string
	name := "download.zip"
	if err := starlark.UnpackArgs("web.zip", args, kwargs, "filesystem", &filesystem, "path", &directory, "name?", &name); err != nil {
		return nil, err
	}
	return &starlarkWebResponse{kind: "zip", status: http.StatusOK, filesystem: filesystem, path: directory, name: name}, nil
}

func starlarkWebHeaders(headers *starlark.Dict) (map[string]string, error) {
	result := make(map[string]string)
	if headers == nil {
		return result, nil
	}
	for _, item := range headers.Items() {
		name, ok := starlark.AsString(item[0])
		if !ok {
			return nil, fmt.Errorf("header name got %s, want string", item[0].Type())
		}
		value, ok := starlark.AsString(item[1])
		if !ok {
			return nil, fmt.Errorf("header %q got %s, want string", name, item[1].Type())
		}
		result[name] = value
	}
	return result, nil
}

type Application struct {
	mu      sync.Mutex
	thread  *starlark.Thread
	handler starlark.Callable
}

func NewApplication(thread *starlark.Thread, handler starlark.Callable) *Application {
	return &Application{thread: thread, handler: handler}
}

func (a *Application) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	value, err := starlarkWebRequest(request)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	result, err := starlark.Call(a.thread, a.handler, starlark.Tuple{value}, nil)
	a.mu.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error handling web request: %v\n", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	response, err := normalizeStarlarkWebResponse(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeStarlarkWebResponse(w, request, response)
}

func starlarkWebRequest(request *http.Request) (starlark.Value, error) {
	body, err := io.ReadAll(io.LimitReader(request.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	query := starlark.NewDict(len(request.URL.Query()))
	for name, values := range request.URL.Query() {
		value := ""
		if len(values) > 0 {
			value = values[0]
		}
		_ = query.SetKey(starlark.String(name), starlark.String(value))
	}
	headers := starlark.NewDict(len(request.Header))
	for name, values := range request.Header {
		_ = headers.SetKey(starlark.String(strings.ToLower(name)), starlark.String(strings.Join(values, ", ")))
	}
	cookies := starlark.NewDict(len(request.Cookies()))
	for _, cookie := range request.Cookies() {
		_ = cookies.SetKey(starlark.String(cookie.Name), starlark.String(cookie.Value))
	}
	return starvalue.NewRecord(starlark.StringDict{
		"body":      starlark.Bytes(body),
		"cookies":   cookies,
		"headers":   headers,
		"host":      starlark.String(request.Host),
		"method":    starlark.String(request.Method),
		"path":      starlark.String(request.URL.Path),
		"query":     query,
		"raw_query": starlark.String(request.URL.RawQuery),
	}), nil
}

func normalizeStarlarkWebResponse(value starlark.Value) (*starlarkWebResponse, error) {
	if response, ok := value.(*starlarkWebResponse); ok {
		return response, nil
	}
	if value == starlark.None {
		return &starlarkWebResponse{kind: "body", status: http.StatusNoContent, headers: map[string]string{}, body: starlark.String("")}, nil
	}
	if _, ok := value.(starfile.File); ok {
		file := value.(starfile.File)
		return &starlarkWebResponse{kind: "file", status: http.StatusOK, headers: map[string]string{}, file: file, name: "download"}, nil
	}
	if _, err := starfile.BytesForValue(value, int64(^uint64(0)>>1)); err == nil {
		return &starlarkWebResponse{kind: "body", status: http.StatusOK, headers: map[string]string{}, body: value}, nil
	}
	return nil, fmt.Errorf("web handler returned %s, want response, string, bytes, file, or None", value.Type())
}

func writeStarlarkWebResponse(w http.ResponseWriter, request *http.Request, response *starlarkWebResponse) {
	for name, value := range response.headers {
		w.Header().Set(name, value)
	}
	switch response.kind {
	case "redirect":
		http.Redirect(w, request, response.headers["Location"], response.status)
	case "file":
		if w.Header().Get("Content-Type") == "" {
			if contentType := mime.TypeByExtension(path.Ext(response.name)); contentType != "" {
				w.Header().Set("Content-Type", contentType)
			}
		}
		if response.status != http.StatusOK {
			w.WriteHeader(response.status)
			_, _ = io.Copy(w, io.NewSectionReader(response.file, 0, response.file.Size()))
			return
		}
		http.ServeContent(w, request, path.Base(response.name), time.Time{}, io.NewSectionReader(response.file, 0, response.file.Size()))
	case "zip":
		serveStarlarkFilesystemZIP(w, response)
	default:
		data, err := starfile.BytesForValue(response.body, int64(^uint64(0)>>1))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(response.status)
		_, _ = w.Write(data)
	}
}

func serveStarlarkFilesystemZIP(w http.ResponseWriter, response *starlarkWebResponse) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", response.name))
	err := WriteZIP(w, response.filesystem, response.path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error streaming ZIP %s: %v\n", response.name, err)
	}
}

// WriteZIP streams a filesystem directory as a ZIP archive without staging
// files on the host.
func WriteZIP(output io.Writer, filesystem starlark.Mapping, directory string) error {
	archive := zip.NewWriter(output)
	err := writeStarlarkZIPDirectory(archive, filesystem, path.Clean("/"+strings.TrimPrefix(directory, "/")), "", make(map[string]bool))
	if closeErr := archive.Close(); err == nil {
		err = closeErr
	}
	return err
}

func writeStarlarkZIPDirectory(archive *zip.Writer, filesystem starlark.Mapping, directory, prefix string, visited map[string]bool) error {
	key := strings.ToLower(directory)
	if visited[key] {
		return fmt.Errorf("directory cycle at %s", directory)
	}
	visited[key] = true
	defer delete(visited, key)
	value, found, err := filesystem.Get(starlark.String(directory))
	if err != nil || !found {
		if err == nil {
			err = fmt.Errorf("directory not found: %s", directory)
		}
		return err
	}
	directoryValue, ok := value.(starlark.HasAttrs)
	if !ok {
		return fmt.Errorf("%s is not a directory", directory)
	}
	filesValue, err := directoryValue.Attr("files")
	if err != nil {
		return err
	}
	iterable, ok := filesValue.(starlark.Iterable)
	if !ok {
		return fmt.Errorf("%s.files is not iterable", directory)
	}
	var names []string
	iterator := iterable.Iterate()
	defer iterator.Done()
	var item starlark.Value
	for iterator.Next(&item) {
		name, ok := starlark.AsString(item)
		if !ok {
			return fmt.Errorf("directory entry got %s, want string", item.Type())
		}
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return strings.ToLower(names[i]) < strings.ToLower(names[j]) })
	for _, name := range names {
		child, found, err := filesystem.Get(starlark.String(name))
		if err != nil || !found {
			if err == nil {
				err = fmt.Errorf("directory entry not found: %s", name)
			}
			return err
		}
		archiveName := path.Join(prefix, path.Base(name))
		if file, ok := child.(starfile.File); ok {
			writer, err := archive.CreateHeader(&zip.FileHeader{Name: archiveName, Method: zip.Deflate})
			if err != nil {
				return err
			}
			if _, err := io.Copy(writer, io.NewSectionReader(file, 0, file.Size())); err != nil {
				return err
			}
			continue
		}
		if _, err := archive.CreateHeader(&zip.FileHeader{Name: archiveName + "/", Method: zip.Store}); err != nil {
			return err
		}
		if err := writeStarlarkZIPDirectory(archive, filesystem, name, archiveName, visited); err != nil {
			return err
		}
	}
	return nil
}
