package windows

import (
	"fmt"
	starfile "github.com/tinyrange/trex/storage/star"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"go.starlark.net/starlark"
)

var symbolServerAtom = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

func windowsSymbolServerBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var baseURL, name, key string
	var guidValue, ageValue starlark.Value = starlark.None, starlark.None
	maximum := int64(256 << 20)
	timeout := starlarkNumber(45)
	if err := starlark.UnpackArgs("symbol_server", args, kwargs,
		"base_url", &baseURL, "name", &name, "key", &key,
		"guid?", &guidValue, "age?", &ageValue, "maximum?", &maximum, "timeout?", &timeout,
	); err != nil {
		return nil, err
	}
	base, err := url.Parse(baseURL)
	if err != nil || base.Scheme != "https" && base.Scheme != "http" || base.Host == "" {
		return nil, fmt.Errorf("symbol_server: base_url must be an absolute HTTP(S) URL")
	}
	if !symbolServerAtom.MatchString(name) || !symbolServerAtom.MatchString(key) || strings.Contains(name, "..") || strings.Contains(key, "..") {
		return nil, fmt.Errorf("symbol_server: invalid name or key")
	}
	if maximum <= 0 || maximum > 1<<30 || timeout <= 0 || timeout > 3600 {
		return nil, fmt.Errorf("symbol_server: invalid maximum or timeout")
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + url.PathEscape(name) + "/" + url.PathEscape(key) + "/" + url.PathEscape(name)
	request, err := http.NewRequest(http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: time.Duration(float64(timeout) * float64(time.Second))}
	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("symbol_server: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("symbol_server: server returned %s", response.Status)
	}
	if response.ContentLength > maximum {
		return nil, fmt.Errorf("symbol_server: response exceeds %d bytes", maximum)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("symbol_server: read response: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("symbol_server: response exceeds %d bytes", maximum)
	}
	file := &starfile.Bytes{Name: name, Data: data}
	if guidValue != starlark.None || ageValue != starlark.None {
		parsed, err := parsePDB(file, min(maximum, int64(pdbDefaultStreamLimit)))
		if err != nil {
			return nil, fmt.Errorf("symbol_server: validate PDB: %w", err)
		}
		if guidValue != starlark.None {
			guid, ok := starlark.AsString(guidValue)
			if !ok {
				return nil, fmt.Errorf("symbol_server: guid must be string")
			}
			guid = strings.ToUpper(strings.Trim(guid, "{}"))
			if guid != parsed.guid {
				return nil, fmt.Errorf("symbol_server: PDB GUID %s does not match %s", parsed.guid, guid)
			}
		}
		if ageValue != starlark.None {
			var age uint64
			if err := starlark.AsInt(ageValue, &age); err != nil || age > ^uint64(uint32(0)) {
				return nil, fmt.Errorf("symbol_server: age must be a 32-bit integer")
			}
			if uint32(age) != parsed.age {
				return nil, fmt.Errorf("symbol_server: PDB age %d does not match %d", parsed.age, age)
			}
		}
	}
	return file, nil
}
