package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	windowsupdate "github.com/tinyrange/trex/windows/update"
)

const maximumCatalogSource = 128 << 20

// Only raw received SOAP bodies and transport framing persist, never a parsed
// Catalog, selected offer, constructed image, or expiring download location.
type catalogExchange struct {
	Endpoint windowsupdate.Endpoint
	Action   string
	Response windowsupdate.Response
}
type catalogSource struct {
	Version   int
	Profile   string
	Exchanges []catalogExchange
}
type catalogRecorder struct {
	upstream  windowsupdate.Transport
	exchanges []catalogExchange
	size      int
}

func (r *catalogRecorder) Do(ctx context.Context, request windowsupdate.Request) (windowsupdate.Response, error) {
	response, err := r.upstream.Do(ctx, request)
	if err != nil {
		return response, err
	}
	if len(r.exchanges) >= 65 || len(response.Body) > defaultMaximumResponse || r.size+len(response.Body) > maximumCatalogSource/2 {
		return windowsupdate.Response{}, fmt.Errorf("catalog source exceeds cache bounds")
	}
	response.Body = bytes.Clone(response.Body)
	r.size += len(response.Body)
	r.exchanges = append(r.exchanges, catalogExchange{request.Endpoint, request.Action, response})
	return response, nil
}

type catalogReplay struct {
	exchanges []catalogExchange
	next      int
}

func (r *catalogReplay) Do(ctx context.Context, request windowsupdate.Request) (windowsupdate.Response, error) {
	if err := ctx.Err(); err != nil {
		return windowsupdate.Response{}, err
	}
	if r.next >= len(r.exchanges) {
		return windowsupdate.Response{}, fmt.Errorf("offline catalog source is incomplete; explicitly fetch again")
	}
	entry := r.exchanges[r.next]
	if entry.Endpoint != request.Endpoint || entry.Action != request.Action {
		return windowsupdate.Response{}, fmt.Errorf("offline catalog source request sequence mismatch; explicitly fetch again")
	}
	r.next++
	return entry.Response, nil
}
func catalogSourcePath(root string, options windowsupdate.ScanOptions) (string, string, error) {
	profile, err := json.Marshal(options)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(profile)
	key := hex.EncodeToString(sum[:])
	return filepath.Join(root, "catalogs-v1", key), key, nil
}
func cachedCatalog(ctx context.Context, root string, options windowsupdate.ScanOptions, network bool, protocol windowsupdate.ClientProtocol) (*windowsupdate.Catalog, error) {
	name, key, err := catalogSourcePath(root, options)
	if err != nil {
		return nil, err
	}
	if !network {
		source, err := readCatalogSource(name, key)
		if err != nil {
			return nil, fmt.Errorf("offline update catalog unavailable: %w; run explicit fetch=true preparation (native network=True)", err)
		}
		replay := &catalogReplay{exchanges: source.Exchanges}
		protocol.Transport = replay // No live transport survives in this path.
		catalog, err := protocol.SyncCatalog(ctx, options)
		if err != nil {
			return nil, fmt.Errorf("offline catalog replay: %w", err)
		}
		if replay.next != len(replay.exchanges) {
			return nil, fmt.Errorf("offline catalog source has trailing responses")
		}
		return catalog, nil
	}
	recorder := &catalogRecorder{upstream: protocol.Transport}
	protocol.Transport = recorder
	catalog, err := protocol.SyncCatalog(ctx, options)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := writeCatalogSource(name, catalogSource{1, key, recorder.exchanges}); err != nil {
		return nil, err
	}
	return catalog, nil
}
func readCatalogSource(name, key string) (*catalogSource, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < sha256.Size || info.Size() > maximumCatalogSource {
		return nil, fmt.Errorf("invalid catalog source type or size")
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maximumCatalogSource+1))
	if err != nil {
		return nil, err
	}
	if len(data) < sha256.Size || len(data) > maximumCatalogSource {
		return nil, fmt.Errorf("invalid catalog source size")
	}
	sum := sha256.Sum256(data[sha256.Size:])
	if !bytes.Equal(data[:sha256.Size], sum[:]) {
		return nil, fmt.Errorf("catalog source checksum mismatch")
	}
	var source catalogSource
	decoder := json.NewDecoder(bytes.NewReader(data[sha256.Size:]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&source); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("trailing catalog source data")
	}
	if source.Version != 1 || source.Profile != key || len(source.Exchanges) == 0 || len(source.Exchanges) > 65 {
		return nil, fmt.Errorf("catalog source version/profile/response count mismatch")
	}
	for _, entry := range source.Exchanges {
		if entry.Response.StatusCode != 200 || len(entry.Response.Body) > defaultMaximumResponse {
			return nil, fmt.Errorf("invalid cached catalog response")
		}
	}
	return &source, nil
}
func writeCatalogSource(name string, source catalogSource) error {
	data, err := json.Marshal(source)
	if err != nil {
		return err
	}
	if len(data)+sha256.Size > maximumCatalogSource {
		return fmt.Errorf("catalog source exceeds cache bound")
	}
	if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(name), ".catalog-*")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	sum := sha256.Sum256(data)
	if _, err = f.Write(sum[:]); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), name)
	}
	return err
}
