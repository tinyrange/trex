package starlarkfrontend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tinyrange/trex/emulator/s390"
	"github.com/tinyrange/trex/emulator/s390/web3270"
)

// fileSnapshots keeps a machine's named snapshots as files in a directory
// beside its state file (STATE.snapshots/NAME.state).
type fileSnapshots struct{ terms *s390.WebTerminals }

func (f fileSnapshots) dir() string { return f.terms.State + ".snapshots" }

func (f fileSnapshots) path(name string) (string, error) {
	if !web3270.SnapshotName.MatchString(name) {
		return "", fmt.Errorf("invalid snapshot name %q", name)
	}
	return filepath.Join(f.dir(), name+".state"), nil
}

func (f fileSnapshots) List() ([]web3270.SnapshotInfo, error) {
	entries, err := os.ReadDir(f.dir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []web3270.SnapshotInfo
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".state")
		if !ok || e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, web3270.SnapshotInfo{Name: name, Bytes: info.Size(), Saved: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Saved.After(out[j].Saved) })
	return out, nil
}

func (f fileSnapshots) Save(name string) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	_, err = writeMachineState(f.terms.Live, p)
	return err
}

func (f fileSnapshots) Restore(name string) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	file, err := os.Open(p)
	if err != nil {
		return err
	}
	defer file.Close()
	return f.terms.Live.Restore(file)
}

func (f fileSnapshots) Delete(name string) error {
	p, err := f.path(name)
	if err != nil {
		return err
	}
	return os.Remove(p)
}

// autosave saves the machine's resume state every interval until ctx is
// done.
func autosave(ctx context.Context, terms *s390.WebTerminals, interval time.Duration, logf func(string, ...any)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if where, err := saveMachineState(terms); err != nil {
				logf("autosave: %v", err)
			} else {
				logf("autosaved %s", where)
			}
		}
	}
}
