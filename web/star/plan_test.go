package star

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/tinyrange/trex/auto"
	autostar "github.com/tinyrange/trex/auto/star"
	starfile "github.com/tinyrange/trex/storage/star"
	"go.starlark.net/starlark"
)

func TestBrowsePlanNavigation(t *testing.T) {
	builds := 0
	auto.RegisterPlan("web-plan-test", func(entries []auto.Entry, source auto.View, o auto.Options) ([]*auto.Plan, error) {
		if len(entries) != 1 || entries[0].Name != "web-plan-input" {
			return nil, nil
		}
		return []*auto.Plan{{ID: "joined", Title: "Combine files", Description: "Test virtual view", Build: func() (auto.View, error) {
			builds++
			return auto.ViewFunc(func() ([]auto.Entry, error) {
				return []auto.Entry{{Name: "combined", Kind: "file", Reader: &starfile.Bytes{Data: []byte("abcdef")}}}, nil
			}), nil
		}}}, nil
	})
	root, err := auto.FromView(auto.ViewFunc(func() ([]auto.Entry, error) {
		return []auto.Entry{{Name: "web-plan-input", Kind: "file", Reader: &starfile.Bytes{Data: []byte("raw")}}}, nil
	}), "", auto.Options{}).WithPlans()
	if err != nil {
		t.Fatal(err)
	}
	app := NewApplication(&starlark.Thread{}, starlark.NewBuiltin("handle", func(t *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		return webBrowseBuiltin(t, b, starlark.Tuple{&autostar.Value{Node: root}, args[0]}, nil)
	}))
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", "/?json=1", nil))
	var response struct {
		Plans []struct {
			ID string `json:"id"`
		}
		Children []auto.Metadata
	}
	if rec.Code != 200 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Plans) != 1 || response.Plans[0].ID != "joined" || builds != 0 || response.Children[0].Name != "web-plan-input" {
		t.Fatal(response, builds)
	}
	req := httptest.NewRequest("GET", "/$plans/joined/combined?raw=1", nil)
	req.Header.Set("Range", "bytes=1-3")
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != 206 || rec.Body.String() != "bcd" || builds != 1 {
		t.Fatal(rec.Code, rec.Body.String(), builds)
	}
}
