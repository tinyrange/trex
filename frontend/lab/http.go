package labfrontend

import (
	"context"
	"encoding/json"
	"errors"
	"image/png"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"time"

	"github.com/tinyrange/trex/lab"
	"github.com/tinyrange/trex/vmm"
)

type httpApp struct {
	ctx                                 context.Context
	manager                             *lab.Manager
	media                               mediaLibrary
	catalog                             []lab.Recipe
	templates                           []lab.Template
	software                            []lab.SoftwareTitle
	alpine                              *lab.AlpineRepository
	localHost, tailnetHost, tailnetUser string
}

func (a httpApp) handler(ui fs.FS) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(ui))
	mux.HandleFunc("GET /api/catalog", func(w http.ResponseWriter, r *http.Request) {
		reply(w, struct {
			Recipes   []lab.Recipe   `json:"recipes"`
			Templates []lab.Template `json:"templates"`
		}{a.catalog, a.templates})
	})
	mux.HandleFunc("GET /api/software", func(w http.ResponseWriter, r *http.Request) {
		reply(w, struct {
			Software []lab.SoftwareTitle `json:"software"`
		}{a.software})
	})
	mux.HandleFunc("GET /api/alpine/packages", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		if len(query) > 128 {
			http.Error(w, "Use a package query of up to 128 bytes.", http.StatusBadRequest)
			return
		}
		if a.alpine == nil {
			http.Error(w, "The Alpine repository is unavailable.", http.StatusServiceUnavailable)
			return
		}
		packages, err := a.alpine.Search(r.Context(), query)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		reply(w, struct {
			Packages []lab.AlpinePackage `json:"packages"`
		}{packages})
	})
	mux.HandleFunc("GET /api/lab", func(w http.ResponseWriter, r *http.Request) { reply(w, a.manager.View()) })
	mux.HandleFunc("PUT /api/lab", a.definition(func(w http.ResponseWriter, d lab.Definition) {
		view, err := a.manager.Save(d)
		respond(w, view, err)
	}))
	mux.HandleFunc("POST /api/plan", a.definition(func(w http.ResponseWriter, d lab.Definition) { reply(w, a.manager.Plan(d)) }))
	mux.HandleFunc("POST /api/apply", a.definition(func(w http.ResponseWriter, d lab.Definition) {
		view, err := a.manager.Apply(d)
		respond(w, view, err)
	}))
	mux.HandleFunc("POST /api/stop", func(w http.ResponseWriter, r *http.Request) { reply(w, a.manager.Stop()) })
	mux.HandleFunc("GET /api/media", func(w http.ResponseWriter, r *http.Request) {
		dir := r.URL.Query().Get("dir")
		if dir == "." {
			dir = ""
		}
		page, err := a.media.browse(dir)
		respond(w, page, err)
	})
	mux.HandleFunc("GET /api/nodes/{id}/surfaces/{surface}/frame", a.surface(a.frame))
	mux.HandleFunc("GET /api/nodes/{id}/surfaces/{surface}/display", a.surface(a.display))
	mux.HandleFunc("GET /api/nodes/{id}/surfaces/{surface}/terminal", a.surface(a.terminal))
	mux.HandleFunc("GET /api/nodes/{id}/surfaces/{surface}/serial", a.surface(a.serial))
	mux.HandleFunc("POST /api/nodes/{id}/surfaces/{surface}/input", a.surface(a.input))
	mux.HandleFunc("GET /api/nodes/{id}/surfaces/{surface}/browse-session", a.surface(a.webSession))
	mux.HandleFunc("GET /api/nodes/{id}/surfaces/{surface}/browse/{$}", a.surface(a.openWeb))
	web := http.NewServeMux()
	web.HandleFunc("/api/nodes/{id}/surfaces/{surface}/browse/{key}/{path...}", a.surface(a.browseWeb))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := "http://" + a.localHost
		switch r.Host {
		case a.localHost:
		case a.tailnetHost:
			origin = "https://" + a.tailnetHost
			if a.tailnetHost == "" || a.tailnetUser == "" || r.Header.Get("Tailscale-User-Login") != a.tailnetUser {
				http.Error(w, "This lab is available only to its tailnet owner.", http.StatusForbidden)
				return
			}
		default:
			http.Error(w, "Unknown lab host.", http.StatusForbidden)
			return
		}
		if _, pattern := web.Handler(r); pattern != "" {
			web.ServeHTTP(w, r)
			return
		}
		if given := r.Header.Get("Origin"); given != "" && given != origin || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Open the editor from its lab address.", http.StatusForbidden)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("X-TinyRangeX") != "lab" {
			http.Error(w, "Use the lab editor to change this workspace.", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		wsOrigin := "ws://" + r.Host
		if r.Host == a.tailnetHost {
			wsOrigin = "wss://" + r.Host
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob: data:; font-src 'self'; connect-src 'self' "+wsOrigin+"; frame-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		mux.ServeHTTP(w, r)
	})
}

func reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func respond(w http.ResponseWriter, value any, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	reply(w, value)
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512<<10))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "Invalid lab request.", http.StatusBadRequest)
		return false
	}
	return true
}

func (a httpApp) definition(fn func(http.ResponseWriter, lab.Definition)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var d lab.Definition
		if decode(w, r, &d) {
			fn(w, d)
		}
	}
}

func (a httpApp) surface(f func(http.ResponseWriter, *http.Request, lab.Surface)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.manager.Surface(r.PathValue("id"), r.PathValue("surface"))
		if !ok {
			http.Error(w, "This guest surface is closed.", http.StatusNotFound)
			return
		}
		f(w, r, s)
	}
}

func (a httpApp) frame(w http.ResponseWriter, r *http.Request, s lab.Surface) {
	if s.Display == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	frame, err := s.Display.Capture(ctx)
	if err != nil || frame == nil {
		http.Error(w, "Waiting for the guest display.", http.StatusConflict)
		return
	}
	if pointer, ok := s.Display.(vmm.AbsolutePointerSource); ok {
		if on, _ := pointer.AbsolutePointer(ctx); on {
			w.Header().Set("X-TinyRangeX-Pointer", "absolute")
		}
	}
	w.Header().Set("Content-Type", "image/png")
	if r.URL.Query().Has("save") {
		w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": r.PathValue("id") + ".png"}))
	}
	_ = (&png.Encoder{CompressionLevel: png.BestSpeed}).Encode(w, frame)
}

func (a httpApp) terminal(w http.ResponseWriter, r *http.Request, s lab.Surface) {
	if s.Terminal == nil {
		http.NotFound(w, r)
		return
	}
	reply(w, map[string]any{"text": s.Terminal.Text(), "waiting": true})
}

func (a httpApp) input(w http.ResponseWriter, r *http.Request, s lab.Surface) {
	var input vmm.Input
	if !decode(w, r, &input) {
		return
	}
	if !validInputSize(input) {
		http.Error(w, "Guest input is too large.", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var err error
	switch {
	case s.Display != nil:
		err = s.Display.Input(ctx, input)
	case s.Terminal != nil && input.Kind == "text":
		err = s.Terminal.Input(ctx, input.Text)
	default:
		err = errors.New("this guest does not support that input")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validInputSize(input vmm.Input) bool {
	return len(input.Text) <= 4096 && len(input.Keys) <= 6 && len(input.Key) <= 24 && len(input.Buttons) <= 3
}
