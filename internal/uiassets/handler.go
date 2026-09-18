// Package uiassets serves the compiled local web interface embedded in the hub.
package uiassets

import (
	"embed"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
)

// dist is replaced by `npm run build` from web/.
//
//go:embed dist
var embedded embed.FS

// Handler returns an HTTP handler for static assets and client-side routes.
// API routes must be registered before mounting this handler at "/".
func Handler() http.Handler {
	assets, err := fs.Sub(embedded, "dist")
	if err != nil {
		panic("uiassets: embedded dist directory is missing")
	}
	return &handler{assets: assets}
}

type handler struct {
	assets fs.FS
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	setSecurityHeaders(w.Header())
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "." || name == "" {
		name = "index.html"
	}

	if strings.HasPrefix(name, "api/") {
		http.NotFound(w, r)
		return
	}

	if file, err := h.assets.Open(name); err == nil {
		defer file.Close()
		if info, statErr := file.Stat(); statErr == nil && !info.IsDir() {
			serveFile(w, r, name, file)
			return
		}
	}

	// Asset requests should fail plainly. Other paths are React routes and receive
	// the shell so browser refresh and copied local URLs keep working offline.
	if strings.HasPrefix(name, "assets/") || path.Ext(name) != "" {
		http.NotFound(w, r)
		return
	}
	index, err := h.assets.Open("index.html")
	if err != nil {
		http.Error(w, "web interface unavailable", http.StatusServiceUnavailable)
		return
	}
	defer index.Close()
	serveFile(w, r, "index.html", index)
}

func serveFile(w http.ResponseWriter, r *http.Request, name string, file fs.File) {
	contentType := mime.TypeByExtension(path.Ext(name))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	w.Header().Set("Content-Type", contentType)
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-store")
	} else if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = io.Copy(w, file)
}

func setSecurityHeaders(header http.Header) {
	header.Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self'")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
}
