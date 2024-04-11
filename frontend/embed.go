package frontend

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
)

//go:embed dist
var Content embed.FS

func Handler() http.HandlerFunc {
	const distPath = "dist"
	webUI, _ := fs.Sub(Content, distPath)
	webServer := http.FileServer(http.FS(webUI))
	return func(w http.ResponseWriter, r *http.Request) {
		// Prevent from directory traversal attack
		path, err := filepath.Abs(r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f, err := Content.Open(filepath.Join(distPath, path))
		if os.IsNotExist(err) {
			// Serve index.html for SPA
			index, err := Content.ReadFile(filepath.Join(distPath, "index.html"))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write(index)
			return
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = f.Close()

		webServer.ServeHTTP(w, r)
	}
}
