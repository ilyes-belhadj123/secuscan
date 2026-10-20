package handlers

// Benchmark : mêmes fonctionnalités que handlers.go, écrites de façon sûre (aucune alerte attendue).

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

func Search(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	rows, _ := db.Query("SELECT id FROM users WHERE name = $1", name)
	defer rows.Close()
}

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, _ := exec.Command("ping", "-c", "1", "--", host).Output()
	w.Write(out)
}

func Download(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	data, _ := os.ReadFile(filepath.Join("/srv/files", filepath.Base(file)))
	w.Write(data)
}

func Proxy(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	resp, _ := http.Get("https://catalog.example.com/items/" + url.PathEscape(id))
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func Hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Bonjour %s</h1>", html.EscapeString(name))
}

func Next(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/compte", http.StatusFound)
}

func Checksum(data string) []byte {
	sum := sha256.Sum256([]byte(data))
	return sum[:]
}

var client = &http.Client{}
