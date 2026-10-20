package handlers

// Benchmark : failles courantes d'un service HTTP Go (vulnérable).

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

var db *sql.DB

func Search(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name)
	rows, _ := db.Query(query)
	defer rows.Close()
}

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	w.Write(out)
}

func Download(w http.ResponseWriter, r *http.Request) {
	file := r.URL.Query().Get("file")
	data, _ := os.ReadFile(filepath.Join("/srv/files", file))
	w.Write(data)
}

func Proxy(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	resp, _ := http.Get(target)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func Hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Bonjour %s</h1>", name)
}

func Next(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

func Checksum(password string) []byte {
	sum := md5.Sum([]byte(password))
	return sum[:]
}

var insecureClient = &http.Client{Transport: &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}}
