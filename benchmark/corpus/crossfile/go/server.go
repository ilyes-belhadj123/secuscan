package files

// Benchmark : entrée utilisateur transmise à des fonctions d'un autre fichier (vulnérable).

import (
	"bytes"
	"io"
	"net/http"
)

func Attachment(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	data, _ := ReadAttachment(name)
	io.Copy(w, bytes.NewReader(data))
}

func Preview(w http.ResponseWriter, r *http.Request) {
	resp, err := FetchPreview(r.URL.Query().Get("url"))
	if err == nil {
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}
}
