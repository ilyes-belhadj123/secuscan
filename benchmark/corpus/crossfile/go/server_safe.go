package files

// Benchmark : mêmes appels entre fichiers, avec des valeurs converties en entiers (aucune alerte attendue).

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
)

func Invoice(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	data, _ := ReadInvoice(id)
	io.Copy(w, bytes.NewReader(data))
}

func Product(w http.ResponseWriter, r *http.Request) {
	productID, _ := strconv.Atoi(r.URL.Query().Get("id"))
	resp, err := FetchProduct(productID)
	if err == nil {
		defer resp.Body.Close()
		io.Copy(w, resp.Body)
	}
}
