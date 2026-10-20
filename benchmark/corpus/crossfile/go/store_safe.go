package files

// Benchmark : fonctions appelées uniquement avec des entiers depuis server_safe.go (aucune alerte attendue).

import (
	"fmt"
	"net/http"
	"os"
)

func ReadInvoice(id int) ([]byte, error) {
	return os.ReadFile(fmt.Sprintf("/srv/invoices/%d.pdf", id))
}

func FetchProduct(id int) (*http.Response, error) {
	return http.Get(fmt.Sprintf("https://catalog.example.com/items/%d", id))
}
