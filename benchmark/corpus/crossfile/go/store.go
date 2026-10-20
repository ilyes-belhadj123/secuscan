package files

// Benchmark : fonctions appelées avec une entrée utilisateur depuis server.go (vulnérable).

import (
	"net/http"
	"os"
)

func ReadAttachment(name string) ([]byte, error) {
	return os.ReadFile("/srv/attachments/" + name)
}

func FetchPreview(target string) (*http.Response, error) {
	return http.Get(target)
}
