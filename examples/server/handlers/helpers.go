package handlers

import (
	"net/http"

	jsoniter "github.com/json-iterator/go"
)

// JSON serialize the data with matching requested encoding
func withJSON(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	json := jsoniter.ConfigCompatibleWithStandardLibrary

	// Marshal response as json
	body, _ := json.Marshal(data)

	// Set content type header
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// Write status
	w.WriteHeader(code)

	// Write response
	w.Write(body)
}
