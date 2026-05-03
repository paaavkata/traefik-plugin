package traefik_gateway_plugin

import (
	"encoding/json"
	"net/http"
)

func writeJSON(rw http.ResponseWriter, statusCode int, data interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(statusCode)
	json.NewEncoder(rw).Encode(data)
}
