package main

import (
	"fmt"
	"net/http"
)

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, fmt.Sprintf("method not allowed: %s", r.Method), http.StatusMethodNotAllowed)
	}

	w.Header().Set("Content-Type", "application/json")
	return
}
