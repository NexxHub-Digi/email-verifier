package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"
)

// privateValidator exposes only a health probe and authenticated single-address checks.
// Limits are per instance; use one instance or an external shared limiter.
func privateValidator(token string, validate http.Handler, now func() time.Time) http.Handler {
	expected := sha256.Sum256([]byte("Bearer " + token))
	var mu sync.Mutex
	var window time.Time
	count := 0
	active := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/api/validate" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		actual := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if len(token) < 32 || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		current := now()
		if window.IsZero() || current.Sub(window) >= time.Minute || current.Before(window) {
			window, count = current, 0
		}
		if count >= 60 {
			mu.Unlock()
			w.Header().Set("Retry-After", "60")
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		count++
		mu.Unlock()
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || kind != "application/json" {
			http.Error(w, "expected json", http.StatusUnsupportedMediaType)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
		if err != nil {
			http.Error(w, "invalid or oversized body", http.StatusRequestEntityTooLarge)
			return
		}
		var body struct {
			Email string `json:"email"`
		}
		if json.Unmarshal(raw, &body) != nil || len(body.Email) == 0 || len(body.Email) > 254 {
			http.Error(w, "invalid email request", http.StatusBadRequest)
			return
		}
		clean, _ := json.Marshal(body)
		r.Body = io.NopCloser(bytes.NewReader(clean))
		r.ContentLength = int64(len(clean))
		r.Header.Del("Authorization")
		validate.ServeHTTP(w, r)
	})
}
