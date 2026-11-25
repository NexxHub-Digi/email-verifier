package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrivateValidator(t *testing.T) {
	token := strings.Repeat("s", 40)
	now := time.Unix(1000, 0)
	calls := 0
	h := privateValidator(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "" {
			t.Error("token leaked to validator")
		}
		w.WriteHeader(http.StatusOK)
	}), func() time.Time { return now })
	request := func(method, path, secret, body string) int {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if secret != "" {
			req.Header.Set("Authorization", "Bearer " + secret)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	valid := `{"email":"staff@example.com"}`
	for _, tc := range []struct {
		method, path, secret, body string
		status int
	}{
		{"GET", "/healthz", "", "", 204},
		{"POST", "/api/validate", "", valid, 401},
		{"POST", "/api/validate", "incorrect", valid, 401},
		{"GET", "/api/validate", token, "", 405},
		{"POST", "/api/validate/batch", token, valid, 404},
		{"GET", "/metrics", token, "", 404},
		{"POST", "/api/validate?email=test", token, valid, 404},
		{"POST", "/api/validate", token, strings.Repeat("x", 2049), 413},
		{"POST", "/api/validate", token, "{}", 400},
		{"POST", "/api/validate", token, valid, 200},
	} {
		if got := request(tc.method, tc.path, tc.secret, tc.body); got != tc.status {
			t.Fatalf("%s %s: got %d want %d", tc.method, tc.path, got, tc.status)
		}
	}
	if calls != 1 {
		t.Fatalf("expected one validator call, got %d", calls)
	}
	for i := 0; i < 57; i++ {
		if got := request("POST", "/api/validate", token, valid); got != 200 {
			t.Fatalf("request %d: %d", i, got)
		}
	}
	if got := request("POST", "/api/validate", token, valid); got != 429 {
		t.Fatalf("expected rate limit, got %d", got)
	}
	now = now.Add(time.Minute)
	if got := request("POST", "/api/validate", token, valid); got != 200 {
		t.Fatalf("limit did not reset: %d", got)
	}
}

func TestMissingTokenFailsClosed(t *testing.T) {
	h := privateValidator("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unexpected validation")
	}), time.Now)
	req := httptest.NewRequest("POST", "/api/validate", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
}
