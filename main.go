// Package main starts the Nexx private email validation service.
package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"emailvalidator/internal/api"
	"emailvalidator/internal/service"
)

func main() {
	token := os.Getenv("NEXX_EMAIL_VALIDATOR_TOKEN")
	if len(token) < 32 {
		log.Fatal("NEXX_EMAIL_VALIDATOR_TOKEN must contain at least 32 characters")
	}
	// Do not configure remote Redis or persist email results.
	emailService, err := service.NewEmailServiceWithCache(nil)
	if err != nil {
		log.Fatal("failed to initialize validator")
	}
	handler := api.NewHandler(emailService)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	srv := &http.Server{
		Addr: ":" + port,
		Handler: privateValidator(token, http.HandlerFunc(handler.HandleValidate), time.Now),
		ReadTimeout: 3 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout: 30 * time.Second,
		ReadHeaderTimeout: 2 * time.Second,
		MaxHeaderBytes: 8192,
	}
	log.Fatal(srv.ListenAndServe())
}
