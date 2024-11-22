package main

import (
	"log"
	"net/http"

	api_sec "github.com/tamaricoh/F5_home_assignment/pkg" // Import your api_sec package
)

func main() {
	// Define your routes
	http.HandleFunc("/register", api_sec.Register)                    // works
	http.HandleFunc("/login", api_sec.Login)                          // works
	http.Handle("/accounts", api_sec.Auth(api_sec.AccountsHandler))

	// Start the server
	log.Println("Starting server on :8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}