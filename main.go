package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	api_sec "github.com/tamaricoh/F5_home_assignment/pkg" // Import your api_sec package
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {

	timestamp := time.Now().Format("20060102150405") // Adding a timestamp to the filename to differentiate between files and avoid overwriting
	logFilename := fmt.Sprintf("log%s.log", timestamp)
	logfile, errLog := os.OpenFile(logFilename, os.O_APPEND | os.O_CREATE | os.O_WRONLY, 0644)
	defer logfile.Close()

	if errLog != nil {
		log.Fatalf("Failed to open log file: %v", errLog)
	}

	log.SetOutput(&lumberjack.Logger{
		Filename:   logFilename,
		MaxSize:    10, // Max megabytes before log rotation
		MaxBackups: 3,  // Max number of old log files to keep
		MaxAge:     28, // Max number of days to keep old log files
		Compress:   true, // Compress old log files
	})

	// Define your routes
	http.HandleFunc("/register", api_sec.Register)                    
	http.HandleFunc("/login", api_sec.Login)                          
	http.HandleFunc("/getusers", api_sec.Auth(api_sec.GetUsers))                          
	http.Handle("/accounts", api_sec.Auth(api_sec.AccountsHandler))   
	http.Handle("/balance", api_sec.Auth(api_sec.BalanceHandler))

	// Start the server
	log.Println("Starting server on :8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}