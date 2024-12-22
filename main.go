package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tamaricoh/F5_home_assignment/pkg/api_sec"
	"gopkg.in/natefinch/lumberjack.v2"
)

func main() {

	timestamp := time.Now().Format("20060102150405") 
	logFilename := fmt.Sprintf("log%s.log", timestamp)
	logfile, errLog := os.OpenFile(logFilename, os.O_APPEND | os.O_CREATE | os.O_WRONLY, 0644)
	
	if errLog != nil {
		log.Fatalf("Failed to open log file: %v", errLog)
	}

	defer logfile.Close()

	log.SetOutput(&lumberjack.Logger{
		Filename:   logFilename,
		MaxSize:    10,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
	})

	http.HandleFunc("/register", api_sec.Register)                    
	http.HandleFunc("/login", api_sec.Login)                          
	http.HandleFunc("/getusers", api_sec.Auth(api_sec.GetUsers))                          
	http.HandleFunc("/accounts", api_sec.Auth(api_sec.AccountsHandler))   
	http.HandleFunc("/balance", api_sec.Auth(api_sec.BalanceHandler))

	log.Println("Starting server on :8080...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal("Error starting server: ", err)
	}
}
