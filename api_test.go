package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// TestRegisterUser sends a POST request to the /register endpoint on the server.
func TestRegisterUser(t *testing.T) {
	input := &RegisterRequest{
		Username: "user1",
		Password: "password123",
		Role:     "user",
	}

	jsonData, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Failed to marshal input: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/register", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code. Modify this according to your API's behavior.
	expectedStatusCode := http.StatusOK
	if resp.StatusCode != expectedStatusCode {
		t.Errorf("Expected status '%d', got '%d'", expectedStatusCode, resp.StatusCode)
	}

	// Read and decode the response body.
	var responseBody map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&responseBody)
	if err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}

	expectedUsername := "user1"
	if responseBody["username"] != expectedUsername {
		t.Errorf("Expected username '%s', got '%s'", expectedUsername, responseBody["username"])
	}
}

func TestRegisterAdmin(t *testing.T) {
	input := &RegisterRequest{
		Username: "admin1",
		Password: "adminpass",
		Role:     "admin",
	}

	jsonData, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Failed to marshal input: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/register", bytes.NewBuffer(jsonData))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response status code. Modify this according to your API's behavior.
	expectedStatusCode := http.StatusOK
	if resp.StatusCode != expectedStatusCode {
		t.Errorf("Expected status '%d', got '%d'", expectedStatusCode, resp.StatusCode)
	}

	// Read and decode the response body.
	var responseBody map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&responseBody)
	if err != nil {
		t.Fatalf("Failed to decode response body: %v", err)
	}

	expectedUsername := "admin1"
	if responseBody["username"] != expectedUsername {
		t.Errorf("Expected username '%s', got '%s'", expectedUsername, responseBody["username"])
	}

	expectedRole := "admin"
	if responseBody["role"] != expectedRole {
		t.Errorf("Expected role '%s', got '%s'", expectedRole, responseBody["role"])
	}
}


