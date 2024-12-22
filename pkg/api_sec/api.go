package api_sec

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
) 

var jwtKey = []byte("sodi")

type Role string

const (
	AdminRole   Role = "admin"
	UserRole 	Role = "user"
)

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	UserID   int    `json:"user_id"`
	jwt.StandardClaims
}

type LogEntry struct {
	Timestamp  string `json:"timestamp"`
	Req Req `json:"req"`
	Rsp Rsp `json:"rsp"`
}

type Req struct {
    Method     string `json:"method"`
	URL        string `json:"url"`
	QSParams   string `json:"qs_params"`
	Headers    string `json:"headers"`
	ReqBodyLen int    `json:"req_body_len"`
	Role       Role   `json:"role"` // Role is an enum-like field
	// UserID     int    `json:"user_id"`
}

type Rsp struct {
	StatusCode   int   `json:"status_code"`
	StatusClass string `json:"status_class"`
	RspBodyLen  int    `json:"rsp_body_len"`
}


func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		handleError(w, r, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		handleError(w, r, "Invalid input", http.StatusBadRequest)
		return
	}

	if len(user.Username) > 16 {
		handleError(w, r, "Username must not be longer than 16 characters", http.StatusBadRequest)
		return
	}

	if len(user.Password) > 16 {
		handleError(w, r, "Password must not be longer than 16 characters", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.Password) == "" {
		handleError(w, r, "Username and password must not be empty", http.StatusBadRequest)
		return
	}
	
	if (user.Role != string(UserRole) && user.Role != string(AdminRole)) || strings.TrimSpace(user.Role) == "" {
		handleError(w, r, "Role must be 'user' or 'admin'", http.StatusBadRequest)
		return
	}

	if _, exists := users[user.Username]; exists {
		handleError(w, r, "Username already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		handleError(w, r, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	user.ID = len(users) + 1 
	users[user.Username] = user

	response := struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
	}

	writeAndLogResponse(w, r, http.StatusOK, response)
}

func Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { 
		handleError(w, r, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds User
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(creds.Username) == "" || strings.TrimSpace(creds.Password) == "" {
		handleError(w, r, "Username and password must not be empty", http.StatusBadRequest)
		return
	}


	var authenticatedUser *User
	for _, user := range users {
		if user.Username == creds.Username {
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err == nil {
				authenticatedUser = &user
				break
			}
		}
	}

	if authenticatedUser == nil {
		handleError(w, r, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: authenticatedUser.Username,
		Role:     authenticatedUser.Role,
		UserID:   authenticatedUser.ID,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		handleError(w, r, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	response := map[string]string{"token": tokenString}
	writeAndLogResponse(w, r, http.StatusOK, response)

}
func GetUsers(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if r.Method != http.MethodGet {
		handleError(w, r, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if claims.Role != "admin" {
		handleError(w, r, "Unauthorized", http.StatusForbidden)
		return
	}

	if len(users) == 0 {
		handleError(w, r, "No users found", http.StatusNotFound)
		return
	}

	var allUsers []User
	for _, user := range users {
		userCopy := user
		userCopy.Password = "" 
		allUsers = append(allUsers, userCopy)
	}

	writeAndLogResponse(w, r, http.StatusOK, allUsers)
}

func AccountsHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if r.Method == http.MethodPost {
		if claims.Role != "admin" {
			handleError(w, r, "Unauthorized", http.StatusForbidden)
			return
		}
		createAccount(w, r, claims)
		return
	}
	if r.Method == http.MethodGet {
		if claims.Role != "admin" {
			handleError(w, r, "Unauthorized", http.StatusForbidden)
			return
		}
		listAccounts(w, r, claims)
		return
	}
	errorMsg := "Method Not Allowed"
	handleError(w, r, errorMsg, http.StatusMethodNotAllowed)
}

func createAccount(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if claims.Role != "admin" {
		handleError(w, r, "Unauthorized", http.StatusForbidden)
		return
	}

	var acc Account
	if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
		handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	if acc.UserID <= 0 || acc.UserID > len(users) {
		handleError(w, r, "Invalid UserID", http.StatusBadRequest)
		return
	}

	if _, exists := accounts[acc.UserID]; exists {
		handleError(w, r, "Account already exists for this UserID", http.StatusConflict)
		return
	}

	acc.ID = len(accounts) + 1
	acc.CreatedAt = time.Now()
	accounts[acc.ID] = acc

	writeAndLogResponse(w, r, http.StatusCreated, acc) 
}

func listAccounts(w http.ResponseWriter, r *http.Request, claims *Claims) {
	if r.Method != http.MethodGet {
		handleError(w, r, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if claims.Role != "admin" {
		handleError(w, r, "Unauthorized", http.StatusForbidden)
		return
	}

	if len(accounts) == 0 {
		handleError(w, r, "No accounts found", http.StatusNotFound)
		return
	}
	var allAccounts []Account
	for _, acc := range accounts {
    	allAccounts = append(allAccounts, acc)
	}

	writeAndLogResponse(w, r, http.StatusOK, allAccounts)
}

func BalanceHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	switch r.Method {
	case http.MethodGet:
		getBalance(w, r, claims)
	case http.MethodPost:
		depositBalance(w, r, claims)
	case http.MethodDelete:
		withdrawBalance(w, r, claims)
	default:
		handleError(w, r, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func getBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	
	userId := r.URL.Query().Get("user_id")
	uid, err := strconv.Atoi(userId)
	
	if err != nil {
		handleError(w, r, "Invalid user_id", http.StatusBadRequest)
		return
	}

	if claims.Role != "admin" && claims.UserID != uid {
		handleError(w, r, "Unauthorized", http.StatusForbidden)
		return
	}

	if acc, exists := accounts[uid]; exists {
		responseBody := map[string]float64{"balance": acc.Balance}
	
		writeAndLogResponse(w, r, http.StatusOK, responseBody,)
		return
	}
	handleError(w, r, "Account not found", http.StatusNotFound)
}

func depositBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {

	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	if body.UserID <= 0 || body.UserID > len(users) {
		handleError(w, r, "Invalid UserID", http.StatusBadRequest)
		return
	}

	if body.Amount <= 0 {
		handleError(w, r, "Amount must be greater than zero", http.StatusBadRequest)
		return
	}	

	if claims.UserID != body.UserID {
		handleError(w, r, "Unauthorized", http.StatusForbidden)
		return
	}

	if acc, exists := accounts[body.UserID]; exists {
		acc.Balance += body.Amount
		accounts[body.UserID] = acc
		responseBody := acc
		writeAndLogResponse(w, r, http.StatusOK, responseBody)
		return
	}
	handleError(w, r, "Account not found", http.StatusNotFound)
}

func withdrawBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {

	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	if body.UserID <= 0 || body.UserID > len(users) {
		handleError(w, r, "Invalid UserID", http.StatusBadRequest)
		return
	}
	
	if body.Amount <= 0 {
		handleError(w, r, "Amount must be greater than zero", http.StatusBadRequest)
		return
	}

	if claims.UserID != body.UserID {
		handleError(w, r, "Unauthorized", http.StatusForbidden)
		return
	}

	if acc, exists := accounts[body.UserID]; exists {
		if acc.Balance < body.Amount {
			handleError(w, r, ErrInsufficientFunds.Error(), http.StatusBadRequest)
			return
		}
	
		acc.Balance -= body.Amount
		accounts[body.UserID] = acc
	
		writeAndLogResponse(w, r, http.StatusOK, acc)
		return
	}
	
	handleError(w, r, "Account not found", http.StatusNotFound)
}

func Auth(next func(http.ResponseWriter, *http.Request, *Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			handleError(w, r, "Missing token", http.StatusUnauthorized)
			return
		}
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			handleError(w, r, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, claims)
	}
}

func logRequestAndResponse(r *http.Request, statusCode int, rspLen int) { 

	loggingReq := &Req{
		Method: 	r.Method,
		URL:        r.URL.String(),
		QSParams:   r.URL.RawQuery,
		Headers:    formatHeaders(r.Header),
		ReqBodyLen: int(r.ContentLength),
	}

	loggingRsp := &Rsp{
		StatusCode: statusCode,
		StatusClass: determineStatusClass(statusCode),
		RspBodyLen:  rspLen,
	}

	logging := &LogEntry{
		Timestamp: time.Now().Format("20060102150405"), // Adding a timestamp
		Req: *loggingReq,
		Rsp: *loggingRsp,
	}

	logData, _ := json.Marshal(logging)
	log.Println(string(logData))
}

func formatHeaders(headers http.Header) string {
	var headerStrings []string
	for k, v := range headers {
		headerStrings = append(headerStrings, fmt.Sprintf("%s: %s", k, strings.Join(v, ",")))
	}
	return strings.Join(headerStrings, "; ")
}

func determineStatusClass(statusCode int) string {
	switch {
	case statusCode >= 100 && statusCode < 200:
		return "1xx"
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500 && statusCode < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

func writeAndLogResponse(w http.ResponseWriter, r *http.Request, statusCode int, responseData interface{}) {
    responseBody, err := json.Marshal(responseData)
    if err != nil {
        handleError(w, r, "Internal Server Error", http.StatusInternalServerError)
        return
    }

    w.WriteHeader(statusCode)
    w.Write(responseBody)

    responseBodyLength := len(responseBody)

    logRequestAndResponse(r, statusCode, responseBodyLength)
}

func handleError(w http.ResponseWriter, r *http.Request, errorMsg string, statusCode int) {
	http.Error(w, errorMsg, statusCode) 
	logRequestAndResponse(r, statusCode, len(errorMsg)) 
}
