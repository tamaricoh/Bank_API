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


/*
1.  JWT Key Management problem :(     | v |
2.  Add input validation              | v | 
>>> buffer overun - limit the length of usernames, passwords, and all user inputs in general.
3.  HTTP Status Codes                 | v |
4.  Hash the passwords                | v |
5.  Make the search more efficient    | v |
6.  SQL injection                     | v |
7.  Require all necessary inputs and ensure they are not empty    | v |
8.  The log is not calculating the length correctly, and I want to check if the parameters in it are correct.    | v |
9.  Everyone can register as an admin
10. No logout implementation
11. We can login several times
*/

/*
1. ID Generation is simple, but accounts or users cannot be deleted.
2. Improve the locking mechanism so that a lock by one user does not block other users.
3. I would check if there are existing packages that perform the validations I wrote manually.
4. Everyone can register as an admin
*/

func Register(w http.ResponseWriter, r *http.Request) {
	/*
		1. Ensure username, password, and role are not empty      | v |
		2. Make the Username unique                               | v |
		3. Hash the passwords                                     | v |
		4. Exclude Password in Response                           | v |
	*/
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

	// Part 1:
	if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.Password) == "" {
		handleError(w, r, "Username and password must not be empty", http.StatusBadRequest)
		return
	}
	
	if (user.Role != string(UserRole) && user.Role != string(AdminRole)) || strings.TrimSpace(user.Role) == "" {
		handleError(w, r, "Role must be 'user' or 'admin'", http.StatusBadRequest)
		return
	}
	// Part 2:
	if _, exists := users[user.Username]; exists {
		handleError(w, r, "Username already exists", http.StatusConflict)
		return
	}

	// Part 3:
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		handleError(w, r, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	user.ID = len(users) + 1 
	users[user.Username] = user

	// Part 4:
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
	/*
	1. Ensure username and password are not empty      | v |
	2. Remove the direct Password comparison           | v |
	*/
	if r.Method != http.MethodPost { 
		handleError(w, r, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds User
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	// Part 1:
	if strings.TrimSpace(creds.Username) == "" || strings.TrimSpace(creds.Password) == "" {
		handleError(w, r, "Username and password must not be empty", http.StatusBadRequest)
		return
	}

	// Authenticate user
	var authenticatedUser *User
	for _, user := range users {
		if user.Username == creds.Username {
			// Part 2:
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err == nil {
				authenticatedUser = &user
				break
			}
		}
	}

	// If user doesn't exist or password is incorrect
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
	/*
	1. Authorization check              | v |
	2. Handle unsupported HTTP methods  | v |
	*/
	if r.Method == http.MethodPost {
		if claims.Role != "admin" {
			handleError(w, r, "Unauthorized", http.StatusForbidden)
			return
		}
		createAccount(w, r, claims)
		return
	}
	if r.Method == http.MethodGet {
		// Part 1:
		if claims.Role != "admin" {
			handleError(w, r, "Unauthorized", http.StatusForbidden)
			return
		}
		listAccounts(w, r, claims)
		return
	}
	// Part 2:
	errorMsg := "Method Not Allowed"
	handleError(w, r, errorMsg, http.StatusMethodNotAllowed)
}

func createAccount(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Authorization check                    | v |
	2. Error Handling for Invalid Data        | v |
	3. Check if account already exists        | v |
	*/

	// Part 1:
	if claims.Role != "admin" {
		handleError(w, r, "Unauthorized", http.StatusForbidden)
		return
	}

	var acc Account
	if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
		handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	// Part 2:
	if acc.UserID <= 0 || acc.UserID > len(users) {
		handleError(w, r, "Invalid UserID", http.StatusBadRequest)
		return
	}

	// Part 3:
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
	/*
	1. Ensure the HTTP method is GET          | v |
 	2. Authorization check                    | v |
	3. Error Handling for Empty accounts      | v |
	*/

	// Part 1:
	if r.Method != http.MethodGet {
		handleError(w, r, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Part 2:
	if claims.Role != "admin" {
		handleError(w, r, "Unauthorized", http.StatusForbidden)
		return
	}

	// Part 3:
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
	/*
	1. Missing Default Case for HTTP Methods
	*/
	switch r.Method {
	case http.MethodGet:
		getBalance(w, r, claims)
	case http.MethodPost:
		depositBalance(w, r, claims)
	case http.MethodDelete:
		withdrawBalance(w, r, claims)
	// Part 1:
	default:
		handleError(w, r, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func getBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Input Validation for user_id         | v |
	2. Authorization check                  | v |
	*/
	
	userId := r.URL.Query().Get("user_id")
	uid, err := strconv.Atoi(userId)
	
	// Part 1:
	if err != nil {
		handleError(w, r, "Invalid user_id", http.StatusBadRequest)
		return
	}

	// Part 2:
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
	/*
	1. Validation for Deposit Amount            | v |
	2. Authorization check                      | v |
	*/

	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	// Part 1:
	if body.UserID <= 0 || body.UserID > len(users) {
		handleError(w, r, "Invalid UserID", http.StatusBadRequest)
		return
	}

	if body.Amount <= 0 {
		handleError(w, r, "Amount must be greater than zero", http.StatusBadRequest)
		return
	}	

	// Part 2:
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
	/*
	1. Validation for Withdrawal Amount         | v |
	2. Authorization check                      | v |
	*/

	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		handleError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	// Part 1:
	if body.UserID <= 0 || body.UserID > len(users) {
		handleError(w, r, "Invalid UserID", http.StatusBadRequest)
		return
	}
	
	if body.Amount <= 0 {
		handleError(w, r, "Amount must be greater than zero", http.StatusBadRequest)
		return
	}

	// Part 2:
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
	case statusCode >= 200 && statusCode < 300:
		return "2xx"
	case statusCode >= 300 && statusCode < 400:
		return "3xx"
	case statusCode >= 400 && statusCode < 500:
		return "4xx"
	case statusCode >= 500:
		return "5xx"
	default:
		return "unknown"
	}
}

func writeAndLogResponse(w http.ResponseWriter, r *http.Request, statusCode int, responseData interface{}) {
    // Marshal the response data into JSON
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