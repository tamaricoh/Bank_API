package api_sec

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var accountMutex sync.Mutex 

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	UserID   int    `json:"user_id"` // For the getBalance Authorization check
	jwt.StandardClaims
}

/*
1. JWT Key Management                |   |
2. Add input validation              | + | 
>>> buffer overun - limit the length of usernames, passwords, and all user inputs in general.
3. HTTP Status Codes                 | v |
4. Rate Limiting                     | ? |
6. Hash the passwords                | v |
7. Make the search more efficient    | v |
*/

/*
README:
1. ID Generation is simple, but accounts or users cannot be deleted.
2. Improve the locking mechanism so that a lock by one user does not block other users.
*/

// Rate limiter ----------------------------------------------------------
var rateLimitMutex sync.Mutex

// Structure to store rate limit data for users
type RateLimiter struct {
	// Store user request counts and timestamps
	UserRequests map[string]int
	Timestamps   map[string]time.Time
}

// Global RateLimiter instance
var rateLimiter = &RateLimiter{
	UserRequests: make(map[string]int),
	Timestamps:   make(map[string]time.Time),
}

// Max requests allowed per minute
const maxRequestsPerMinute = 100

func RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rateLimitMutex.Lock()
		defer rateLimitMutex.Unlock()

		// Get user IP or identifier (You can use other identifiers like username or token for rate limiting)
		userID := r.RemoteAddr

		// Check if the timestamp for the user exists and is still valid (within the last minute)
		if lastRequestTime, exists := rateLimiter.Timestamps[userID]; exists {
			// If within the last minute, check the request count
			if time.Since(lastRequestTime) < time.Minute {
				// Check if the user exceeded the rate limit
				if rateLimiter.UserRequests[userID] >= maxRequestsPerMinute {
					http.Error(w, "Too many requests. Please try again later.", http.StatusTooManyRequests)
					return
				}
			} else {
				// Reset the rate limit count after a minute
				rateLimiter.UserRequests[userID] = 0
				rateLimiter.Timestamps[userID] = time.Now()
			}
		} else {
			// If it's the user's first request, initialize the counters
			rateLimiter.UserRequests[userID] = 0
			rateLimiter.Timestamps[userID] = time.Now()
		}

		// Increment the request count for the user
		rateLimiter.UserRequests[userID]++

		// Pass the request to the next handler
		next.ServeHTTP(w, r)
	})
}
// Rate limiter ----------------------------------------------------------

func Register(w http.ResponseWriter, r *http.Request) {
	/*
		1. Make the Username unique            | v |
		2. Hash the passwords                  | v |
		3. Exclude Password in Response        | v |
	*/
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Part 1: Check if username is unique
	userExists := false
	for _, existingUser := range userMap {
		if existingUser.Username == user.Username {
			userExists = true
			break
		}
	}
	
	if userExists {
		http.Error(w, "Username already exists", http.StatusConflict)
		return
	}

	// Part 2: Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	user.ID = len(userMap) + 1 // Assuming the IDs are sequential, you can compute it from the map size.
	userMap[user.ID] = user

	// Part 3: Exclude the password from the response
	responseUser := struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Role     string `json:"role"`
	}{
		ID:       user.ID,
		Username: user.Username,
		Role:     user.Role,
	}

	json.NewEncoder(w).Encode(responseUser)
}

func Login(w http.ResponseWriter, r *http.Request) {
	/*
	1. Remove the direct Password comparison        | v |
	*/
	if r.Method != http.MethodPost { 
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	var creds User
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Authenticate user
	var authenticatedUser *User
	for _, user := range userMap {
		if user.Username == creds.Username {
			// Part 1:
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err == nil {
				authenticatedUser = &user
				break
			}
		}
	}

	// If user doesn't exist or password is incorrect
	if authenticatedUser == nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		Username: authenticatedUser.Username,
		Role:     authenticatedUser.Role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})

}

func AccountsHandler(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Authorization check              | v |
	2. Handle unsupported HTTP methods  | v |
	*/
	if r.Method == http.MethodPost {
		if claims.Role != "admin" {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		createAccount(w, r, claims)
		return
	}
	if r.Method == http.MethodGet {
		// Part 1:
		if claims.Role != "admin" {
			http.Error(w, "Unauthorized", http.StatusForbidden)
			return
		}
		listAccounts(w, r, claims)
		return
	}
	// Part 2:
	http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
}

func createAccount(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Authorization check                    | v |
	2. Error Handling for Invalid Data        | v |
	3. Check if account already exists        | v |
	*/

	// Part 1:
	if claims.Role != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	var acc Account
	if err := json.NewDecoder(r.Body).Decode(&acc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Part 2:
	if acc.UserID <= 0 {
		http.Error(w, "Invalid UserID: must be greater than 0", http.StatusBadRequest)
		return
	}

	// Part 3:
	if _, exists := accountMap[acc.UserID]; exists {
		http.Error(w, "Account already exists for this UserID", http.StatusConflict)
		return
	}

	acc.ID = len(accountMap) + 1
	acc.CreatedAt = time.Now()
	accountMap[acc.ID] = acc

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(acc)   
}

func listAccounts(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Ensure the HTTP method is GET          | v |
 	2. Authorization check                    | v |
	3. Error Handling for Empty accounts      | v |
	*/

	// Part 1:
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Part 2:
	if claims.Role != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Part 3:
	if len(accountMap) == 0 {
		http.Error(w, "No accounts found", http.StatusNotFound)
		return
	}
	var allAccounts []Account
	for _, acc := range accountMap {
    	allAccounts = append(allAccounts, acc)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allAccounts)
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
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
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
		http.Error(w, "Invalid user_id", http.StatusBadRequest)
		return
	}

	// Part 2:
	if claims.Role != "admin" && claims.UserID != uid {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}
	if acc, exists := accountMap[uid]; exists {
		json.NewEncoder(w).Encode(map[string]float64{"balance": acc.Balance})
		return
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func depositBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Authorization check                    | v |
	2. Validation for Deposit Amount          | v |
	3. Lock objects to make synchronization   | v |
	*/
	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}
	
	// Part 1:
	if claims.UserID != body.UserID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Part 2:
	if body.Amount <= 0 {
		http.Error(w, "Amount must be greater than zero", http.StatusBadRequest)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Part 3:
	accountMutex.Lock()
	defer accountMutex.Unlock()

	if acc, exists := accountMap[body.UserID]; exists {
		acc.Balance += body.Amount
		accountMap[body.UserID] = acc  // Update the account in the map
		json.NewEncoder(w).Encode(acc) // Return the updated account
		return
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func withdrawBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Authorization check                      | v |
	2. Validation for Withdrawal Amount         | v |
	3. Lock objects to make synchronization     | v |
	*/
	var body struct {
		UserID int     `json:"user_id"`
		Amount float64 `json:"amount"`
	}

	// Part 1:
	if claims.UserID != body.UserID {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Part 2:
	if body.Amount <= 0 {
		http.Error(w, "Amount must be greater than zero", http.StatusBadRequest)
		return
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Part 3:
	accountMutex.Lock()
	defer accountMutex.Unlock()

	if acc, exists := accountMap[body.UserID]; exists {
		if acc.Balance < body.Amount {
			http.Error(w, ErrInsufficientFunds.Error(), http.StatusBadRequest)
			return
		}
		acc.Balance -= body.Amount
		accountMap[body.UserID] = acc // Update the account in the map
		json.NewEncoder(w).Encode(acc) // Return the updated account
		return
	}
	http.Error(w, "Account not found", http.StatusNotFound)
	
}

func Auth(next func(http.ResponseWriter, *http.Request, *Claims)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.Header.Get("Authorization")
		if tokenStr == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}
		tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r, claims)
	}
}
