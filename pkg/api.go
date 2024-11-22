package api_sec

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	UserID   int    `json:"user_id"` // For the getBalance Authorization check
	jwt.StandardClaims
}

/*
1. JWT Key Management        |   |
2. Add input validation      |   | >>> buffer overun -- הגבלה על אורך יוזרניים וסיסמא וכל אינפוט מהמשתמש
3. No HTTP Status Codes      |   |
4. ID Generation is simple, but accounts or users cannot be deleted. >>> לכתוב ברידמי
5. No Rate Limiting
6. Hash the passwords?       | v |
7. Make the search more efficient
*/

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
	for _, existingUser := range users {
		if existingUser.Username == user.Username {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
	}

	// Part 2: Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	user.Password = string(hashedPassword)

	// Add user to the list
	user.ID = len(users) + 1
	users = append(users, user)

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
	for _, user := range users {
		if user.Username == creds.Username {
			// Part 1: Remove the direct Password comparison
			if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password)); err == nil {
				authenticatedUser = &user
				break
			}
		}
	}
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
	2. Error Handling for Invalid Data        | v | --------------------------------------------
	3. Check if account already exists        | v |  ????????
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
	// // Part 2:
	// if acc.UserID <= 0 {
	// 	http.Error(w, "Invalid UserID: must be greater than 0", http.StatusBadRequest)
	// 	return
	// }
	// if acc.CreatedAt.IsZero() { // sanity about time - not created in the future
	// 	http.Error(w, "Invalid CreatedAt: timestamp cannot be empty", http.StatusBadRequest)
	// 	return
	// }

	// Part 3:
	for _, existingAccount := range accounts {
		if existingAccount.UserID == acc.UserID {
			http.Error(w, "Account already exists for this UserID", http.StatusConflict)
			return
		}
	}

	acc.ID = len(accounts) + 1
	acc.CreatedAt = time.Now()
	accounts = append(accounts, acc)
	json.NewEncoder(w).Encode(acc)
}

func listAccounts(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Authorization check                  | v |
	2. Error Handling for Empty accounts    | v |
	3. r *http.Request ?????????????????? -- must be get!!!!
	*/

	// Part 1:
	if claims.Role != "admin" {
		http.Error(w, "Unauthorized", http.StatusForbidden)
		return
	}

	// Part 2:
	if len(accounts) == 0 {
		http.Error(w, "No accounts found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(accounts)
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
	for _, acc := range accounts {
		if acc.UserID == uid {
			json.NewEncoder(w).Encode(map[string]float64{"balance": acc.Balance})
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func depositBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Authorization check              | v |
	2. Validation for Deposit Amount    | v |
	3. Lock objects to make synchronization ???? ------------------------------
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
	for i, acc := range accounts {
		if acc.UserID == body.UserID {
			accounts[i].Balance += body.Amount
			json.NewEncoder(w).Encode(accounts[i])
			return
		}
	}
	http.Error(w, "Account not found", http.StatusNotFound)
}

func withdrawBalance(w http.ResponseWriter, r *http.Request, claims *Claims) {
	/*
	1. Authorization check                 | v |
	2. Validation for Withdrawal Amount    | v |
	3. Lock objects to make synchronization ????
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
	for i, acc := range accounts {
		if acc.UserID == body.UserID {
			if acc.Balance < body.Amount {
				http.Error(w, ErrInsufficientFunds.Error(), http.StatusBadRequest)
				return
			}
			accounts[i].Balance -= body.Amount
			json.NewEncoder(w).Encode(accounts[i])
			return
		}
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
