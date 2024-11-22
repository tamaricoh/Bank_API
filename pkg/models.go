package api_sec

import (
	"errors"
	"time"
)

type User struct {
	ID       int
	Username string
	Password string
	Role     string // "admin" or "user"
}

type Account struct {
	ID        int
	UserID    int
	Balance   float64
	CreatedAt time.Time
}

var users []User
var accounts []Account

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrAccountNotFound   = errors.New("account not found")
	ErrInsufficientFunds = errors.New("insufficient funds")
)
