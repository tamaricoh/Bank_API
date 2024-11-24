# Security Enhancements in `api.go`

## Overview of the Changes

Below are the main changes implemented in the `api.go` file to enhance security and address potential vulnerabilities. In addition, the code is accompanied by comments that highlight the changes I made.

### 1. **Prevented Empty Fields During Registration**

- **Problem**: The previous implementation allowed users to register without validating if the username, password, or role was empty, which could lead to invalid entries.
- **Solution**: Added validation to ensure `username`, `password`, and `role` are non-empty. For instance:
  ```go
  if strings.TrimSpace(user.Username) == "" || strings.TrimSpace(user.Password) == "" {
      handleError(w, r, "Username and password must not be empty", http.StatusBadRequest)
      return
  }
  ```

---

### 2. **Restricted Username and Password Length**

- **Problem**: The lack of length restrictions on `username` and `password` allowed overly long inputs, which could lead to buffer overflows or resource exhaustion.
- **Solution**: Introduced checks to limit `username` and `password` to a maximum of 16 characters.

  ```go
  if len(user.Username) > 16 || len(user.Password) > 16 {
      handleError(w, r, "Username and password must not exceed 16 characters", http.StatusBadRequest)
      return
  }
  ```

  - Next step will be to find where a buffer overrun can occure

---

### 3. **Unique Username Enforcement**

- **Problem**: The system allowed duplicate usernames, leading to ambiguity and potential user impersonation.
- **Solution**: Checked for existing usernames before registering a new user.
  ```go
  if _, exists := users[user.Username]; exists {
      handleError(w, r, "Username already exists", http.StatusConflict)
      return
  }
  ```

---

### 4. **Password Hashing**

- **Problem**: Storing plaintext passwords poses a severe security risk if the database is compromised.
- **Solution**: Integrated bcrypt hashing for passwords during registration.
  ```go
  hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
  if err != nil {
      handleError(w, r, "Internal Server Error", http.StatusInternalServerError)
      return
  }
  user.Password = string(hashedPassword)
  ```

---

### 5. **Excluding Sensitive Data in Responses**

- **Problem**: The API response included sensitive data such as passwords, which could be exploited.
- **Solution**: Updated the API to exclude passwords from the response.
  ```go
  response := struct {
      ID       int    `json:"id"`
      Username string `json:"username"`
      Role     string `json:"role"`
  }{
      ID:       user.ID,
      Username: user.Username,
      Role:     user.Role,
  }
  ```

---

### 6. Implemented Locking Mechanism for Deposit Operations

- **Problem**: Concurrent deposit operations on the same account could lead to inconsistent balance updates.
- **Solution**: Added a locking mechanism to ensure only one deposit operation can be processed at a time on the same account:

```go
    accountMutex.Lock()
	defer accountMutex.Unlock()
```

---

### 7. Efficient User and Account Search with Map

### Changes Made

- Replaced the `[]User` slice with a `map[string]User` for faster username lookups.
- This change improves search efficiency from O(n) to O(1) average time complexity.

### Code Before:

```go
var users []User
for _, user := range users {
	if user.Username == creds.Username && user.Password == creds.Password {
		authenticatedUser = &user
		break
	}
}
```

### Code After Optimization

```go
var users = make(map[string]User)
if _, exists := users[user.Username]; exists {
	handleError(w, r, "Username already exists", http.StatusConflict)
	return
}
```

## Next steps

1. **Generate a more complex ID:** The current ID generation method is too straightforward and needs to be improved for better uniqueness and security.

2. **Improve locking mechanism:** The current locking system allows one user's lock to block others. This needs to be refined to prevent such conflicts and ensure better concurrency.

3. **Refactor validation logic:** Manually written validations should be replaced with existing packages that provide these checks in a more efficient and standardized way.

4. **Restrict admin registration:** Currently, anyone can register as an admin. This should be restricted to certain criteria or roles.

5. **Implement logout functionality:** A logout feature needs to be implemented to ensure users can end their sessions securely.

6. **Handle multiple logins properly:** Currently, users can log in multiple times without restrictions. This behavior needs to be controlled or adjusted based on security requirements.
