package auth

type User struct {
	PasswordHash string          `json:"passwordHash"`
	Tokens       map[string]bool `json:"tokens"`
}
