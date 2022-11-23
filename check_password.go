package auth

import (
	"golang.org/x/crypto/bcrypt"
)

func CheckPassword(password, hash string) bool {
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return false
	}
	return true
}
