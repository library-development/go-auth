package auth

import "errors"

func ValidatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("must be at least 8 characters")
	}
	return nil
}
