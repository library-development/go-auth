package auth

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

type Service struct {
	Users        map[string]*User `json:"users"`
	InviteTokens map[string]bool  `json:"inviteTokens"`
}

type User struct {
	PasswordHash string          `json:"passwordHash"`
	Tokens       map[string]bool `json:"tokens"`
}

func (s *Service) AddInviteToken() string {
	token := GenerateRandomToken()
	s.InviteTokens[token] = true
	return token
}

func (s *Service) RemoveInviteToken(token string) {
	delete(s.InviteTokens, token)
}

func (s *Service) SignUp(email, password, inviteToken string) (string, error) {
	if !s.InviteTokens[inviteToken] {
		return "", errors.New("invalid invite token")
	}
	if _, ok := s.Users[email]; ok {
		return "", fmt.Errorf("email already registered")
	}
	if err := ValidatePassword(password); err != nil {
		return "", err
	}

	passwordHash := HashPassword(password)
	token := GenerateRandomToken()
	s.Users[email] = &User{
		PasswordHash: passwordHash,
		Tokens: map[string]bool{
			token: true,
		},
	}

	delete(s.InviteTokens, inviteToken)

	return token, nil
}

func (s *Service) SignIn(email, password string) (string, error) {
	user, ok := s.Users[email]
	if !ok {
		return "", errors.New("email not registered")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", errors.New("wrong password")
	}
	token := GenerateRandomToken()
	user.Tokens[token] = true
	return token, nil
}

func (s *Service) SignOut(email, token string) error {
	user, ok := s.Users[email]
	if !ok {
		return errors.New("email not registered")
	}
	if !user.Tokens[token] {
		return errors.New("invalid token")
	}
	delete(user.Tokens, token)
	return nil
}

func (s *Service) ChangePassword(email, token, password string) error {
	user, ok := s.Users[email]
	if !ok {
		return errors.New("email not registered")
	}
	if !user.Tokens[token] {
		return errors.New("invalid token")
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	user.PasswordHash = HashPassword(password)
	return nil
}

func (s *Service) VerifyToken(email, token string) bool {
	user, ok := s.Users[email]
	if !ok {
		return false
	}
	if !user.Tokens[token] {
		return false
	}
	return true
}
