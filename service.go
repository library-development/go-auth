package auth

import (
	"errors"
	"fmt"
)

type Service struct {
	Users       map[string]*User `json:"users"`
	InviteCodes map[string]bool  `json:"inviteCodes"`
	AdminID     string           `json:"adminId"`
}

type User struct {
	PasswordHash string          `json:"passwordHash"`
	Tokens       map[string]bool `json:"tokens"`
}

func (s *Service) CreateInviteCode(email, token string) (string, error) {
	if email != s.AdminID {
		return "", errors.New("unauthorized")
	}
	if !s.VerifyToken(email, token) {
		return "", errors.New("unauthorized")
	}
	t := GenerateRandomToken()
	s.InviteCodes[t] = true
	return t, nil
}

func (s *Service) RemoveInviteCode(email, token, inviteCode string) error {
	if email != s.AdminID {
		return errors.New("unauthorized")
	}
	if !s.VerifyToken(email, token) {
		return errors.New("unauthorized")
	}
	delete(s.InviteCodes, inviteCode)
	return nil
}

func (s *Service) SignUp(email, password, inviteCode string) (string, error) {
	if !s.InviteCodes[inviteCode] {
		return "", errors.New("invalid invite code")
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

	delete(s.InviteCodes, inviteCode)

	return token, nil
}

func (s *Service) SignIn(email, password string) (string, error) {
	user, ok := s.Users[email]
	if !ok {
		return "", errors.New("email not registered")
	}
	if !CheckPassword(password, user.PasswordHash) {
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
