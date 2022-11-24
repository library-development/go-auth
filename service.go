package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
)

type Service struct {
	Users       map[string]*User `json:"users"`
	InviteCodes map[string]bool  `json:"inviteCodes"`
	AdminID     string           `json:"adminId"`
	lock        sync.Mutex
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

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.lock.Lock()
		defer s.lock.Unlock()
		switch r.URL.Path {
		case "/cmd/admin/create-invite-code":
			var input struct {
				Email string `json:"email"`
				Code  string `json:"code"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			inviteToken, err := s.CreateInviteCode(input.Email, input.Code)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(inviteToken)
		case "/cmd/admin/remove-invite-code":
			var input struct {
				Email      string `json:"email"`
				Token      string `json:"token"`
				InviteCode string `json:"inviteCode"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			s.RemoveInviteCode(input.Email, input.Token, input.InviteCode)
		case "/cmd/user/sign-up":
			var input struct {
				Email      string `json:"email"`
				Password   string `json:"password"`
				InviteCode string `json:"inviteCode"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			token, err := s.SignUp(input.Email, input.Password, input.InviteCode)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(token)
		case "/cmd/user/sign-in":
			var input struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			token, err := s.SignIn(input.Email, input.Password)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(token)
		case "/cmd/user/sign-out":
			var input struct {
				Email string `json:"email"`
				Token string `json:"token"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			err := s.SignOut(input.Email, input.Token)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "/cmd/user/change-password":
			var input struct {
				Email    string `json:"email"`
				Token    string `json:"token"`
				Password string `json:"password"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			err := s.ChangePassword(input.Email, input.Token, input.Password)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "/cmd/admin/verify-token":
			var input struct {
				Email string `json:"email"`
				Token string `json:"token"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			ok := s.VerifyToken(input.Email, input.Token)
			json.NewEncoder(w).Encode(ok)
		}
	}
}
