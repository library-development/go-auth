package auth

import (
	"encoding/json"
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

func (s *Service) UserID(creds *Credentials) string {
	user, ok := s.Users[creds.Email]
	if !ok {
		return ""
	}
	if !user.Tokens[creds.Token] {
		return ""
	}
	return creds.Email
}

func (s *Service) IsAdmin(creds *Credentials) bool {
	return s.UserID(creds) == s.AdminID
}

func (s *Service) CreateInviteCode(creds *Credentials) (string, error) {
	if !s.IsAdmin(creds) {
		return "", fmt.Errorf("not authorized")
	}

	t := GenerateRandomToken()
	s.InviteCodes[t] = true
	return t, nil
}

func (s *Service) RemoveInviteCode(creds *Credentials, inviteCode string) error {
	if !s.IsAdmin(creds) {
		return fmt.Errorf("not authorized")
	}

	delete(s.InviteCodes, inviteCode)
	return nil
}

func (s *Service) SignUp(email, password, inviteCode string) (string, error) {
	if !s.InviteCodes[inviteCode] {
		return "", fmt.Errorf("invalid invite code")
	}
	if _, ok := s.Users[email]; ok {
		return "", fmt.Errorf("email already registered")
	}
	if err := ValidatePassword(password); err != nil {
		return "", fmt.Errorf("password not strong enough: %s", err)
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
	if !ok || !CheckPassword(password, user.PasswordHash) {
		return "", fmt.Errorf("wrong username or password")
	}
	token := GenerateRandomToken()
	user.Tokens[token] = true
	return token, nil
}

func (s *Service) SignOut(creds *Credentials) error {
	userID := s.UserID(creds)
	if userID == "" {
		return fmt.Errorf("not authorized")
	}
	delete(s.Users[userID].Tokens, creds.Token)
	return nil
}

func (s *Service) ChangePassword(creds *Credentials, password string) error {
	userID := s.UserID(creds)
	if userID == "" {
		return fmt.Errorf("not authorized")
	}
	if err := ValidatePassword(password); err != nil {
		return fmt.Errorf("password not strong enough: %s", err)
	}

	s.Users[userID].PasswordHash = HashPassword(password)
	return nil
}

func (s *Service) VerifyToken(creds *Credentials) bool {
	return s.UserID(creds) != ""
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.lock.Lock()
		defer s.lock.Unlock()
		switch r.URL.Path {
		case "/admin/create-invite-code":
			var input struct {
				Auth *Credentials `json:"auth"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			inviteToken, err := s.CreateInviteCode(input.Auth)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(inviteToken)
		case "/admin/remove-invite-code":
			var input struct {
				Auth       *Credentials `json:"auth"`
				InviteCode string       `json:"inviteCode"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			err := s.RemoveInviteCode(input.Auth, input.InviteCode)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "/sign-up":
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
		case "/sign-in":
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
		case "/sign-out":
			var input struct {
				Auth *Credentials `json:"auth"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			err := s.SignOut(input.Auth)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "/change-password":
			var input struct {
				Auth     *Credentials `json:"auth"`
				Password string       `json:"password"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			err := s.ChangePassword(input.Auth, input.Password)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		case "/admin/verify-token":
			var input struct {
				Auth *Credentials `json:"auth"`
			}
			json.NewDecoder(r.Body).Decode(&input)
			ok := s.VerifyToken(input.Auth)
			json.NewEncoder(w).Encode(ok)
		}
	}
}
