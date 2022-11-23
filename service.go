package auth

import "github.com/schema-cafe/go-types/ui"

type Service struct {
	Users map[string]*ui.User
	Apps  map[string]*struct {
		ID           string
		PasswordHash string
		APIKeys      map[string]bool
	}
}

func (s *Service) SignIn(username, password string) (*ui.User, error) {
}
