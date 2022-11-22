package auth

import "github.com/schema-cafe/go-types/ui"

type Service struct {
	Users map[string]*ui.User
}

func (s *Service) SignIn(username, password string) (*ui.User, error) {
	if user, ok := s.Users[username]; ok {
		if user.Password == password {
			return user, nil
		}
	}

	return nil, ErrInvalidCredentials
}
