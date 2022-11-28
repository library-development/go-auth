package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Client struct {
	Endpoint string `json:"endpoint"`
	UserID   string `json:"userId"`
	Token    string `json:"token"`
}

func (c *Client) VerifyToken(creds *Credentials) (bool, error) {
	b, err := json.Marshal(VerifyTokenRequest{
		Auth:  &Credentials{Email: c.UserID, Token: c.Token},
		Creds: creds,
	})
	if err != nil {
		return false, err
	}
	body := bytes.NewReader(b)
	res, err := http.Post(c.Endpoint+"/admin/verify-token", "application/json", body)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return false, fmt.Errorf("invalid status code: %d", res.StatusCode)
	}
	var valid bool
	if err := json.NewDecoder(res.Body).Decode(&valid); err != nil {
		return false, err
	}
	return valid, nil
}
