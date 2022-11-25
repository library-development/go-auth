package auth

type Client struct {
	Endpoint string `json:"endpoint"`
	UserID   string `json:"userId"`
	Token    string `json:"token"`
}

// func (c *Client) AddInviteToken() (string, error) {
// }
