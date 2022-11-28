package auth

type VerifyTokenRequest struct {
	Auth  *Credentials `json:"auth"`
	Creds *Credentials `json:"creds"`
}
