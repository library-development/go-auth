package main

import (
	"encoding/json"
	"net/http"
	"os"
	"sync"

	"github.com/library-development/go-auth"
	"github.com/library-development/go-web"
)

var db auth.Service
var dataFile string

func init() {
	dataFile = os.Getenv("DATA_FILE")
	if dataFile == "" {
		panic("DATA_FILE environment variable not set")
	}
	b, err := os.ReadFile(dataFile)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(b, &db)
	if err != nil {
		panic(err)
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		panic("PORT environment variable not set")
	}

	lock := sync.Mutex{}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		web.HandleCORS(w, r)
		if r.Method == http.MethodPost {
			lock.Lock()
			defer lock.Unlock()
			switch r.URL.Path {
			case "/cmd/admin/add-invite-token":
				var input struct {
					Email    string `json:"email"`
					Password string `json:"password"`
				}
				json.NewDecoder(r.Body).Decode(&input)
				token, err := db.AddInviteToken(input.Email, input.Password)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				json.NewEncoder(w).Encode(token)
			case "/cmd/admin/remove-invite-token":
				var input struct {
					Email       string `json:"email"`
					Password    string `json:"password"`
					InviteToken string `json:"inviteToken"`
				}
				json.NewDecoder(r.Body).Decode(&input)
				db.RemoveInviteToken(input.Email, input.Password, input.InviteToken)
			case "/cmd/user/sign-up":
				var input struct {
					Email       string `json:"email"`
					Password    string `json:"password"`
					InviteToken string `json:"inviteToken"`
				}
				json.NewDecoder(r.Body).Decode(&input)
				token, err := db.SignUp(input.Email, input.Password, input.InviteToken)
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
				token, err := db.SignIn(input.Email, input.Password)
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
				err := db.SignOut(input.Email, input.Token)
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
				err := db.ChangePassword(input.Email, input.Token, input.Password)
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
				ok := db.VerifyToken(input.Email, input.Token)
				json.NewEncoder(w).Encode(ok)
			}

			b, err := json.Marshal(db)
			if err != nil {
				panic(err)
			}
			err = os.WriteFile(dataFile, b, 0644)
			if err != nil {
				panic(err)
			}
		}
	})

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		panic(err)
	}
}
