package main

import (
	"encoding/json"
	"net/http"
	"os"

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		web.HandleCORS(w, r)
		db.ServeHTTP(w, r)
		if r.Method == http.MethodPost {
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
