package main

import (
	"fmt"
	"html/template"
	"net/http"

	//for the passwords

	//"github.com/gorilla/mux"

	"github.com/dgrijalva/jwt-go"
)

// Tdata : Execute data structure
type Tdata struct {
	Name      string
	ErrorMess ErrorMessage
}

func welcome(w http.ResponseWriter, r *http.Request) {
	fmt.Println(" welcome method:", r.Method)
	if r.Method == "GET" {
		// Get the JWT string from the cookie
		tknStr := ReadCookieHandler(w, r)

		fmt.Println("Token String: ", tknStr)

		// Initialize a new instance of `Claims`
		claims := &Claims{}

		// Parse the JWT string and store the result in `claims`.
		// Note that we are passing the key in this method as well. This method will return an error
		// if the token is invalid (if it has expired according to the expiry time we set on sign in),
		// or if the signature does not match
		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil {
			fmt.Println("Error in the Welcome opening of the JWT")
			fmt.Println(err)
			switchtolog(w, r)
			return
		}
		if !tkn.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			fmt.Println("Redirecting to Log in since token expired")
			switchtolog(w, r)
			return
		}

		t, _ := template.ParseFiles("static/welcome.html")
		// t, _ := template.ParseFiles("static/chat.html")
		fmt.Println("mess")
		// fmt.Println("about to refresh")

		// refreshJWT(w, r)
		mess := ErrorMessage{"welcoming test"}
		td := Tdata{claims.Name, mess}
		fmt.Println("Welcome!")

		// t.Execute(w, td)
		t.Execute(w, td)

	}

}
