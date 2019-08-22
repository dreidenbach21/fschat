package main

import (
	"fmt"
	"net/http"

	"time"

	//for the passwords

	//"github.com/gorilla/mux"

	"github.com/dgrijalva/jwt-go"
)

// Claims : the body that will hold the data for the JWT
type Claims struct {
	Email string //`json:"email"`
	jwt.StandardClaims
	Name string // this is for the welcome page
}

var jwtKey = []byte("my_secret_key") //this is for the JWT
// SetCookieHandler : sets the secure cookies with the JWT secure string
func SetCookieHandler(w http.ResponseWriter, r *http.Request, val string) {
	encoded, err := s.Encode("cookie-name", val)
	if err == nil {
		cookie := &http.Cookie{
			Name:  "cookie-name",
			Value: encoded, // see first line for what is to be enconded
			Path:  "/",
		}
		http.SetCookie(w, cookie)
		fmt.Println(cookie.Value)
		fmt.Println("cookie value above set")
	} else {
		fmt.Println("Error: ")
		fmt.Println(err)
	}
}

//You could then read this cookie by using the same SecureCookie object in another handler.

// ReadCookieHandler : reads cookies
func ReadCookieHandler(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie("cookie-name"); err == nil {
		var value string
		if err = s.Decode("cookie-name", cookie.Value, &value); err == nil {
			fmt.Println(value)
			fmt.Println("cookie value above read")
			return value
		}
	} else {
		fmt.Println("Error!!!!!!!!!!!!!")
		fmt.Println(err)
	}
	return ""
}

func refreshJWT(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Refreshing...")
	fmt.Println("")
	tknStr := ReadCookieHandler(w, r)
	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	fmt.Println(claims)
	if !tkn.Valid {
		fmt.Println("JWT is not valid")
		return
	}
	if err != nil {
		fmt.Println("Error: ")
		fmt.Println(err)
		return
	}

	// We ensure that a new token is not issued until enough time has elapsed
	// In this case, a new token will only be issued if the old token is within
	// 30 seconds of expiry. Otherwise, return a bad request status
	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
		fmt.Println("Still got Time brother")
		return
	}

	// Now, create a new token for the current use, with a renewed expiration time
	expirationTime := time.Now().Add(5 * time.Minute)
	fmt.Println("the new exp time: ")
	fmt.Println(expirationTime)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set the new token as the users `token` cookie
	SetCookieHandler(w, r, tokenString)
	fmt.Println("Refreshed")
}

func getName(w http.ResponseWriter, r *http.Request) string {
	// mess := r.Form["message"][0]

	tknStr := ReadCookieHandler(w, r)
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
		return ""
	}
	if !tkn.Valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		fmt.Println("Redirecting to Log in since token expired")
		switchtolog(w, r)
		return ""
	}

	name := claims.Name
	name += ": "

	// byteName := []byte(name)

	// _ = byteName
	fmt.Println(name)
	return name

}

func getEmail(w http.ResponseWriter, r *http.Request) string {
	// mess := r.Form["message"][0]

	tknStr := ReadCookieHandler(w, r)
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
		return ""
	}
	if !tkn.Valid {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		fmt.Println("Redirecting to Log in since token expired")
		switchtolog(w, r)
		return ""
	}

	name := claims.Email

	// byteName := []byte(name)

	// _ = byteName

	return name

}
