package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"unicode"

	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"golang.org/x/crypto/bcrypt" //for the passwords

	//"github.com/gorilla/mux"

	"github.com/gorilla/securecookie"

	"github.com/dgrijalva/jwt-go"
)

// User : the user
type User struct {
	FirstName string
	LastName  string
	Email     string
	Password  string
}

// ErrorMessage : the message that is displaed under the main page
type ErrorMessage struct {
	ErrorMess string
}

var hashKey = []byte("very-secretvery-secret")
var blockKey = []byte("abcdefghijklmnop")
var s = securecookie.New(hashKey, blockKey)

func verifyPassword(password string) string {
	var uppercasePresent bool
	var lowercasePresent bool
	var numberPresent bool
	var specialCharPresent bool
	const minPassLength = 7
	const maxPassLength = 64
	var passLen int
	var errorString string

	for _, ch := range password {
		switch {
		case unicode.IsNumber(ch):
			numberPresent = true
			passLen++
		case unicode.IsUpper(ch):
			uppercasePresent = true
			passLen++
		case unicode.IsLower(ch):
			lowercasePresent = true
			passLen++
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			specialCharPresent = true
			passLen++
		case ch == ' ':
			passLen++
		}
	}
	// can use string buidler for efficiency
	if !lowercasePresent {
		errorString = "lowercase letter missing"
	}

	if !uppercasePresent {
		if len(errorString) == 0 {
			errorString = "uppercase letter missing"
		} else {
			errorString += " and uppercase letter missing"
		}
	}

	if !numberPresent {
		if len(errorString) == 0 {
			errorString = "atleast one numeric character required"
		} else {
			errorString += " and atleast one numeric character required"
		}
	}

	if !specialCharPresent {
		if len(errorString) == 0 {
			errorString = "special character missing"
		} else {
			errorString += " and special character missing"
		}
	}

	if !(minPassLength <= passLen && passLen <= maxPassLength) {
		if len(errorString) == 0 {
			errorString = fmt.Sprintf("password length must be between %d to %d characters long", minPassLength, maxPassLength)
		} else {
			errorString += " and " + fmt.Sprintf("password length must be between %d to %d characters long", minPassLength, maxPassLength)
		}
	}

	return errorString
}

func dealBadInfo(uemail string, upass string, cpass string, w http.ResponseWriter, path string) bool {

	t, _ := template.ParseFiles(path)

	if !strings.HasSuffix(uemail, ".edu") {
		fmt.Println("invalid email")
		//t, _ := template.ParseFiles("static/signupdatabase.html")
		mess := ErrorMessage{"Invalid Email Please Enter a School Email!"}
		t.Execute(w, mess)

		//using of the templates to access structs now works
		// t.Execute(w, template.HTML("Invalid Email Please Enter a School Email!"))
		return true
	}

	var passCheck = verifyPassword(upass)
	if len(passCheck) > 0 {
		fmt.Println("invalid password")
		//t, _ := template.ParseFiles("static/signupdatabase.html")
		mess := ErrorMessage{passCheck}
		t.Execute(w, mess)
		//t.Execute(w, template.HTML(passCheck))
		return true
	}

	if upass != cpass {
		fmt.Println("valid password but confirmation and entry do not match")
		//t, _ := template.ParseFiles("static/signupdatabase.html")
		mess := ErrorMessage{"Please Make Sure You Confirm Your Password Correctly"}
		t.Execute(w, mess)
		return true
	}
	return false
}

func signup(w http.ResponseWriter, r *http.Request) {
	fmt.Println("signup function")
	//mess := ErrorMessage{"testing 123 now"}

	fmt.Println("method:", r.Method) //get request method
	if r.Method == "GET" {
		t, _ := template.ParseFiles("static/signupdatabase.html")
		t.Execute(w, nil)
		//fmt.Println("shouldve worked")
		//until a post method is recieved just keep the same page
	} else {
		r.ParseForm()
		// logic part of log in
		var firster = r.Form["firstName"][0]
		var laster = r.Form["lastName"][0]
		var uemail = r.Form["email"][0]
		var upass = r.Form["password"][0]
		var cpass = r.Form["confPassword"][0]

		t, _ := template.ParseFiles("static/signupdatabase.html")

		filter := bson.D{{Key: "email", Value: uemail}}
		var result User

		eror := collection.FindOne(context.TODO(), filter).Decode(&result)
		//decode takes the found data point and puts it into value

		if eror == nil { // therefore it did find an email on file
			//log.Fatal(eror)
			mess := ErrorMessage{"There is already an account registered to this email "}
			t.Execute(w, mess)
			return
		}

		var ok = dealBadInfo(uemail, upass, cpass, w, "static/signupdatabase.html")
		if ok {
			fmt.Println("improper sign up")
			return
		}

		// Use GenerateFromPassword to hash & salt pwd.
		// MinCost is just an integer constant provided by the bcrypt
		// package along with DefaultCost & MaxCost.
		// The cost can be any value you want provided it isn't lower
		// than the MinCost (4)
		uupass := []byte(upass)
		hash, err := bcrypt.GenerateFromPassword(uupass, bcrypt.MinCost)
		if err != nil {
			log.Println(err)
		}
		// GenerateFromPassword returns a byte slice so we need to
		// convert the bytes to a string and return it
		salt := string(hash)

		fmt.Println("email:", r.Form["email"])
		fmt.Println("password:", r.Form["password"])
		fmt.Println("salted password:", salt)

		ash := User{firster, laster, uemail, salt} // only storing salted password
		insertResult, err := collection.InsertOne(context.TODO(), ash)
		fmt.Println(ash)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("Inserted a single document: ", insertResult.InsertedID)

		expirationTime := time.Now().Add(5 * time.Minute)
		claims := &Claims{
			Email: uemail,
			StandardClaims: jwt.StandardClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: expirationTime.Unix(),
			},
			Name: firster,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			// If there is an error in creating the JWT return an internal server error
			fmt.Println("Error with JWT token!")
			return
		}
		SetCookieHandler(w, r, tokenString)

		//mess := ErrorMessage{"Sign Up Successful"}
		fmt.Println("switching to welcome from sign...")
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
		// welcome
	}
}

func comparePasswords(hashedPwd string, plainPwd string) bool {
	// Since we'll be getting the hashed password from the DB it
	// will be a string so we'll need to convert it to a byte slice
	byteHash := []byte(hashedPwd)
	plain := []byte(plainPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, plain)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("login function")
	fmt.Println("method:", r.Method) //get request method

	if r.Method == "GET" {
		t, _ := template.ParseFiles("static/logindatabase.html")
		t.Execute(w, nil)
		//fmt.Println("shouldve worked")
		//until a post method is recieved just keep the same page
	} else {
		r.ParseForm()
		// logic part of log in

		var uemail = r.Form["email"][0]
		var upass = r.Form["password"][0]

		fmt.Println("attempting to log.....")
		t, _ := template.ParseFiles("static/logindatabase.html")

		//MongoDB logging in
		//filter := bson.D{{"email", uemail},{"passlsword",upass}}
		filter := bson.D{{Key: "email", Value: uemail}}
		var result User

		eror := collection.FindOne(context.TODO(), filter).Decode(&result)
		if eror != nil {
			//there is no account with the given email
			mess := ErrorMessage{"There is no account registered to that email please Sign Up"}
			fmt.Println("Log Failed: attempting to sign up.....")
			t, _ := template.ParseFiles("static/signupdatabase.html")
			t.Execute(w, mess)
			return
		}

		fmt.Printf("Found a single document: %+v\n", result)
		fmt.Println("email:", r.Form["email"])
		fmt.Println("password:", r.Form["password"])

		salted := result.Password //  decoded in the compare function

		if !comparePasswords(salted, upass) {
			mess := ErrorMessage{"Error: Password does not match"}
			t.Execute(w, mess)
			return
		}

		fmt.Println("loging in.....")

		expirationTime := time.Now().Add(5 * time.Minute)
		claims := &Claims{
			Email: uemail,
			StandardClaims: jwt.StandardClaims{
				// In JWT, the expiry time is expressed as unix milliseconds
				ExpiresAt: expirationTime.Unix(),
			},
			Name: result.FirstName,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			// If there is an error in creating the JWT return an internal server error
			fmt.Println("Error with JWT token!")
			return
		}
		SetCookieHandler(w, r, tokenString)

		cooks := ReadCookieHandler(w, r)

		fmt.Println(cooks)
		fmt.Println("completed cookie check in")
		//mess := ErrorMessage{"cookie has been confirmed"}
		//uData = Tdata{result, mess}
		// t, _ = template.ParseFiles("static/welcome.html")
		// t.Execute(w, td)
		fmt.Println("switching to welcome from log...")
		http.Redirect(w, r, "/welcome", http.StatusSeeOther)

		//FIGURE OUT HOW TO SEND OVER RETRIVED USER TO THE WELCOME PAGE
		// ALSO FIGURE OUT HOW TO SEND MULTIPLE DATAS IN THE TEMPLE USING THE T.EXECUTE
	}
}
func switchtosign(w http.ResponseWriter, r *http.Request) {
	fmt.Println("switching to sign.....")
	// t, _ := template.ParseFiles("static/signupdatabase.html")
	// t.Execute(w, nil)
	http.Redirect(w, r, "/signup", http.StatusSeeOther)
}
func switchtolog(w http.ResponseWriter, r *http.Request) {
	fmt.Println("switching to log.....")
	// t, _ := template.ParseFiles("static/logindatabase.html")
	// t.Execute(w, nil)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
