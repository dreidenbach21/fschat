package main

import (
	"log"
	"net/http"
	//for the passwords
	//"github.com/gorilla/mux"
)

// var mapp map[string]User

func main() {

	// mapp = make(map[string]User)

	indianGrey := mongose()

	collection = indianGrey.Database("Data").Collection("Information")

	fs := http.FileServer(http.Dir("./static"))

	//router := mux.NewRouter()

	//Stylesheet not loaded because of MIME-type when using the mux router
	//https://stackoverflow.com/questions/39585208/error-rendering-mime-types-of-assets-in-golang-server

	//hubby := newHub()
	//for hub and connection

	http.Handle("/", fs)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/login", login)
	http.HandleFunc("/refresh", refreshJWT)
	http.HandleFunc("/welcome", welcome)

	// using a MUX to get 2 /log and /sign
	// these never will appear jsut use to re route
	http.HandleFunc("/switchtosign", switchtosign)
	http.HandleFunc("/switchtolog", switchtolog)

	log.Println("Listening...")

	http.HandleFunc("/ws", handleConnections)
	go handleMessages()

	http.ListenAndServe(":8070", nil)
}

// // Tdata : Execute data structure
// type Tdata struct {
// 	Name      string
// 	ErrorMess ErrorMessage
// }

// // User : the user
// type User struct {
// 	FirstName string
// 	LastName  string
// 	Email     string
// 	Password  string
// }

// // ErrorMessage : the message that is displaed under the main page
// type ErrorMessage struct {
// 	ErrorMess string
// }

// // Claims : the body that will hold the data for the JWT
// type Claims struct {
// 	Email string //`json:"email"`
// 	jwt.StandardClaims
// 	Name string // this is for the welcome page
// }

// global variables

// var collection *mongo.Collection

// var hashKey = []byte("very-secretvery-secret")
// var blockKey = []byte("abcdefghijklmnop")
// var s = securecookie.New(hashKey, blockKey)

// encoding and decoding cookies works

// var jwtKey = []byte("my_secret_key") //this is for the JWT

// var activeUsers = make(map[string]*websocket.Conn)
// var clients = make(map[*websocket.Conn]bool) // connected clients
// var broadcast = make(chan Message)           // broadcast channel
// var upgrader = websocket.Upgrader{}

// // Message : messages
// type Message struct {
// 	// Name    string `json:"name"`
// 	Message string `json:"message"`
// }

// SetCookieHandler : sets cookies
// func SetCookieHandler(w http.ResponseWriter, r *http.Request, val string) {
// 	encoded, err := s.Encode("cookie-name", val)
// 	if err == nil {
// 		cookie := &http.Cookie{
// 			Name:  "cookie-name",
// 			Value: encoded, // see first line for what is to be enconded
// 			Path:  "/",
// 		}
// 		http.SetCookie(w, cookie)
// 		fmt.Println(cookie.Value)
// 		fmt.Println("cookie value above set")
// 	} else {
// 		fmt.Println("Error: ")
// 		fmt.Println(err)
// 	}
// }

// //You could then read this cookie by using the same SecureCookie object in another handler.

// // ReadCookieHandler : reads cookies
// func ReadCookieHandler(w http.ResponseWriter, r *http.Request) string {
// 	if cookie, err := r.Cookie("cookie-name"); err == nil {
// 		var value string
// 		if err = s.Decode("cookie-name", cookie.Value, &value); err == nil {
// 			fmt.Println(value)
// 			fmt.Println("cookie value above read")
// 			return value
// 		}
// 	} else {
// 		fmt.Println("Error!!!!!!!!!!!!!")
// 		fmt.Println(err)
// 	}
// 	return ""
// }

// func verifyPassword(password string) string {
// 	var uppercasePresent bool
// 	var lowercasePresent bool
// 	var numberPresent bool
// 	var specialCharPresent bool
// 	const minPassLength = 7
// 	const maxPassLength = 64
// 	var passLen int
// 	var errorString string

// 	for _, ch := range password {
// 		switch {
// 		case unicode.IsNumber(ch):
// 			numberPresent = true
// 			passLen++
// 		case unicode.IsUpper(ch):
// 			uppercasePresent = true
// 			passLen++
// 		case unicode.IsLower(ch):
// 			lowercasePresent = true
// 			passLen++
// 		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
// 			specialCharPresent = true
// 			passLen++
// 		case ch == ' ':
// 			passLen++
// 		}
// 	}
// 	// can use string buidler for efficiency
// 	if !lowercasePresent {
// 		errorString = "lowercase letter missing"
// 	}

// 	if !uppercasePresent {
// 		if len(errorString) == 0 {
// 			errorString = "uppercase letter missing"
// 		} else {
// 			errorString += " and uppercase letter missing"
// 		}
// 	}

// 	if !numberPresent {
// 		if len(errorString) == 0 {
// 			errorString = "atleast one numeric character required"
// 		} else {
// 			errorString += " and atleast one numeric character required"
// 		}
// 	}

// 	if !specialCharPresent {
// 		if len(errorString) == 0 {
// 			errorString = "special character missing"
// 		} else {
// 			errorString += " and special character missing"
// 		}
// 	}

// 	if !(minPassLength <= passLen && passLen <= maxPassLength) {
// 		if len(errorString) == 0 {
// 			errorString = fmt.Sprintf("password length must be between %d to %d characters long", minPassLength, maxPassLength)
// 		} else {
// 			errorString += " and " + fmt.Sprintf("password length must be between %d to %d characters long", minPassLength, maxPassLength)
// 		}
// 	}

// 	return errorString
// }

// func dealBadInfo(uemail string, upass string, cpass string, w http.ResponseWriter, path string) bool {

// 	t, _ := template.ParseFiles(path)

// 	if !strings.HasSuffix(uemail, ".edu") {
// 		fmt.Println("invalid email")
// 		//t, _ := template.ParseFiles("static/signupdatabase.html")
// 		mess := ErrorMessage{"Invalid Email Please Enter a School Email!"}
// 		t.Execute(w, mess)

// 		//using of the templates to access structs now works
// 		// t.Execute(w, template.HTML("Invalid Email Please Enter a School Email!"))
// 		return true
// 	}

// 	var passCheck = verifyPassword(upass)
// 	if len(passCheck) > 0 {
// 		fmt.Println("invalid password")
// 		//t, _ := template.ParseFiles("static/signupdatabase.html")
// 		mess := ErrorMessage{passCheck}
// 		t.Execute(w, mess)
// 		//t.Execute(w, template.HTML(passCheck))
// 		return true
// 	}

// 	if upass != cpass {
// 		fmt.Println("valid password but confirmation and entry do not match")
// 		//t, _ := template.ParseFiles("static/signupdatabase.html")
// 		mess := ErrorMessage{"Please Make Sure You Confirm Your Password Correctly"}
// 		t.Execute(w, mess)
// 		return true
// 	}
// 	return false
// }

// func signup(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("signup function")
// 	//mess := ErrorMessage{"testing 123 now"}

// 	fmt.Println("method:", r.Method) //get request method
// 	if r.Method == "GET" {
// 		t, _ := template.ParseFiles("static/signupdatabase.html")
// 		t.Execute(w, nil)
// 		//fmt.Println("shouldve worked")
// 		//until a post method is recieved just keep the same page
// 	} else {
// 		r.ParseForm()
// 		// logic part of log in
// 		var firster = r.Form["firstName"][0]
// 		var laster = r.Form["lastName"][0]
// 		var uemail = r.Form["email"][0]
// 		var upass = r.Form["password"][0]
// 		var cpass = r.Form["confPassword"][0]

// 		t, _ := template.ParseFiles("static/signupdatabase.html")

// 		filter := bson.D{{Key: "email", Value: uemail}}
// 		var result User

// 		eror := collection.FindOne(context.TODO(), filter).Decode(&result)
// 		//decode takes the found data point and puts it into value

// 		if eror == nil { // therefore it did find an email on file
// 			//log.Fatal(eror)
// 			mess := ErrorMessage{"There is already an account registered to this email "}
// 			t.Execute(w, mess)
// 			return
// 		}

// 		var ok = dealBadInfo(uemail, upass, cpass, w, "static/signupdatabase.html")
// 		if ok {
// 			fmt.Println("improper sign up")
// 			return
// 		}

// 		// Use GenerateFromPassword to hash & salt pwd.
// 		// MinCost is just an integer constant provided by the bcrypt
// 		// package along with DefaultCost & MaxCost.
// 		// The cost can be any value you want provided it isn't lower
// 		// than the MinCost (4)
// 		uupass := []byte(upass)
// 		hash, err := bcrypt.GenerateFromPassword(uupass, bcrypt.MinCost)
// 		if err != nil {
// 			log.Println(err)
// 		}
// 		// GenerateFromPassword returns a byte slice so we need to
// 		// convert the bytes to a string and return it
// 		salt := string(hash)

// 		fmt.Println("email:", r.Form["email"])
// 		fmt.Println("password:", r.Form["password"])
// 		fmt.Println("salted password:", salt)

// 		ash := User{firster, laster, uemail, salt} // only storing salted password
// 		insertResult, err := collection.InsertOne(context.TODO(), ash)
// 		fmt.Println(ash)
// 		if err != nil {
// 			log.Fatal(err)
// 		}

// 		fmt.Println("Inserted a single document: ", insertResult.InsertedID)

// 		expirationTime := time.Now().Add(5 * time.Minute)
// 		claims := &Claims{
// 			Email: uemail,
// 			StandardClaims: jwt.StandardClaims{
// 				// In JWT, the expiry time is expressed as unix milliseconds
// 				ExpiresAt: expirationTime.Unix(),
// 			},
// 			Name: firster,
// 		}
// 		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

// 		tokenString, err := token.SignedString(jwtKey)
// 		if err != nil {
// 			// If there is an error in creating the JWT return an internal server error
// 			fmt.Println("Error with JWT token!")
// 			return
// 		}
// 		SetCookieHandler(w, r, tokenString)

// 		//mess := ErrorMessage{"Sign Up Successful"}
// 		fmt.Println("switching to welcome from sign...")
// 		http.Redirect(w, r, "/welcome", http.StatusSeeOther)
// 		// welcome
// 	}
// }

// func comparePasswords(hashedPwd string, plainPwd string) bool {
// 	// Since we'll be getting the hashed password from the DB it
// 	// will be a string so we'll need to convert it to a byte slice
// 	byteHash := []byte(hashedPwd)
// 	plain := []byte(plainPwd)
// 	err := bcrypt.CompareHashAndPassword(byteHash, plain)
// 	if err != nil {
// 		log.Println(err)
// 		return false
// 	}

// 	return true
// }

// Welcome : handling the home page
// func welcome(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println(" welcome method:", r.Method)
// 	if r.Method == "GET" {
// 		// Get the JWT string from the cookie
// 		tknStr := ReadCookieHandler(w, r)

// 		fmt.Println("Token String: ", tknStr)

// 		// Initialize a new instance of `Claims`
// 		claims := &Claims{}

// 		// Parse the JWT string and store the result in `claims`.
// 		// Note that we are passing the key in this method as well. This method will return an error
// 		// if the token is invalid (if it has expired according to the expiry time we set on sign in),
// 		// or if the signature does not match
// 		tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
// 			return jwtKey, nil
// 		})
// 		if err != nil {
// 			fmt.Println("Error in the Welcome opening of the JWT")
// 			fmt.Println(err)
// 			switchtolog(w, r)
// 			return
// 		}
// 		if !tkn.Valid {
// 			http.Redirect(w, r, "/login", http.StatusSeeOther)
// 			fmt.Println("Redirecting to Log in since token expired")
// 			switchtolog(w, r)
// 			return
// 		}

// 		t, _ := template.ParseFiles("static/welcome.html")
// 		// t, _ := template.ParseFiles("static/chat.html")
// 		fmt.Println("mess")
// 		// fmt.Println("about to refresh")

// 		// refreshJWT(w, r)
// 		mess := ErrorMessage{"welcoming test"}
// 		td := Tdata{claims.Name, mess}
// 		fmt.Println("Welcome!")

// 		// t.Execute(w, td)
// 		t.Execute(w, td)

// 	}

// }

// func login(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("login function")
// 	fmt.Println("method:", r.Method) //get request method

// 	if r.Method == "GET" {
// 		t, _ := template.ParseFiles("static/logindatabase.html")
// 		t.Execute(w, nil)
// 		//fmt.Println("shouldve worked")
// 		//until a post method is recieved just keep the same page
// 	} else {
// 		r.ParseForm()
// 		// logic part of log in

// 		var uemail = r.Form["email"][0]
// 		var upass = r.Form["password"][0]

// 		fmt.Println("attempting to log.....")
// 		t, _ := template.ParseFiles("static/logindatabase.html")

// 		//MongoDB logging in
// 		//filter := bson.D{{"email", uemail},{"passlsword",upass}}
// 		filter := bson.D{{Key: "email", Value: uemail}}
// 		var result User

// 		eror := collection.FindOne(context.TODO(), filter).Decode(&result)
// 		if eror != nil {
// 			//there is no account with the given email
// 			mess := ErrorMessage{"There is no account registered to that email please Sign Up"}
// 			fmt.Println("Log Failed: attempting to sign up.....")
// 			t, _ := template.ParseFiles("static/signupdatabase.html")
// 			t.Execute(w, mess)
// 			return
// 		}

// 		fmt.Printf("Found a single document: %+v\n", result)
// 		fmt.Println("email:", r.Form["email"])
// 		fmt.Println("password:", r.Form["password"])

// 		salted := result.Password //  decoded in the compare function

// 		if !comparePasswords(salted, upass) {
// 			mess := ErrorMessage{"Error: Password does not match"}
// 			t.Execute(w, mess)
// 			return
// 		}

// 		fmt.Println("loging in.....")

// 		expirationTime := time.Now().Add(5 * time.Minute)
// 		claims := &Claims{
// 			Email: uemail,
// 			StandardClaims: jwt.StandardClaims{
// 				// In JWT, the expiry time is expressed as unix milliseconds
// 				ExpiresAt: expirationTime.Unix(),
// 			},
// 			Name: result.FirstName,
// 		}
// 		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

// 		tokenString, err := token.SignedString(jwtKey)
// 		if err != nil {
// 			// If there is an error in creating the JWT return an internal server error
// 			fmt.Println("Error with JWT token!")
// 			return
// 		}
// 		SetCookieHandler(w, r, tokenString)

// 		cooks := ReadCookieHandler(w, r)

// 		fmt.Println(cooks)
// 		fmt.Println("completed cookie check in")
// 		//mess := ErrorMessage{"cookie has been confirmed"}
// 		//uData = Tdata{result, mess}
// 		// t, _ = template.ParseFiles("static/welcome.html")
// 		// t.Execute(w, td)
// 		fmt.Println("switching to welcome from log...")
// 		http.Redirect(w, r, "/welcome", http.StatusSeeOther)

// 		//FIGURE OUT HOW TO SEND OVER RETRIVED USER TO THE WELCOME PAGE
// 		// ALSO FIGURE OUT HOW TO SEND MULTIPLE DATAS IN THE TEMPLE USING THE T.EXECUTE
// 	}
// }
// func switchtosign(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("switching to sign.....")
// 	// t, _ := template.ParseFiles("static/signupdatabase.html")
// 	// t.Execute(w, nil)
// 	http.Redirect(w, r, "/signup", http.StatusSeeOther)
// }
// func switchtolog(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("switching to log.....")
// 	// t, _ := template.ParseFiles("static/logindatabase.html")
// 	// t.Execute(w, nil)

// 	http.Redirect(w, r, "/login", http.StatusSeeOther)
// }

// refreshJWT : refresh the expiration time of the JWT token
// func refreshJWT(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println("Refreshing...")
// 	fmt.Println("")
// 	tknStr := ReadCookieHandler(w, r)
// 	claims := &Claims{}
// 	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
// 		return jwtKey, nil
// 	})
// 	fmt.Println(claims)
// 	if !tkn.Valid {
// 		fmt.Println("JWT is not valid")
// 		return
// 	}
// 	if err != nil {
// 		fmt.Println("Error: ")
// 		fmt.Println(err)
// 		return
// 	}

// 	// We ensure that a new token is not issued until enough time has elapsed
// 	// In this case, a new token will only be issued if the old token is within
// 	// 30 seconds of expiry. Otherwise, return a bad request status
// 	if time.Unix(claims.ExpiresAt, 0).Sub(time.Now()) > 30*time.Second {
// 		fmt.Println("Still got Time brother")
// 		return
// 	}

// 	// Now, create a new token for the current use, with a renewed expiration time
// 	expirationTime := time.Now().Add(5 * time.Minute)
// 	fmt.Println("the new exp time: ")
// 	fmt.Println(expirationTime)
// 	claims.ExpiresAt = expirationTime.Unix()
// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenString, err := token.SignedString(jwtKey)
// 	if err != nil {
// 		w.WriteHeader(http.StatusInternalServerError)
// 		return
// 	}

// 	// Set the new token as the users `token` cookie
// 	SetCookieHandler(w, r, tokenString)
// 	fmt.Println("Refreshed")
// }

// func mongose() *mongo.Client {
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel() //what ever the /test part is is waht opens up teh starting call to db
// 	client, err := mongo.Connect(ctx, options.Client().ApplyURI(
// 		"mongodb+srv://dreidenbach:Reidenbach1@fschat-gipdg.mongodb.net/test?w=majority",
// 	))
// 	fmt.Println("pre ping")
// 	err = client.Ping(ctx, nil)
// 	if err != nil {
// 		fmt.Println(err)
// 		os.Exit(1)
// 	}

// 	fmt.Println("Connected to MongoDB!")

// 	return client
// }

// func getName(w http.ResponseWriter, r *http.Request) string {
// 	// mess := r.Form["message"][0]

// 	tknStr := ReadCookieHandler(w, r)
// 	claims := &Claims{}

// 	// Parse the JWT string and store the result in `claims`.
// 	// Note that we are passing the key in this method as well. This method will return an error
// 	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
// 	// or if the signature does not match
// 	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
// 		return jwtKey, nil
// 	})

// 	if err != nil {
// 		fmt.Println("Error in the Welcome opening of the JWT")
// 		fmt.Println(err)
// 		switchtolog(w, r)
// 		return ""
// 	}
// 	if !tkn.Valid {
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		fmt.Println("Redirecting to Log in since token expired")
// 		switchtolog(w, r)
// 		return ""
// 	}

// 	name := claims.Name
// 	name += ": "

// 	// byteName := []byte(name)

// 	// _ = byteName
// 	fmt.Println(name)
// 	return name

// }

// func getEmail(w http.ResponseWriter, r *http.Request) string {
// 	// mess := r.Form["message"][0]

// 	tknStr := ReadCookieHandler(w, r)
// 	claims := &Claims{}

// 	// Parse the JWT string and store the result in `claims`.
// 	// Note that we are passing the key in this method as well. This method will return an error
// 	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
// 	// or if the signature does not match
// 	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
// 		return jwtKey, nil
// 	})

// 	if err != nil {
// 		fmt.Println("Error in the Welcome opening of the JWT")
// 		fmt.Println(err)
// 		switchtolog(w, r)
// 		return ""
// 	}
// 	if !tkn.Valid {
// 		http.Redirect(w, r, "/login", http.StatusSeeOther)
// 		fmt.Println("Redirecting to Log in since token expired")
// 		switchtolog(w, r)
// 		return ""
// 	}

// 	name := claims.Email

// 	// byteName := []byte(name)

// 	// _ = byteName

// 	return name

// }
// func handleConnections(w http.ResponseWriter, r *http.Request) {
// 	// Upgrade initial GET request to a websocket
// 	fmt.Println("handling connections")
// 	ws, err := upgrader.Upgrade(w, r, nil)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	fmt.Println("passed err 1")
// 	// Make sure we close the connection when the function returns
// 	defer ws.Close()

// 	// em := getEmail(w, r)

// 	// if val, ok := activeUsers[em]; !ok {
// 	// 	//do something here
// 	// 	clients[ws] = true // registering the client
// 	// 	activeUsers[em] = ws
// 	// 	_ = val
// 	// }
// 	clients[ws] = true

// 	for {
// 		var msg Message
// 		// Read in a new message as JSON and map it to a Message object
// 		err := ws.ReadJSON(&msg)
// 		//fmt.Println(msg.Message)
// 		if err != nil {
// 			fmt.Printf("error: %v", err)
// 			fmt.Println("handdle connections error")
// 			delete(clients, ws)
// 			break
// 		}
// 		fmt.Println("passed err 2")

// 		msg.Message = getName(w, r) + msg.Message

// 		fmt.Println(msg.Message)
// 		// Send the newly received message to the broadcast channel
// 		broadcast <- msg
// 		// refreshJWT(w, r)
// 	}

// }

// func handleMessages() {
// 	var did = 1
// 	var dod = 1
// 	for {
// 		fmt.Println("handling messages")
// 		// Grab the next message from the broadcast channel
// 		msg := <-broadcast
// 		// Send it out to every client that is currently connected
// 		//fmt.Println(msg.Message)
// 		fmt.Println("outer: ", did)
// 		did++

// 		fmt.Println(clients)
// 		for client := range clients {
// 			fmt.Println("inner: ", dod)
// 			dod++
// 			err := client.WriteJSON(msg)
// 			if err != nil {
// 				log.Printf("error: %v", err)
// 				client.Close()
// 				delete(clients, client)
// 			}
// 		}
// 	}
// }
