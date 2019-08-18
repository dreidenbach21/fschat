package main

import (
	"fmt"
	"net/http"
	// "html/template"
	//"strings"
	//"firebase.google.com/go/auth"
)

func helloWorld(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World")
}

// func main() {
// 	opt := option.WithCredentialsFile("/Users/dannyreidenbach/Desktop/FSchat/fschat-e96d5-firebase-adminsdk-kmijl-aa87ed842d.json")
// 	app, err := firebase.NewApp(context.Background(), nil)
// 	if err != nil {
// 		log.Fatalf("error initializing app: %v\n", err)
// 	}
// 	_, _, _ = app, err, opt //this is just to get it to compile early on

// 	fs := http.FileServer(http.Dir("./static"))
// 	http.Handle("/", fs)

// 	log.Println("Listening...")

// 	// http.HandleFunc("/hello", sayhelloName) // setting router rule
// 	// http.HandleFunc("/login", login)

// 	http.ListenAndServe(":8070", nil)

// 	//export GOOGLE_APPLICATION_CREDENTIALS="/Users/dannyreidenbach/Desktop/FSchat/fschat-e96d5-firebase-adminsdk-kmijl-97bf20d317.json"
// }
