package main
import (
"fmt"
"net/http"
// "html/template"
"log"
"strings"
"golang.org/x/net/context"

firebase "firebase.google.com/go"
//"firebase.google.com/go/auth"

"google.golang.org/api/option"


"html/template"
)

type UserDetails struct {
    Email   string
    Password string
}

func sayhelloName(w http.ResponseWriter, r *http.Request) {
    r.ParseForm() //Parse url parameters passed, then parse the response packet for the POST body (request body)
    // attention: If you do not call ParseForm method, the following data can not be obtained form
    fmt.Println(r.Form) // print information on server side.
    fmt.Println("path", r.URL.Path)
    fmt.Println("scheme", r.URL.Scheme)
    fmt.Println(r.Form["url_long"])
    for k, v := range r.Form {
        fmt.Println("key:", k)
        fmt.Println("val:", strings.Join(v, ""))
    }
    fmt.Fprintf(w, "Hello astaxie!") // write data to response
}

func login(w http.ResponseWriter, r *http.Request) {
    fmt.Println("method:", r.Method) //get request method
    if r.Method == "GET" {
        t, _ := template.ParseFiles("signUp.html")
        t.Execute(w, nil)
    } else {
        r.ParseForm()
        // logic part of log in
        fmt.Println("username:", r.Form["username"])
        fmt.Println("password:", r.Form["password"])
    }
}


func helloWorld(w http.ResponseWriter, r *http.Request){
    fmt.Fprintf(w, "Hello World")
}
func main() {
  opt := option.WithCredentialsFile("/Users/dannyreidenbach/Desktop/FSchat/fschat-e96d5-firebase-adminsdk-kmijl-97bf20d317.json")
  app, err := firebase.NewApp(context.Background(), nil)
  if err != nil {
          log.Fatalf("error initializing app: %v\n", err)
  }
  _,_,_ = app,err,opt //this is just to get it to compile early on


  fs := http.FileServer(http.Dir("./static"))
  http.Handle("/", fs)



  log.Println("Listening...")

  http.HandleFunc("/hello", sayhelloName) // setting router rule
  http.HandleFunc("/login", login)

  http.ListenAndServe(":8070", nil)


//export GOOGLE_APPLICATION_CREDENTIALS="/Users/dannyreidenbach/Desktop/FSchat/fschat-e96d5-firebase-adminsdk-kmijl-97bf20d317.json"
}