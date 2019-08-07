package main
import (
"fmt"
"net/http"
// "html/template"
"log"

"golang.org/x/net/context"

firebase "firebase.google.com/go"
//"firebase.google.com/go/auth"

"google.golang.org/api/option"
)





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
  http.ListenAndServe(":8070", nil)

//export GOOGLE_APPLICATION_CREDENTIALS="/Users/dannyreidenbach/Desktop/FSchat/fschat-e96d5-firebase-adminsdk-kmijl-97bf20d317.json"
}
