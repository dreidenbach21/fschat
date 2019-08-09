package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"
    "strings"
    "unicode"
)

// func sayhelloName(w http.ResponseWriter, r *http.Request) {
//   fmt.Println("say hello name")
//     r.ParseForm() //Parse url parameters passed, then parse the response packet for the POST body (request body)
//     // attention: If you do not call ParseForm method, the following data can not be obtained form
//     fmt.Println(r.Form) // print information on server side.
//     fmt.Println("path", r.URL.Path)
//     fmt.Println("scheme", r.URL.Scheme)
//     fmt.Println(r.Form["url_long"])
//     for k, v := range r.Form {
//         fmt.Println("key:", k)
//         fmt.Println("val:", strings.Join(v, ""))
//     }
//     fmt.Fprintf(w, "Hello astaxie!") // write data to response
// }
type User struct {
    firstName string
    lastName string
    Email   string
    Password string

}

var mapp map[string]User


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
            errorString+= " and uppercase letter missing"
          }
        }

        if !numberPresent {
          if len(errorString) == 0 {
            errorString = "atleast one numeric character required"
          } else {
            errorString+= " and atleast one numeric character required"
          }
        }

        if !specialCharPresent {
          if len(errorString) == 0 {
            errorString = "special character missing"
          } else {
            errorString+= " and special character missing"
          }
        }

        if !(minPassLength <= passLen && passLen <= maxPassLength) {
          if len(errorString) == 0 {
            errorString = fmt.Sprintf("password length must be between %d to %d characters long", minPassLength, maxPassLength)
          } else {
            errorString+= " and " + fmt.Sprintf("password length must be between %d to %d characters long", minPassLength, maxPassLength)
          }
        }

        return errorString
    }

func dealBadInfo(firster string,uemail string,upass string,cpass string ,w http.ResponseWriter) bool{

  t, _ := template.ParseFiles("static/signupdatabase.html")

  if !strings.HasSuffix(uemail,".edu") {
    fmt.Println("invalid email")
    //t, _ := template.ParseFiles("static/signupdatabase.html")
    t.Execute(w, template.HTML("Invalid Email Please Enter a School Email!"))
    return true
  }

  var passCheck = verifyPassword(upass)
  if len(passCheck) > 0 {
    fmt.Println("invalid password")
    //t, _ := template.ParseFiles("static/signupdatabase.html")
    t.Execute(w, template.HTML(passCheck))
    return true
  }

  if(upass != cpass) {
    fmt.Println("valid password but confirmation and entry do not match")
    //t, _ := template.ParseFiles("static/signupdatabase.html")
    t.Execute(w, template.HTML("Please Make Sure You Confirm Your Password Correctly"))
    return true
  }
  return false
}

func login(w http.ResponseWriter, r *http.Request) {
  fmt.Println("login function")
    fmt.Println("method:", r.Method) //get request method
    if r.Method == "GET" {
        t, _ := template.ParseFiles("static/signupdatabase.html")
        t.Execute(w, nil)
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


        var ok = dealBadInfo(firster,uemail,upass,cpass,w)
        if(ok){
          return
        }


        fmt.Println("email:", r.Form["email"])
        fmt.Println("password:", r.Form["password"])

        mapp[uemail] = User{firster,laster,uemail,upass}

        t.Execute(w, nil)
        //this sends the webpage back to the sign up page after the log in is complete
    }
}

func main() {

  //  http.HandleFunc("/", sayhelloName) // setting router rule
    mapp = make(map[string]User)
    fs := http.FileServer(http.Dir("./static"))
    http.Handle("/", fs)
    http.HandleFunc("/login", login)



    log.Println("Listening...")

    // http.HandleFunc("/hello", sayhelloName) // setting router rule
    // http.HandleFunc("/login", login)

    http.ListenAndServe(":8070", nil)
}
