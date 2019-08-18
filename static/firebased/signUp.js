function signUp(){
  var userEmail = document.getElementById("email_field").value;
  var userPassword = document.getElementById("password_field").value;
  window.alert(userEmail);
  //window.alert(userEmail.endsWith(".edu")); // not working
    if (userEmail.length < 4) {
        alert('Please enter an email address.');
        return;
      }

      if (userPassword.length < 4) {
        alert('Please enter a password.');
        return;
      }


      if (! userEmail.endsWith(".edu")) {
        alert('Please enter a College email.');
        return;
      }
      // Sign in with email and pass.
      // [START createwithemail]

      //firebase.auth is not a function ?????
      firebase.auth().createUserWithEmailAndPassword(userEmail, userPassword).catch(function(error) {
        // Handle Errors here.
        var errorCode = error.code;
        var errorMessage = error.message;
        // [START_EXCLUDE]
        if (errorCode == 'auth/weak-password') {
          alert('The password is too weak.');
        } else {
          alert(errorMessage);
        }
        console.log(error);
        // [END_EXCLUDE]
      });
}
