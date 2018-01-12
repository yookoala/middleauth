package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/joho/godotenv"
	"github.com/yookoala/middleauth"
	gormstorage "github.com/yookoala/middleauth/storage/gorm"
	"gopkg.in/jose.v1/crypto"
)

func main() {

	// the handlers implement http.Handler and
	// works with any router that accept it.
	mux := http.NewServeMux()

	// (optional) load variables in .env as environment variavbles
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// some settings
	var host, port, cookieName string
	host, cookieName = "localhost", "middleauth-example"
	if port = os.Getenv("PORT"); port == "" {
		port = "8080"
	}

	// database for test
	db, err := gorm.Open("sqlite3", "example-server.db")
	if err != nil {
		log.Fatalf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	db.AutoMigrate(
		middleauth.User{},
		middleauth.UserEmail{},
	)

	// overrides expiration of default JWTSession setting
	mySession := middleauth.SessionExpires(12 * time.Hour)(
		middleauth.JWTSession(
			cookieName,
			"some-encryption-key",
			crypto.SigningMethodHS256,
		),
	)

	// path to use for login authentications
	loginBasePath := "/login/oauth2"

	// get providers from environment variables
	providers := middleauth.EnvProviders(os.Getenv, loginBasePath)

	// handle login paths, the trailing slash is needed here
	// for mux routing
	mux.Handle(loginBasePath+"/", middleauth.LoginHandler(
		gormstorage.UserStorageCallback(db),
		mySession,
		providers,
		"http://"+host+":8080", loginBasePath,
		"http://"+host+":8080"+"/success",
		"http://"+host+":8080"+"/error",
	))

	// handle login page
	mux.Handle("/login", middleauth.LoginPageHandler(
		func(r *http.Request) middleauth.LoginPageContent {
			return middleauth.LoginPageContent{
				PageHeaderTitle: "Login | Example Server",
				PageTitle:       "Login to Example Server",
				Actions:         providers,
			}
		},
	))

	// handle logout path
	mux.Handle("/logout", middleauth.LogoutHandler(
		"http://"+host+":8080/logout",
		cookieName,
	))

	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "error!")
	})
	mux.HandleFunc("/success", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "success!")
	})

	// TODO: middleware for session user retrieval
	// TODO: example handler for success path (with session user info display)
	// TODO: example handler for error path (with proper error message)

	// serve to some place
	log.Printf("Listening: http://" + host + ":" + port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), mux)
}
