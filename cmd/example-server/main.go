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

func varFromEnv() (host, port, cookieName, publicURL string) {

	// (optional) load variables in .env as environment variavbles
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// hard code these 2 here
	host, cookieName = "localhost", "middleauth-example"

	// get port and public url here
	if port = os.Getenv("PORT"); port == "" {
		port = "8080"
	}
	if publicURL = os.Getenv("PUBLIC_URL"); publicURL == "" {
		publicURL = "http://localhost:8080"
	}

	return
}

func getDB() (db *gorm.DB) {
	db, err := gorm.Open("sqlite3", "example-server.db")
	if err != nil {
		log.Fatalf("unexpected error: %s", err.Error())
	}

	db.AutoMigrate(
		middleauth.User{},
		middleauth.UserEmail{},
	)
	return
}

func main() {

	// the handlers implement http.Handler and
	// works with any router that accept it.
	mux := http.NewServeMux()

	// some settings
	host, port, cookieName, publicURL := varFromEnv()

	// database for test
	db := getDB()
	defer db.Close()

	// overrides expiration of default JWTSession setting
	mySession := middleauth.SessionExpires(12 * time.Hour)(
		middleauth.JWTSession(
			cookieName,
			"some-encryption-key",
			crypto.SigningMethodHS256,
		),
	)

	// get providers from environment variables
	providers := middleauth.EnvProviders(os.Getenv)

	// handles the common paths:
	// 1. login page
	// 2. login redirect and callback for OAuth2 / OAuth1.0a
	middleauth.CommonHandler(
		mux,
		providers,
		gormstorage.UserStorageCallback(db),
		mySession,
		cookieName,
		publicURL,
		"/login",
		"/login/oauth2",
		"/logout",
		publicURL+"/success",
		publicURL+"/error",
	)

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
