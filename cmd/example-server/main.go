package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/yookoala/middleauth"
	gormstorage "github.com/yookoala/middleauth/storage/gorm"
	"gopkg.in/jose.v1/crypto"
)

func main() {

	// the handlers implement http.Handler and
	// works with any router that accept it.
	mux := http.NewServeMux()

	// environment details that are not important for now.
	host, port, cookieName, publicURL := varFromEnv()

	db := getDB() // gorm.db for user data storage
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
