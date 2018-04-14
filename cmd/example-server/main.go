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

	jwtKey := "some-encryption-key"

	// overrides expiration of default JWTSession setting
	mySession := middleauth.SessionExpires(12 * time.Hour)(
		middleauth.JWTSession(
			cookieName,
			jwtKey,
			crypto.SigningMethodHS256,
		),
	)

	// handles the common paths:
	// 1. login page
	// 2. login redirect and callback for OAuth2 / OAuth1.0a
	handlerCtx, err := middleauth.NewContext(publicURL)
	if err != nil {
		panic(err)
	}

	handlerCtx.AuthPath = "/login"
	handlerCtx.LoginPath = "/login/oauth2"
	handlerCtx.LogoutPath = "/logout"
	handlerCtx.SuccessPath = ""
	handlerCtx.ErrPath = "/error"
	middleauth.CommonHandler(
		mux,
		middleauth.EnvProviders(os.Getenv),
		gormstorage.UserStorageCallback(db),
		mySession,
		handlerCtx,
	)

	// the dummy app endpoints
	appMux := http.NewServeMux()
	appMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		user := middleauth.GetUser(r.Context())
		w.Header().Add("Content-Type", "text/html;charset=utf-8")
		if user != nil {
			fmt.Fprintf(w, `Hello <a href="mailto:%s">%s</a>. You may <a href="/logout">logout here</a>`, user.PrimaryEmail, user.Name)
		} else {
			fmt.Fprintf(w, `You have not login. Please <a href="/login">login here</a>.`)
		}
	})
	appMux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "error!")
	})

	// middleware that decodes JWT session
	// and get user from gorm db storage
	app := middleauth.SessionMiddleware(
		middleauth.JWTSessionDecoder(cookieName, jwtKey, crypto.SigningMethodHS256),
		gormstorage.RetrieveUser(db),
	)(appMux)
	mux.Handle("/", app)

	// TODO: example handler for success path (with session user info display)
	// TODO: example handler for error path (with proper error message)

	// serve to some place
	log.Printf("Listening: http://" + host + ":" + port)
	http.ListenAndServe(fmt.Sprintf(":%s", port), mux)
}
