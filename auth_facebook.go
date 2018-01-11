package middleauth

import (
	"context"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/go-restit/lzjson"
	"github.com/jinzhu/gorm"
	"gopkg.in/jose.v1/crypto"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/facebook"
)

// FacebookConfig provides OAuth2 config for google login
func FacebookConfig(provider AuthProvider, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Scopes: []string{
			"email",
		},
		Endpoint: facebook.Endpoint,
	}
}

// FacebookCallback returns a http.Handler for Google account login handing
func FacebookCallback(
	conf *oauth2.Config,
	db *gorm.DB,
	genLoginCookie CookieFactory,
	jwtKey, successURL, errURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		token, err := conf.Exchange(oauth2.NoContext, code)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("code exchange failed")
			http.Redirect(w, r, errURL, http.StatusTemporaryRedirect)
			return
		}

		client := conf.Client(context.Background(), token)
		resp, err := client.Get("https://graph.facebook.com/v2.9/me?fields=id,name,email")
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("failed to retrieve id, name and email")
			http.Redirect(w, r, errURL, http.StatusTemporaryRedirect)
			return
		}

		// read into
		/*
			// NOTE: JSON structure of normal response body
			{
			  "id": "numerical-user-id",
			  "name": "user display name",
			  "email": "email address"
			}
		*/

		result := lzjson.Decode(resp.Body)

		// TODO: detect read  / decode error
		// TODO: check if the email has been verified or not
		authUser, err := loadOrCreateUser(
			db,
			User{
				Name:         result.Get("name").String(),
				PrimaryEmail: result.Get("email").String(),
			},
			[]string{},
		)

		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("error loading or creating user")

			// TODO; return some warning message to redirected page
			http.Redirect(w, r, errURL, http.StatusTemporaryRedirect)
			return
		}

		logrus.WithFields(logrus.Fields{
			"user.id":   authUser.ID,
			"user.name": authUser.Name,
		}).Info("user found or created.")

		// set authUser digest to cookie as jwt
		http.SetCookie(w,
			authJWTCookie(
				genLoginCookie(r),
				jwtKey,
				crypto.SigningMethodHS256,
				*authUser,
			),
		)

		http.Redirect(w, r, successURL, http.StatusTemporaryRedirect)
	}
}
