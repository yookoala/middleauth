package middleauth

import (
	"context"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/go-restit/lzjson"
	"github.com/jinzhu/gorm"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// GoogleConfig provides OAuth2 config for google login
func GoogleConfig(provider AuthProvider, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

// GoogleCallback returns a http.Handler for Google account login handing
func GoogleCallback(
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
		resp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo")
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("failed to retrieve userinfo")
			http.Redirect(w, r, errURL, http.StatusTemporaryRedirect)
			return
		}

		// read into
		/*
			// NOTE: JSON structure of normal response body
			{
			 "id": "some-id-in-google-account",
			 "email": "email-for-the-account",
			 "verified_email": true,
			 "name": "Some Name",
			 "given_name": "Some",
			 "family_name": "Name",
			 "link": "https://plus.google.com/+SomeUserOnGPlus",
			 "picture": "url-to-some-picture",
			 "gender": "female",
			 "locale": "zh-HK"
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
			http.Redirect(w, r, errURL, http.StatusFound)
			return
		}

		logrus.WithFields(logrus.Fields{
			"user.id":   authUser.ID,
			"user.name": authUser.Name,
		}).Info("user found or created.")

		// set authUser digest to cookie as jwt
		http.SetCookie(w,
			authJWTCookie(genLoginCookie(r), jwtKey, *authUser))

		http.Redirect(w, r, successURL, http.StatusTemporaryRedirect)
	}
}
