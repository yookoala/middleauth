package middleauth

import (
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/go-restit/lzjson"
	"github.com/mrjones/oauth"
	"gopkg.in/jose.v1/crypto"
)

var tokens map[string]*oauth.RequestToken

func init() {
	tokens = make(map[string]*oauth.RequestToken, 1024)
}

// TokenSave stores a copy of token in a map by token key
func TokenSave(token *oauth.RequestToken) {
	// TODO: add mutex lock mechanism
	tokens[token.Token] = token
}

// TokenConsume return the token stored previously and remove it
// from the map
func TokenConsume(tokenKey string) (token *oauth.RequestToken) {
	// TODO: add mutex lock mechanism
	token, ok := tokens[tokenKey]
	if ok {
		delete(tokens, tokenKey)
	}
	return
}

// TwitterConsumer provides OAuth config for twitter login
func TwitterConsumer(provider AuthProvider) *oauth.Consumer {
	return oauth.NewConsumer(
		provider.ClientID,
		provider.ClientSecret,
		oauth.ServiceProvider{
			RequestTokenUrl:   "https://api.twitter.com/oauth/request_token",
			AuthorizeTokenUrl: "https://api.twitter.com/oauth/authorize",
			AccessTokenUrl:    "https://api.twitter.com/oauth/access_token",
		},
	)
}

// TwitterCallback returns a http.Handler for Twitter account login handing
func TwitterCallback(
	c *oauth.Consumer,
	userCallback UserCallback,
	tokenConsume func(tokenKey string) *oauth.RequestToken,
	genLoginCookie CookieFactory,
	jwtKey, successURL, errURL string,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		values := r.URL.Query()
		verificationCode := values.Get("oauth_verifier")
		tokenKey := values.Get("oauth_token")

		accessToken, err := c.AuthorizeToken(tokenConsume(tokenKey), verificationCode)
		if err != nil {
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"error": err.Error(),
				}).Error("failed to retrieve access token")
				http.Redirect(w, r, errURL, http.StatusTemporaryRedirect)
				return
			}
		}

		client, err := c.MakeHttpClient(accessToken)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("error making credential client")
			http.Redirect(w, r, errURL, http.StatusTemporaryRedirect)
			return
		}

		resp, err := client.Get(
			"https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true&skip_status")
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("failed to retrieve verified credentials")
			http.Redirect(w, r, errURL, http.StatusTemporaryRedirect)
			return
		}
		defer resp.Body.Close()

		// read into
		result := lzjson.Decode(resp.Body)
		/*
			// NOTE: JSON structure of normal response body
			{
				"contributors_enabled": true,
				"created_at": "Sat May 09 17:58:22 +0000 2009",
				"default_profile": false,
				"default_profile_image": false,
				"description": "I taught your phone that thing you like.  The Mobile Partner Engineer @Twitter. ",
				"favourites_count": 588,
				"follow_request_sent": null,
				"followers_count": 10625,
				"following": null,
				"friends_count": 1181,
				"geo_enabled": true,
				"id": 38895958,
				"id_str": "38895958",
				"is_translator": false,
				"lang": "en",
				"listed_count": 190,
				"location": "San Francisco",
				"name": "Sean Cook",
				"email": "sean.cook@email.com",
				"notifications": null,
				"profile_background_color": "1A1B1F",
				"profile_background_image_url": "http://a0.twimg.com/profile_background_images/495742332/purty_wood.png",
				"profile_background_image_url_https": "https://si0.twimg.com/profile_background_images/495742332/purty_wood.png",
				"profile_background_tile": true,
				"profile_image_url": "http://a0.twimg.com/profile_images/1751506047/dead_sexy_normal.JPG",
				"profile_image_url_https": "https://si0.twimg.com/profile_images/1751506047/dead_sexy_normal.JPG",
				"profile_link_color": "2FC2EF",
				"profile_sidebar_border_color": "181A1E",
				"profile_sidebar_fill_color": "252429",
				"profile_text_color": "666666",s
				"profile_use_background_image": true,
				"protected": false,
				"screen_name": "theSeanCook",
				"show_all_inline_media": true,
				"statuses_count": 2609,aI was
				"time_zone": "Pacific Time (US & Canada)",
				"url": null,
				"utc_offset": -28800,
				"verified": false
			}
		*/

		// TODO: detect read  / decode error
		// TODO: check if the email has been verified or not
		authUser, err := userCallback(
			r.Context(),
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
