package middleauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/go-restit/lzjson"
	"github.com/mrjones/oauth"
)

// TokenStore is the interface for token storage facility
// for temporary token storage and mapping in OAuth1.0a
type TokenStore interface {
	Save(token *oauth.RequestToken)
	Consume(tokenKey string) (token *oauth.RequestToken)
}

// tokenStore stores OAuth1.0a request token
// temporarily to a map of the token field
type tokenStore map[string]*oauth.RequestToken

// Save stores a copy of token in a map by token key
func (tokens tokenStore) Save(token *oauth.RequestToken) {
	tokens[token.Token] = token
}

// Consume remove a token, if exists, from the token store
// and return the just removed token.
func (tokens tokenStore) Consume(tokenKey string) (token *oauth.RequestToken) {
	// TODO: add mutex lock mechanism
	// TODO: make this a distributed storage
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

// TwitterClientFactory generates ProviderClientFactory of the given
// consumer
func TwitterClientFactory(c *oauth.Consumer, tokens TokenStore) CallbackReqDecoder {
	return func(r *http.Request) (ctxNext context.Context, client *http.Client, err error) {

		values := r.URL.Query()
		verificationCode := values.Get("oauth_verifier")
		tokenKey := values.Get("oauth_token")

		// TODO: add mutex lock mechanism to ensure read, write
		// or have global token storage for distributed access
		token := tokens.Consume(tokenKey)
		if token == nil {
			err = fmt.Errorf("relevant request token not found")
		}

		accessToken, err := c.AuthorizeToken(token, verificationCode)
		if err != nil {
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"error": err.Error(),
				}).Error("failed to retrieve access token")
				return
			}
		}

		client, err = c.MakeHttpClient(accessToken)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("error making credential client")
			return
		}

		return
	}
}

// TwitterAuthUserFactory implements ProviderAuthUserFactory
func TwitterAuthUserFactory(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *User, err error) {
	resp, err := client.Get(
		"https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true&skip_status")
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to retrieve verified credentials")
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
	authUser = &User{
		Name:         result.Get("name").String(),
		PrimaryEmail: result.Get("email").String(),
	}
	ctxNext = ctx
	return
}
