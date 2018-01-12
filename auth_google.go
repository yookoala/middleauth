package middleauth

import (
	"context"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/go-restit/lzjson"

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

// GoogleAuthUserFactory implements ProviderAuthUserFactory
func GoogleAuthUserFactory(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *User, err error) {

	resp, err := client.Get("https://www.googleapis.com/oauth2/v1/userinfo")
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to retrieve id, name and email")
		return
	}

	result := lzjson.Decode(resp.Body)

	// read into
	/*
		// NOTE: JSON structure of normal response body
		{
		  "id": "numerical-user-id",
		  "name": "user display name",
		  "email": "email address"
		}
	*/
	authUser = &User{
		Name:         result.Get("name").String(),
		PrimaryEmail: result.Get("email").String(),
	}
	ctxNext = ctx
	return
}
