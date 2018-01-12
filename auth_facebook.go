package middleauth

import (
	"context"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/go-restit/lzjson"

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

// FacebookAuthUserFactory implements ProviderAuthUserFactory
func FacebookAuthUserFactory(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *User, err error) {

	resp, err := client.Get("https://graph.facebook.com/v2.9/me?fields=id,name,email")
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
