package middleauth_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/mrjones/oauth"
	"github.com/yookoala/middleauth"
	"golang.org/x/oauth2"
)

func TestOAuth2AuthURLFactory(t *testing.T) {

	factory := middleauth.OAuth2AuthURLFactory(&oauth2.Config{
		RedirectURL:  "http://foobar.com/redirect",
		ClientID:     "foobar-client-id",
		ClientSecret: "foobar-secret",
		Scopes: []string{
			"scope-1",
			"scope-2",
		},
		//Endpoint: oauth2,
		Endpoint: oauth2.Endpoint{
			AuthURL:  "http://dummy-oauth2-provider.com/auth",
			TokenURL: "http://dummy-oauth2-provider.com/token",
		},
	})

	r, _ := http.NewRequest("GET", "http://foobar.com/login", nil)
	rawurl, err := factory(r)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	parsedURL, err := url.Parse(rawurl)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}

	q := parsedURL.Query()

	if want, have := "offline", q.Get("access_type"); want != have {
		t.Errorf("wanted %#v, got %#v", want, have)
	}
	if want, have := "foobar-client-id", q.Get("client_id"); want != have {
		t.Errorf("wanted %#v, got %#v", want, have)
	}
	if want, have := "http://foobar.com/redirect", q.Get("redirect_uri"); want != have {
		t.Errorf("wanted %#v, got %#v", want, have)
	}
	if want, have := "code", q.Get("response_type"); want != have {
		t.Errorf("wanted %#v, got %#v", want, have)
	}
	if want, have := "scope-1 scope-2", q.Get("scope"); want != have {
		t.Errorf("wanted %#v, got %#v", want, have)
	}
	if want, have := "state", q.Get("state"); want != have {
		t.Errorf("wanted %#v, got %#v", want, have)
	}
}

type testOAuth1aConsumer struct {
	callbackURL string
}

func (c *testOAuth1aConsumer) GetRequestTokenAndUrl(callbackURL string) (token *oauth.RequestToken, url string, err error) {

	// store given callbackURL
	c.callbackURL = callbackURL

	// return dummy contents
	token = &oauth.RequestToken{
		Token:  "dummy-token",
		Secret: "dummy-secret",
	}
	url = callbackURL + "?token=" + token.Token
	return
}

func TestOAuth1aAuthURLFactory(t *testing.T) {

	dummyConsumer := &testOAuth1aConsumer{}
	tokenStore := middleauth.NewTokenStore()
	factory := middleauth.OAuth1aAuthURLFactory(
		dummyConsumer,
		"https://foobar.com/callback",
		tokenStore,
	)

	r, _ := http.NewRequest("GET", "http://foobar.com/login", nil)
	rawurl, err := factory(r)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
	}
	if want, have := "https://foobar.com/callback", dummyConsumer.callbackURL; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

	parsed, _ := url.Parse(rawurl)
	storedToken := tokenStore.Consume(parsed.Query().Get("token"))
	if storedToken == nil {
		t.Errorf("expected token, got nil")
	} else if want, have := "dummy-token", storedToken.Token; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	} else if want, have := "dummy-secret", storedToken.Secret; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
}
