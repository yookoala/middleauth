package middleauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mrjones/oauth"
	uuid "github.com/satori/go.uuid"
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

func TestCallbackHandler(t *testing.T) {

	flags := make(map[string]bool)
	stages := []string{"getClient", "getAuthUser", "findOrCreateUser", "genSessionCookie"}

	getClient := middleauth.CallbackReqDecoder(func(r *http.Request) (ctxNext context.Context, client *http.Client, err error) {
		ctxNext = r.Context()
		// TODO: need mock client
		flags["getClient"] = true
		return
	})

	getAuthUser := middleauth.AuthUserDecoder(func(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *middleauth.User, err error) {
		ctxNext = ctx
		var userID uuid.UUID
		userID, _ = uuid.NewV4()
		authUser = &middleauth.User{
			ID:   userID.String(),
			Name: "dummy user",
		}
		flags["getAuthUser"] = true
		return
	})

	findOrCreateUser := middleauth.UserStorageCallback(func(ctx context.Context, authUser *middleauth.User) (ctxNext context.Context, confirmedUser *middleauth.User, err error) {
		ctxNext = ctx
		confirmedUser = authUser
		flags["findOrCreateUser"] = true
		return
	})

	genSessionCookie := middleauth.CookieFactory(func(ctx context.Context, in *http.Cookie, confirmedUser *middleauth.User) (out *http.Cookie, err error) {
		out = &http.Cookie{
			Name:  "hello-cookie",
			Value: "dummy-session-cookie",
		}
		flags["genSessionCookie"] = true
		return
	})

	handler := middleauth.NewCallbackHandler(
		getClient,
		getAuthUser,
		findOrCreateUser,
		genSessionCookie,
		"http://foobar.com/success",
		"http://foobar.com/error",
	)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "http://foobar.com/oauth2/dummy-provider", nil)
	handler.ServeHTTP(w, r)

	for _, stage := range stages {
		if ok, _ := flags[stage]; !ok {
			t.Errorf("did not run %s", stage)
		}
	}
}

func TestCallbackHandler_Errors(t *testing.T) {

	getClient := middleauth.CallbackReqDecoder(func(r *http.Request) (ctxNext context.Context, client *http.Client, err error) {
		ctxNext = r.Context()
		// TODO: need mock client
		return
	})
	getClientError := middleauth.CallbackReqDecoder(func(r *http.Request) (ctxNext context.Context, client *http.Client, err error) {
		err = fmt.Errorf("getClient")
		return
	})

	getAuthUser := middleauth.AuthUserDecoder(func(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *middleauth.User, err error) {
		ctxNext = ctx

		var userID uuid.UUID
		userID, _ = uuid.NewV4()
		authUser = &middleauth.User{
			ID:   userID.String(),
			Name: "dummy user",
		}
		return
	})
	getAuthUserError := middleauth.AuthUserDecoder(func(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *middleauth.User, err error) {
		ctxNext = ctx
		err = fmt.Errorf("getAuthUser")
		return
	})

	findOrCreateUser := middleauth.UserStorageCallback(func(ctx context.Context, authUser *middleauth.User) (ctxNext context.Context, confirmedUser *middleauth.User, err error) {
		ctxNext = ctx
		confirmedUser = authUser
		return
	})
	findOrCreateUserError := middleauth.UserStorageCallback(func(ctx context.Context, authUser *middleauth.User) (ctxNext context.Context, confirmedUser *middleauth.User, err error) {
		ctxNext = ctx
		err = fmt.Errorf("findOrCreateUser")
		return
	})

	genSessionCookie := middleauth.CookieFactory(func(ctx context.Context, in *http.Cookie, confirmedUser *middleauth.User) (out *http.Cookie, err error) {
		out = &http.Cookie{
			Name:  "hello-cookie",
			Value: "dummy-session-cookie",
		}
		return
	})
	genSessionCookieError := middleauth.CookieFactory(func(ctx context.Context, in *http.Cookie, confirmedUser *middleauth.User) (out *http.Cookie, err error) {
		err = fmt.Errorf("genSessionCookie")
		return
	})

	tests := []struct {
		Handler  http.Handler
		ExptdErr string
	}{
		{
			Handler: middleauth.NewCallbackHandler(
				getClientError,
				getAuthUser,
				findOrCreateUser,
				genSessionCookie,
				"http://foobar.com/success",
				"http://foobar.com/error",
			),
			ExptdErr: "getClient",
		},
		{
			Handler: middleauth.NewCallbackHandler(
				getClient,
				getAuthUserError,
				findOrCreateUser,
				genSessionCookie,
				"http://foobar.com/success",
				"http://foobar.com/error",
			),
			ExptdErr: "getAuthUser",
		},
		{
			Handler: middleauth.NewCallbackHandler(
				getClient,
				getAuthUser,
				findOrCreateUserError,
				genSessionCookie,
				"http://foobar.com/success",
				"http://foobar.com/error",
			),
			ExptdErr: "findOrCreateUser",
		},
		{
			Handler: middleauth.NewCallbackHandler(
				getClient,
				getAuthUser,
				findOrCreateUser,
				genSessionCookieError,
				"http://foobar.com/success",
				"http://foobar.com/error",
			),
			ExptdErr: "genSessionCookie",
		},
	}

	for _, test := range tests {
		w := httptest.NewRecorder()
		r, _ := http.NewRequest("GET", "http://foobar.com/oauth2/dummy-provider", nil)
		test.Handler.ServeHTTP(w, r)

		redirectURL := w.Header().Get("Location")
		if redirectURL == "" {
			t.Errorf("unexpected empty redirectURL")
			continue
		}

		// get error message in redirectURL
		parsed, err := url.Parse(redirectURL)
		if err != nil {
			t.Errorf("unexpected parse error for url: %#v, error: %s",
				redirectURL, err.Error(),
			)
		} else if want, have := test.ExptdErr, parsed.Query().Get("error"); want != have {
			t.Errorf("wanted %#v, got %#v", want, have)
		} else if parsed.Query().Get("message") == "" {
			t.Error("unexpected empty message field.")
		}
	}
}
