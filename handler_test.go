package middleauth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gofrs/uuid"
	"github.com/mrjones/oauth"
	"github.com/yookoala/middleauth"
	"golang.org/x/oauth2"
)

func TestContext_urlMethods(t *testing.T) {

	var ctx *middleauth.Context
	var err error

	methods := []struct {
		name    string
		setPath func(*middleauth.Context, string)
		call    func(ctx *middleauth.Context) string
	}{
		{
			name: "AuthURL",
			setPath: func(ctx *middleauth.Context, value string) {
				ctx.AuthPath = value
			},
			call: func(ctx *middleauth.Context) string {
				return ctx.AuthURL().String()
			},
		},
		{
			name: "TokenURL",
			setPath: func(ctx *middleauth.Context, value string) {
				ctx.TokenPath = value
			},
			call: func(ctx *middleauth.Context) string {
				return ctx.TokenURL().String()
			},
		},
		{
			name: "LoginURL",
			setPath: func(ctx *middleauth.Context, value string) {
				ctx.LoginPath = value
			},
			call: func(ctx *middleauth.Context) string {
				return ctx.LoginURL().String()
			},
		},
		{
			name: "LoginURL",
			setPath: func(ctx *middleauth.Context, value string) {
				ctx.LoginPath = value
			},
			call: func(ctx *middleauth.Context) string {
				return ctx.LoginURL().String()
			},
		},
		{
			name: "LogoutURL",
			setPath: func(ctx *middleauth.Context, value string) {
				ctx.LogoutPath = value
			},
			call: func(ctx *middleauth.Context) string {
				return ctx.LogoutURL().String()
			},
		},
		{
			name: "SuccessURL",
			setPath: func(ctx *middleauth.Context, value string) {
				ctx.SuccessPath = value
			},
			call: func(ctx *middleauth.Context) string {
				return ctx.SuccessURL().String()
			},
		},
		{
			name: "ErrURL",
			setPath: func(ctx *middleauth.Context, value string) {
				ctx.ErrPath = value
			},
			call: func(ctx *middleauth.Context) string {
				return ctx.ErrURL().String()
			},
		},
	}

	tests := []struct {
		desc      string
		publicURL string
		path      string
		expected  string
	}{
		{
			desc:      "publicURL without suffix slash",
			publicURL: "https://foobar.com/hello",
			path:      "world/foo/bar",
			expected:  "https://foobar.com/hello/world/foo/bar",
		},
		{
			desc:      "publicURL with suffix slash",
			publicURL: "https://foobar.com/hello/",
			path:      "world/foo/bar",
			expected:  "https://foobar.com/hello/world/foo/bar",
		},
		{
			desc:      "publicURL with suffix slash and path with prefix slash",
			publicURL: "https://foobar.com/hello/",
			path:      "/world/foo/bar",
			expected:  "https://foobar.com/hello/world/foo/bar",
		},
	}

	for _, method := range methods {
		for _, test := range tests {

			// initialize context
			ctx, err = middleauth.NewContext(test.publicURL)
			if err != nil {
				t.Errorf(
					"[%s, %s]\nunexpected error: %s",
					method.name,
					test.desc,
					err,
				)
			}

			initialPath := ctx.PublicURL.Path

			// call the method and examine result
			method.setPath(ctx, test.path)
			result := method.call(ctx)
			if want, have := test.expected, result; want != have {
				t.Errorf(
					"[%s, %s]\nexpect %#v, got %#v",
					method.name,
					test.desc,
					want,
					have,
				)
			}

			// should be the same as beginning
			if want, have := initialPath, ctx.PublicURL.Path; want != have {
				t.Errorf(
					"[%s, %s]\nexpected %#v, got %#v",
					method.name,
					test.desc,
					want,
					have,
				)
			}
		}
	}
}

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

	getAuthUser := middleauth.AuthUserDecoder(func(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *middleauth.UserIdentity, err error) {
		var ID uuid.UUID
		ID, _ = uuid.NewV4()
		ctxNext = ctx
		authUser = &middleauth.UserIdentity{
			Name:       "dummy user",
			Provider:   "dummy provider",
			ProviderID: ID.String(),
		}
		flags["getAuthUser"] = true
		return
	})

	findOrCreateUser := middleauth.UserStorageCallback(func(ctx context.Context, authIdentity *middleauth.UserIdentity) (ctxNext context.Context, confirmedUser *middleauth.User, err error) {
		var ID uuid.UUID
		ID, _ = uuid.NewV4()
		ctxNext = ctx
		confirmedUser = &middleauth.User{
			ID:           ID.String(),
			Name:         authIdentity.Name,
			PrimaryEmail: authIdentity.PrimaryEmail,
		}
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

	ctx, _ := middleauth.NewContext("http://foobar.com/")
	ctx.SuccessPath = "success"
	ctx.ErrPath = "error"
	handler := middleauth.NewCallbackHandler(
		getClient,
		getAuthUser,
		findOrCreateUser,
		genSessionCookie,
		ctx,
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

	getAuthUser := middleauth.AuthUserDecoder(func(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *middleauth.UserIdentity, err error) {
		ctxNext = ctx

		var ID uuid.UUID
		ID, _ = uuid.NewV4()
		authUser = &middleauth.UserIdentity{
			Name:       "dummy user",
			Provider:   "dummy provider",
			ProviderID: ID.String(),
		}
		return
	})
	getAuthUserError := middleauth.AuthUserDecoder(func(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *middleauth.UserIdentity, err error) {
		ctxNext = ctx
		err = fmt.Errorf("getAuthUser")
		return
	})

	findOrCreateUser := middleauth.UserStorageCallback(func(ctx context.Context, authIdentity *middleauth.UserIdentity) (ctxNext context.Context, confirmedUser *middleauth.User, err error) {
		ctxNext = ctx
		confirmedUser = &middleauth.User{
			Name:         authIdentity.Name,
			PrimaryEmail: authIdentity.PrimaryEmail,
		}
		return
	})
	findOrCreateUserError := middleauth.UserStorageCallback(func(ctx context.Context, authIdentity *middleauth.UserIdentity) (ctxNext context.Context, confirmedUser *middleauth.User, err error) {
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

	ctx, _ := middleauth.NewContext("http://foobar.com/")
	ctx.SuccessPath = "success"
	ctx.ErrPath = "error"

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
				ctx,
			),
			ExptdErr: "getClient",
		},
		{
			Handler: middleauth.NewCallbackHandler(
				getClient,
				getAuthUserError,
				findOrCreateUser,
				genSessionCookie,
				ctx,
			),
			ExptdErr: "getAuthUser",
		},
		{
			Handler: middleauth.NewCallbackHandler(
				getClient,
				getAuthUser,
				findOrCreateUserError,
				genSessionCookie,
				ctx,
			),
			ExptdErr: "findOrCreateUser",
		},
		{
			Handler: middleauth.NewCallbackHandler(
				getClient,
				getAuthUser,
				findOrCreateUser,
				genSessionCookieError,
				ctx,
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
		} else if want, have := test.ExptdErr, parsed.Query().Get("error_details"); want != have {
			t.Logf("query: %#v", parsed.Query().Encode())
			t.Errorf("wanted %#v, got %#v", want, have)
		} else if parsed.Query().Get("error_description") == "" {
			t.Error("unexpected empty message field.")
		}
	}
}
