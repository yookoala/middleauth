package middleauth

import (
	"context"
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/mrjones/oauth"

	"golang.org/x/oauth2"
)

// AuthURLFactory manufactures redirectURLs to authentication endpoint
// with the correct callback path back to the application site.
type AuthURLFactory func(r *http.Request) (redirectURL string, err error)

// OAuth2AuthURLFactory generates factory of authentication URL
// to the oauth2 config
func OAuth2AuthURLFactory(conf *oauth2.Config) AuthURLFactory {
	return func(r *http.Request) (url string, err error) {
		url = conf.AuthCodeURL("state", oauth2.AccessTypeOffline)
		return
	}
}

// OAuth1aConsumer provide ways to get reuest token and auth url
type OAuth1aConsumer interface {
	GetRequestTokenAndUrl(callbackURL string) (token *oauth.RequestToken, url string, err error)
}

// OAuth1aAuthURLFactory generates factory of authentication URL
// to the oauth1a consumer and callback URL
func OAuth1aAuthURLFactory(c OAuth1aConsumer, callbackURL string, tokens TokenStore) AuthURLFactory {
	return func(r *http.Request) (url string, err error) {
		requestToken, url, err := c.GetRequestTokenAndUrl(callbackURL)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("error retrieving access token.")
			return
		}
		tokens.Save(requestToken)
		return
	}
}

// RedirectHandler handles the generation and redirection to
// authentication endpoint with proper parameters
func RedirectHandler(getAuthURL AuthURLFactory, errURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url, err := getAuthURL(r)
		if err != nil {
			// TODO: redirect to the errURL with status messages
			http.Redirect(w, r, errURL, http.StatusTemporaryRedirect)
			return
		}
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

// CallbackReqDecoder is responsible to, according to
// the callback endpoint request, formulate
//
// 1. A context for follow up callback to use;
// 2. The http Client for API calls based on the token; and
// 3. Error, if any step prodcued one.
type CallbackReqDecoder func(r *http.Request) (ctxNext context.Context, client *http.Client, err error)

// OAuth2CallbackDecoder implements CallbackReqDecoder
func OAuth2CallbackDecoder(conf *oauth2.Config) CallbackReqDecoder {
	return func(r *http.Request) (ctxNext context.Context, client *http.Client, err error) {
		code := r.URL.Query().Get("code")
		token, err := conf.Exchange(oauth2.NoContext, code)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err.Error(),
			}).Error("code exchange failed")
			return
		}
		client = conf.Client(r.Context(), token)
		return
	}
}

// AuthUserDecoder is responsible to use the given
// context and http Client to make API calls and get
// information about the authenticating user.
type AuthUserDecoder func(ctx context.Context, client *http.Client) (ctxNext context.Context, authUser *User, err error)

// UserStorageCallback is responsible to take the given authenticating
// user information, and
//
// 1. Search backend storage to see if the user already exists.
// 2. If not, create a user entry as appropriated.
// 3. Return a *User for cookie, or return nil with error.
type UserStorageCallback func(ctx context.Context, authUser *User) (ctxNext context.Context, confirmedUser *User, err error)

// CookieFactory process the given authentication information
// into some kind of session storage made available with cookies.
type CookieFactory func(ctx context.Context, in *http.Cookie, confirmedUser *User) (out *http.Cookie, err error)

// NewCallbackHandler creates a callback handler with the provided
// callbacks and information
func NewCallbackHandler(
	getClient CallbackReqDecoder,
	getAuthUser AuthUserDecoder,
	findOrCreateUser UserStorageCallback,
	genSessionCookie CookieFactory,
	successURL string,
	errURL string,
) http.Handler {
	return &CallbackHandler{
		getClient:        getClient,
		getAuthUser:      getAuthUser,
		findOrCreateUser: findOrCreateUser,
		genSessionCookie: genSessionCookie,
		successURL:       successURL,
		errURL:           errURL,
	}
}

// CallbackHandler is responsible to SetterSetterproduce
// an http.Handler that, with given callbacks functions,
// handle the OAuth2 / OAuth callback endpoint of a certain
// provider.
type CallbackHandler struct {
	getClient        CallbackReqDecoder
	getAuthUser      AuthUserDecoder
	findOrCreateUser UserStorageCallback
	genSessionCookie CookieFactory
	successURL       string
	errURL           string
}

// ServeHTTP implements http.Handler
func (cbh *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// get an *http.Client for the API call
	ctx, client, err := cbh.getClient(r)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to create API client")
		http.Redirect(w, r, cbh.errURL, http.StatusTemporaryRedirect)
	}

	// get info of authenticating user from API calls
	ctx, authUser, err := cbh.getAuthUser(ctx, client)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed retrieve authenticating user info from OAuth2 provider")
		http.Redirect(w, r, cbh.errURL, http.StatusTemporaryRedirect)
	}

	// find or create user from the given info of
	// authenticating user
	ctx, confirmedUser, err := cbh.findOrCreateUser(ctx, authUser)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to find or create authenticating user")
		http.Redirect(w, r, cbh.errURL, http.StatusTemporaryRedirect)
	}

	// log success
	logrus.WithFields(logrus.Fields{
		"user.id":   authUser.ID,
		"user.name": authUser.Name,
	}).Info("user found or created.")

	// set authUser digest to cookie as jwt
	sessCookie := &http.Cookie{}
	cookie, err := cbh.genSessionCookie(
		ctx,
		sessCookie,
		confirmedUser,
	)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to generate session cookie")
		http.Redirect(w, r, cbh.errURL, http.StatusTemporaryRedirect)
	}

	// set the session cookie, then redirect user temporarily
	// temporary redirect user to success url
	http.SetCookie(w, cookie)
	http.Redirect(
		w, r,
		cbh.successURL,
		http.StatusTemporaryRedirect,
	)
}

// LogoutHandler makes a cookie of a given name expires
func LogoutHandler(redirectURL string, cookieName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			// should have encountered http.ErrNoCookie
			// no cookie to logout from
			// TODO: figure how we should handle this.
			return
		}
		cookie.Expires = time.Now().Add(-1 * time.Hour) // expires immediately
		http.SetCookie(w, cookie)
		http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
	}
}

// LoginHandler return a mux to handle all login related routes
func LoginHandler(
	userStorageCallback UserStorageCallback,
	cookieFactory CookieFactory,
	providers []AuthProvider,
	baseURL, oauth2Path, successPath, errPath string,
) http.Handler {

	// Note: oauth2Path must start with "/" and must not have trailing slash
	// Note: baseURL must be full URL without path or any trailing slash

	mux := http.NewServeMux()
	oauth2URL := baseURL + oauth2Path   // full URL to oauth2 path
	successURL := baseURL + successPath // full URL to success page
	tokenStore := tokenStore(make(map[string]*oauth.RequestToken, 1024))

	if provider := FindProvider("google", providers); provider != nil {
		mux.Handle(oauth2Path+"/google", RedirectHandler(
			OAuth2AuthURLFactory(GoogleConfig(
				*provider,
				oauth2URL+"/google/callback",
			)),
			errPath,
		))
		mux.Handle(
			oauth2Path+"/google/callback",
			NewCallbackHandler(
				OAuth2CallbackDecoder(GoogleConfig(
					*provider,
					oauth2URL+"/google/callback",
				)),
				GoogleAuthUserFactory,
				userStorageCallback,
				cookieFactory,
				successURL,
				errPath,
			),
		)
	}

	if provider := FindProvider("facebook", providers); provider != nil {
		mux.Handle(oauth2Path+"/facebook", RedirectHandler(
			OAuth2AuthURLFactory(FacebookConfig(
				*provider,
				oauth2URL+"/facebook/callback",
			)),
			errPath,
		))
		mux.Handle(
			oauth2Path+"/facebook/callback",
			NewCallbackHandler(
				OAuth2CallbackDecoder(FacebookConfig(
					*provider,
					oauth2URL+"/facebook/callback",
				)),
				FacebookAuthUserFactory,
				userStorageCallback,
				cookieFactory,
				successURL,
				errPath,
			),
		)
	}

	if provider := FindProvider("github", providers); provider != nil {
		mux.Handle(oauth2Path+"/github", RedirectHandler(
			OAuth2AuthURLFactory(GithubConfig(
				*provider,
				oauth2URL+"/github/callback",
			)),
			errPath,
		))
		mux.Handle(
			oauth2Path+"/github/callback",
			NewCallbackHandler(
				OAuth2CallbackDecoder(GithubConfig(
					*provider,
					oauth2URL+"/github/callback",
				)),
				FacebookAuthUserFactory,
				userStorageCallback,
				cookieFactory,
				successURL,
				errPath,
			),
		)
	}

	if provider := FindProvider("twitter", providers); provider != nil {
		mux.Handle(oauth2Path+"/twitter", RedirectHandler(
			OAuth1aAuthURLFactory(
				TwitterConsumer(*provider),
				oauth2URL+"/twitter/callback",
				tokenStore,
			),
			errPath,
		))
		mux.Handle(
			oauth2Path+"/twitter/callback",
			NewCallbackHandler(
				TwitterClientFactory(
					TwitterConsumer(*provider),
					tokenStore,
				),
				TwitterAuthUserFactory,
				userStorageCallback,
				cookieFactory,
				successURL,
				errPath,
			),
		)
	}

	return mux
}
