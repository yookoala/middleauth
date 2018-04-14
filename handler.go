package middleauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/mrjones/oauth"

	"golang.org/x/oauth2"
)

// Context contains information about a specific handler setup
type Context struct {

	// CookieName contains the cookie name for authentications
	CookieName string

	// PublicURL contains the base URL for public to
	// access all paths within this context
	PublicURL *url.URL

	// Paths for doing login

	AuthPath    string
	TokenPath   string
	LoginPath   string
	LogoutPath  string
	SuccessPath string
	ErrPath     string
}

// NewContext creates a handler context from the given raw public url
func NewContext(rawPublicURL string) (ctx *Context, err error) {
	publicURL, err := url.Parse(rawPublicURL)
	if err != nil {
		return
	}
	ctx = &Context{
		PublicURL: publicURL,
	}
	return
}

// AuthURL returns the full auth endpoint URL
func (ctx Context) AuthURL(parts ...string) *url.URL {
	u := *ctx.PublicURL
	u.Path = path.Join(
		append([]string{u.Path, ctx.AuthPath}, parts...)...)
	return &u
}

// TokenURL returns the full auth endpoint URL
func (ctx Context) TokenURL(parts ...string) *url.URL {
	u := *ctx.PublicURL
	u.Path = path.Join(
		append([]string{u.Path, ctx.TokenPath}, parts...)...)
	return &u
}

// LoginURL returns the full login URL
func (ctx Context) LoginURL(parts ...string) *url.URL {
	u := *ctx.PublicURL
	u.Path = path.Join(
		append([]string{u.Path, ctx.LoginPath}, parts...)...)
	return &u
}

// LogoutURL returns the full logout URL
func (ctx Context) LogoutURL(parts ...string) *url.URL {
	u := *ctx.PublicURL
	u.Path = path.Join(
		append([]string{u.Path, ctx.LogoutPath}, parts...)...)
	return &u
}

// SuccessURL returns the full success URL
func (ctx Context) SuccessURL(parts ...string) *url.URL {
	u := *ctx.PublicURL
	u.Path = path.Join(
		append([]string{u.Path, ctx.SuccessPath}, parts...)...)
	return &u
}

// ErrURL returns the full error URL
func (ctx Context) ErrURL(parts ...string) *url.URL {
	u := *ctx.PublicURL
	u.Path = path.Join(
		append([]string{u.Path, ctx.ErrPath}, parts...)...)
	return &u
}

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

// OAuth1aCallbackDecoder generates ProviderClientFactory of the given
// consumer
func OAuth1aCallbackDecoder(c *oauth.Consumer, tokens TokenStore) CallbackReqDecoder {
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

// AuthUserDecoder is responsible to use the given
// context and http Client to make API calls and get
// information about the authenticating user.
type AuthUserDecoder func(ctx context.Context, client *http.Client) (ctxNext context.Context, authIdentity *UserIdentity, err error)

// UserStorageCallback is responsible to take the given authenticating
// user information, and
//
// 1. Search backend storage to see if the user already exists.
// 2. If not, create a user entry as appropriated.
// 3. Return a *User for cookie, or return nil with error.
type UserStorageCallback func(ctx context.Context, authIdentity *UserIdentity) (ctxNext context.Context, confirmedUser *User, err error)

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
	ctx *Context,
) http.Handler {
	return &CallbackHandler{
		getClient:        getClient,
		getAuthUser:      getAuthUser,
		findOrCreateUser: findOrCreateUser,
		genSessionCookie: genSessionCookie,
		ctx:              ctx,
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
	ctx              *Context
}

// ServeHTTP implements http.Handler
func (cbh *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	// for additional parameters
	errURL, _ := url.Parse(cbh.ctx.ErrURL().String())

	// get an *http.Client for the API call
	ctx, client, err := cbh.getClient(r)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to create API client")

		q := url.Values{}
		q.Add("message", "failed to create API client")
		q.Add("error", err.Error())
		errURL.RawQuery = q.Encode()
		http.Redirect(w, r, errURL.String(), http.StatusTemporaryRedirect)
		return
	}

	// get info of authenticating user from API calls
	ctx, authIdentity, err := cbh.getAuthUser(ctx, client)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed retrieve authenticating user info from OAuth2 provider")

		q := url.Values{}
		q.Add("message", "failed retrieve authenticating user info from OAuth2 provider")
		q.Add("error", err.Error())
		errURL.RawQuery = q.Encode()
		http.Redirect(w, r, errURL.String(), http.StatusTemporaryRedirect)
		return
	}

	// find or create user from the given info of
	// authenticating user
	ctx, confirmedUser, err := cbh.findOrCreateUser(ctx, authIdentity)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to find or create authenticating user")

		q := url.Values{}
		q.Add("message", "failed to find or create authenticating user")
		q.Add("error", err.Error())
		errURL.RawQuery = q.Encode()
		http.Redirect(w, r, errURL.String(), http.StatusTemporaryRedirect)
		return
	}

	// log success
	logrus.WithFields(logrus.Fields{
		"user.id":   confirmedUser.ID,
		"user.name": confirmedUser.Name,
	}).Info("user found or created.")

	// set authUser digest to cookie as jwt
	sessCookie := &http.Cookie{
		Name:     cbh.ctx.CookieName,
		Path:     "/",
		HttpOnly: true,
		Expires:  time.Now().Add(time.Hour), // expires in 1 hour
	}
	cookie, err := cbh.genSessionCookie(
		ctx,
		sessCookie,
		confirmedUser,
	)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err.Error(),
		}).Error("failed to generate session cookie")

		q := url.Values{}
		q.Add("message", "failed to generate session cookie")
		q.Add("error", err.Error())
		errURL.RawQuery = q.Encode()
		http.Redirect(w, r, errURL.String(), http.StatusTemporaryRedirect)
		return
	}

	// set the session cookie, then redirect user temporarily
	// temporary redirect user to success url
	//
	// TODO: implement custom redirect / success messages to success url
	http.SetCookie(w, cookie)
	http.Redirect(
		w, r,
		cbh.ctx.SuccessURL().String(),
		http.StatusTemporaryRedirect,
	)
}

// LogoutHandler makes a cookie of a given name expires
func LogoutHandler(ctx *Context) http.HandlerFunc {
	redirectURL := ctx.SuccessURL().String()
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(ctx.CookieName)
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
	ctx *Context,
) http.Handler {

	loginPath := ensureTrailingSlash(ctx.LoginURL().Path)
	errURL := ctx.ErrURL().Path

	// Note: oauth2Path must start with "/" and must not have trailing slash
	// Note: publicURL must be full URL without path or any trailing slash

	mux := http.NewServeMux()
	tokenStore := NewTokenStore()

	if provider := FindProvider("google", providers); provider != nil {
		mux.Handle(loginPath+"google", RedirectHandler(
			OAuth2AuthURLFactory(GoogleConfig(
				*provider,
				ctx.LoginURL("google/callback").String(),
			)),
			errURL,
		))
		mux.Handle(
			loginPath+"google/callback",
			NewCallbackHandler(
				OAuth2CallbackDecoder(GoogleConfig(
					*provider,
					ctx.LoginURL("google/callback").String(),
				)),
				GoogleAuthUserFactory,
				userStorageCallback,
				cookieFactory,
				ctx,
			),
		)
	}

	if provider := FindProvider("facebook", providers); provider != nil {
		mux.Handle(loginPath+"facebook", RedirectHandler(
			OAuth2AuthURLFactory(FacebookConfig(
				*provider,
				ctx.LoginURL("facebook/callback").String(),
			)),
			errURL,
		))
		mux.Handle(
			loginPath+"facebook/callback",
			NewCallbackHandler(
				OAuth2CallbackDecoder(FacebookConfig(
					*provider,
					ctx.LoginURL("facebook/callback").String(),
				)),
				FacebookAuthUserFactory,
				userStorageCallback,
				cookieFactory,
				ctx,
			),
		)
	}

	if provider := FindProvider("github", providers); provider != nil {
		mux.Handle(loginPath+"github", RedirectHandler(
			OAuth2AuthURLFactory(GithubConfig(
				*provider,
				ctx.LoginURL("github/callback").String(),
			)),
			errURL,
		))
		mux.Handle(
			loginPath+"github/callback",
			NewCallbackHandler(
				OAuth2CallbackDecoder(GithubConfig(
					*provider,
					ctx.LoginURL("github/callback").String(),
				)),
				GithubAuthUserFactory,
				userStorageCallback,
				cookieFactory,
				ctx,
			),
		)
	}

	if provider := FindProvider("twitter", providers); provider != nil {
		mux.Handle(loginPath+"twitter", RedirectHandler(
			OAuth1aAuthURLFactory(
				TwitterConsumer(*provider),
				ctx.LoginURL("twitter/callback").String(),
				tokenStore,
			),
			errURL,
		))
		mux.Handle(
			loginPath+"twitter/callback",
			NewCallbackHandler(
				OAuth1aCallbackDecoder(
					TwitterConsumer(*provider),
					tokenStore,
				),
				TwitterAuthUserFactory,
				userStorageCallback,
				cookieFactory,
				ctx,
			),
		)
	}

	return mux
}

const loginPageDefaultCSS = `
{{ define "defaultCSS" }}
#page-login {
	margin: 0;
	font-family: san-serif;
	background-color: #EEE;
}
#page-login h1 {
	font-size: 1.3em;
	margin: 1em 0 2em;
	text-align: center;
}

#login-box {
	max-width: 300px;
	margin: calc(50vh - 250px) auto 0;
	padding: 30px 50px;
	box-shadow: 1px 1px 10px #999;
	background-color: #FFF;}
#login-box .actions .btn {
	background-color: #444;
	color: #FFF;
	display: block;
	margin: 0.5em;
	padding: 0.5em 1em;
	border-radius: 0.2em;
	text-decoration: none;
	text-align: center;
	font-weight: bold;
	transition: opacity 0.5s;
}
#login-box .actions .btn:hover {
	opacity: 0.7;
}
#login-box .actions .btn-login-google {
	background-color: #DB4437;
}
#login-box .actions .btn-login-facebook {
	background-color: #3B5998;
}
#login-box .actions .btn-login-twitter {
	background-color: #1DA1F2;
}
#login-box .actions .btn-login-github {
	background-color: #24292E;
}
#login-box .no-actions .messages {
	padding: 0.5em 1em;
	background-color: #FDD;
	color: #A00;
	text-align: center;
	border: 1px solid #A00;
}
{{ end }}
`

const loginPageHTML = `
<!doctype html>
<html>
<head>
<title>{{ if .PageHeaderTitle }}{{ .PageHeaderTitle }}{{ else if .PageTitle }}{{ .PageTitle }}{{ else }}Login{{ end }}</title>
{{ range $index, $style := .Stylesheets }}
  <link rel="stylesheet" type="text/css" href="{{ $style }}">
{{ else }}
<style>
{{ template "defaultCSS" }}
</style>
{{ end }}
</head>
<body id="page-login">
<main id="login-box">
<h1>{{ if .PageTitle }}{{ .PageTitle }}{{ else }}Login{{ end }}</h1>
{{ if .Actions }}
  <div class="actions">
	{{ $loginPath := .LoginPath }}
    {{ range $action := .Actions }}
      <a class="btn btn-login-{{ $action.ID }}" href="{{ $loginPath }}{{ $action.ID }}">{{ $action.Name }}</a>
    {{ end }}
  </div>
{{ else }}
  <div class="no-actions">
    <div class="messages">
      <p>
        {{ if .NoticeNoAction }}{{ .NoticeNoAction }}{{ else }}Please setup authentication provider.{{ end }}
      </p>
    </div>
  </div>
{{ end }}
</main>
</body>
{{ range $index, $script := .Scripts }}
  <script src="{{ $script }}"></script>
{{ end }}
</html>
`

// LoginPageContent is the contents to be filled to the login page
type LoginPageContent struct {
	PageTitle       string
	PageHeaderTitle string
	LoginPath       string
	Stylesheets     []string
	Actions         []AuthProvider
	NoticeNoAction  string
}

// LoginPageContentCallback returns LoginPageContent for a given
// http.Request
type LoginPageContentCallback func(r *http.Request) LoginPageContent

// LoginPageHandler returns an http.HandlerFunc for
// a plain simple login page
func LoginPageHandler(getContent LoginPageContentCallback) http.HandlerFunc {
	loginTemplate := template.New("login")
	loginTemplate = template.Must(loginTemplate.Parse(loginPageHTML))
	loginTemplate = template.Must(loginTemplate.Parse(loginPageDefaultCSS))
	return func(w http.ResponseWriter, r *http.Request) {
		loginTemplate.Execute(w, getContent(r))
	}
}

func ensureLeadingSlash(path string) string {
	return "/" + strings.TrimLeft(path, "/")
}

func ensureTrailingSlash(path string) string {
	return strings.TrimRight(path, "/") + "/"
}

// CommonHandler generates a common login / logout paths
// handler from LoginHandler, LoginPageHandler and LogoutHandler
func CommonHandler(
	mux *http.ServeMux,
	providers []AuthProvider,
	userStorageCallback UserStorageCallback,
	cookieFactory CookieFactory,
	ctx *Context,
) *http.ServeMux {

	// TODO: remove intermediate paths
	loginPath := ensureTrailingSlash(ctx.LoginURL().Path)

	// Handle login paths.
	// Note: Trailing slash of loginPath is required for mux
	// to correctly route all the sub-path within to the same handler.
	mux.Handle(loginPath, LoginHandler(
		userStorageCallback,
		cookieFactory,
		providers,
		ctx,
	))

	// handle login page
	mux.Handle(ctx.AuthPath, LoginPageHandler(
		func(r *http.Request) LoginPageContent {
			return LoginPageContent{
				PageHeaderTitle: "Login | Example Server",
				PageTitle:       "Login to Example Server",
				LoginPath:       loginPath,
				Actions:         providers,
			}
		},
	))

	// handle logout path
	mux.Handle(ctx.LogoutPath, LogoutHandler(ctx))
	return mux
}
