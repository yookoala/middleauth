# middleauth [![Build Status][travis-shield]][travis-link]

An OAuth2 user authentication and authorization as a Golang middleware.

[travis-link]: https://travis-ci.org/yookoala/middleauth
[travis-shield]: https://api.travis-ci.org/yookoala/middleauth.svg?branch=master

## Getting Start

Say you're writing a web app with a page like this:

```go
app := http.NewServeMux()
app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    user := GetSessionUser(r)
    w.Header().Add("Content-Type", "text/html;charset=utf-8")
    if user != nil {
        fmt.Fprintf(w, `Hello <a href="mailto:%s">%s</a>. You may <a href="/logout">logout here</a>`, user.PrimaryEmail, user.Name)
    } else {
        fmt.Fprintf(w, `You have not login. Please <a href="/login">login here</a>.`)
    }
})
http.ServeAndListen(":8080", app)
```

Usually we get the User from session cookie, header value or some GET parameter. But we
have to get it written there in the first place. So we have to write codes to:

1. Authenticate a user.
1. Store some user identifications into cookie / header / localStorage.
1. Then when a request come with the session identity, we need to extract user
   information by it.
1. Then we do program logic with the user.

How about we do the **first 3 steps** in some reusable fashion?

Say we add some middleware to the app:

```go

// the original app
app := http.NewServeMux()
app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    user := middleauth.GetUser(r.Context())
    w.Header().Add("Content-Type", "text/html;charset=utf-8")
    if user != nil {
        fmt.Fprintf(w, `Hello <a href="mailto:%s">%s</a>. You may <a href="/logout">logout here</a>`, user.PrimaryEmail, user.Name)
    } else {
        fmt.Fprintf(w, `You have not login. Please <a href="/login">login here</a>.`)
    }
})

// retrieve user from gorm storage
// then store it into request context for handler to use
http.ServeAndListen(":8080", middleauth.SessionMiddleware(
    middleauth.JWTSessionDecoder(cookieName, jwtKey, crypto.SigningMethodHS256),
    gormstorage.RetrieveUser(db),
)(app))

```

Oh, we need to handle the logins in the first place. So some path and redirection and cookie...

Say we use Google or Facebook as authentication providers. And we use gorm as storage engine to
create / find user to authenticate with. Then we store user ID with JWT in a cookie of a
name of your choice:

```go

// the original app
app := http.NewServeMux()
app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    user := middleauth.GetUser(r.Context())
    w.Header().Add("Content-Type", "text/html;charset=utf-8")
    if user != nil {
        fmt.Fprintf(w, `Hello <a href="mailto:%s">%s</a>. You may <a href="/logout">logout here</a>`, user.PrimaryEmail, user.Name)
    } else {
        fmt.Fprintf(w, `You have not login. Please <a href="/login">login here</a>.`)
    }
})

// outer mux
mux := http.NewServeMux()

// handles the common paths:
// 1. login page
// 2. login redirect and callback for OAuth2 / OAuth1.0a
middleauth.CommonHandler(
    mux,
    middleauth.EnvProviders(os.Getenv),
    gormstorage.UserStorageCallback(db),
    middleauth.JWTSession(cookieName, jwtKey, crypto.SigningMethodHS256),
    cookieName,
    publicURL,
    "/login",
    "/login/oauth2",
    "/logout",
    publicURL,
    publicURL+"/error",
)

// serve the app at root, if not within the login path
mux.Handle("/", middleauth.SessionMiddleware(
    middleauth.JWTSessionDecoder(cookieName, jwtKey, crypto.SigningMethodHS256),
    gormstorage.RetrieveUser(db),
)(app))

http.ServeAndListen(":8080", mux)

```

Make sense?

**middleauth** works with any http.Handler implementations. So any framework that works with http.Handler, middleauth works with you.

Also components are written in `type` and `interface`. You may usually rewrite code base on your needs.

You may see the [example-server](cmd/example-server) code to further understand it in and out.