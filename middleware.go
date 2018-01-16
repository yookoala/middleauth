package middleauth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/go-midway/midway"
)

type contextKey int

const (
	userKey contextKey = iota
)

// WithUser add a *User to a given context
func WithUser(parent context.Context, user *User) context.Context {
	return context.WithValue(parent, userKey, user)
}

// GetUser gets a *User, if exists, from a context
func GetUser(ctx context.Context) (user *User) {
	userRaw := ctx.Value(userKey)
	user, _ = userRaw.(*User)
	return
}

// SessionDecoder decodes the request into userID
type SessionDecoder func(r *http.Request) (userID uint, err error)

// RetrieveUser retrieves a user by the given user id
type RetrieveUser func(ctx context.Context, id uint) (*User, error)

// SessionMiddleware retrieves the session user, if any, from
// the given cookie key and storage access.
func SessionMiddleware(decodeSession SessionDecoder, retrieveUser RetrieveUser) midway.Middleware {
	return func(inner http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// decode user id from session
			userID, err := decodeSession(r)
			if err == http.ErrNoCookie {
				// ignore the middleware logic
				// and go to the inner handler
				inner.ServeHTTP(w, r)
				return
			} else if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "bad request: %s", err.Error())
				return
			}

			// get user of the user id
			user, err := retrieveUser(r.Context(), uint(userID))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintf(w, "bad request: %s", err.Error())
				return
			}

			// pass the request to inner handler with
			// the context storing the user.
			inner.ServeHTTP(w, r.WithContext(WithUser(r.Context(), user)))
		})
	}
}
