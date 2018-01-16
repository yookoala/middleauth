package middleauth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
	"gopkg.in/jose.v1/jwt"
)

// DecodeTokenStr parses token string into JWT token
func DecodeTokenStr(key, tokenStr string, method crypto.SigningMethod) (token jwt.JWT, err error) {
	token, _ = jws.ParseJWT([]byte(tokenStr))
	if err = token.Validate([]byte(key), method); err != nil {
		err = fmt.Errorf("error validating token: %s", err.Error())
		return
	}
	return
}

// EncodeTokenStr encode a given claim as a JWT token string
func EncodeTokenStr(key string, claims jws.Claims, method crypto.SigningMethod) (tokenStr string, err error) {
	jwtToken := jws.NewJWT(claims, method)
	serializedToken, err := jwtToken.Serialize([]byte(key))
	tokenStr = string(serializedToken)
	return
}

// (obsoleted, will be replaced with the new JWTSession)
func authJWTCookie(cookie *http.Cookie, jwtKey string, method crypto.SigningMethod, authUser User) *http.Cookie {

	// Create JWS claims with the user info
	claims := jws.Claims{}
	claims.Set("id", authUser.ID)
	claims.Set("name", authUser.Name)
	claims.SetAudience(cookie.Domain)
	claims.SetExpiration(cookie.Expires)

	// encode token and store in cookies
	cookie.Value, _ = EncodeTokenStr(jwtKey, claims, method)
	return cookie
}

// JWTSession produces a CookieFractory from given JWT key and signing method
// to create a JWT based cookie
func JWTSession(cookieName, jwtKey string, method crypto.SigningMethod) CookieFactory {
	return func(ctx context.Context, in *http.Cookie, confirmedUser *User) (cookie *http.Cookie, err error) {

		cookie = in
		cookie.Name = cookieName

		// Create JWS claims with the user info
		// TODO: need to have middleware for claims
		claims := jws.Claims{}
		claims.Set("id", confirmedUser.ID)
		claims.Set("name", confirmedUser.Name)
		claims.SetAudience(cookie.Domain)
		claims.SetExpiration(cookie.Expires)

		// encode token and store in cookies
		cookie.Value, _ = EncodeTokenStr(jwtKey, claims, method)
		return
	}
}

// SessionExpires is a middleware for CookieFactory which apply
// an expiration period to the cookie created.
func SessionExpires(d time.Duration) func(inner CookieFactory) CookieFactory {
	return func(inner CookieFactory) CookieFactory {
		return func(ctx context.Context, in *http.Cookie, confirmedUser *User) (cookie *http.Cookie, err error) {
			if in == nil {
				return inner(ctx, in, confirmedUser)
			}
			cookie = in
			cookie.Expires = time.Now().Add(d)
			return inner(ctx, cookie, confirmedUser)
		}
	}
}

// JWTSessionDecoder return a SessionDecoder that decodes a JWT cookie session
// and return the user found.
func JWTSessionDecoder(cookieName, jwtKey string, method crypto.SigningMethod) SessionDecoder {
	return func(r *http.Request) (userID string, err error) {

		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return
		}

		token, err := DecodeTokenStr(jwtKey, cookie.Value, method)
		if err != nil {
			err = fmt.Errorf("token reading error (%s)", err.Error())
			return
		}

		idRaw := token.Claims().Get("id")
		if idRaw == nil {
			err = fmt.Errorf("invalid user id in token (id is nil)")
			return
		}

		switch id := idRaw.(type) {
		case string:
			userID = id
		default:
			err = fmt.Errorf("invalid user id in token (id should be string)")
		}
		return
	}
}
