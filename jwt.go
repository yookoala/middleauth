package middleauth

import (
	"context"
	"fmt"
	"log"
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

		// Create JWS claims with the user info
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
			log.Printf("cookie: %#v", cookie)
			if cookie != nil {
				cookie.Expires = time.Now().Add(d)
			}
			return inner(ctx, in, confirmedUser)
		}
	}
}
