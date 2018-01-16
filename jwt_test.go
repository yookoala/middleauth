package middleauth_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/yookoala/middleauth"

	"gopkg.in/jose.v1/crypto"
	"gopkg.in/jose.v1/jws"
)

func TestDecodeTokenStr(t *testing.T) {
	key := "abcdef"
	claims := jws.Claims{
		"hello": "world",
		"foo":   "bar",
	}
	jwtToken := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := jwtToken.Serialize([]byte(key))

	parsedToken, err := middleauth.DecodeTokenStr(
		key,
		string(serializedToken),
		crypto.SigningMethodHS256,
	)
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	for claimName, value := range jwtToken.Claims() {
		if !parsedToken.Claims().Has(claimName) {
			t.Errorf("result token does not have %#v claim", claimName)
		} else if want, have := value, parsedToken.Claims()[claimName]; want != have {
			t.Errorf("expected %#v for claim %#v, got %#v", want, claimName, have)
		}
	}
}

func TestDecodeTokenStr_error(t *testing.T) {
	key := "abcdef"
	claims := jws.Claims{
		"hello": "world",
		"foo":   "bar",
	}
	jwtToken := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := jwtToken.Serialize([]byte(key))

	_, err := middleauth.DecodeTokenStr(
		"wrongkey",
		string(serializedToken),
		crypto.SigningMethodHS256,
	)
	if err == nil {
		t.Errorf("expected error and got nil")
	}
	if want, have := "error validating token: signature is invalid", err.Error(); want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
}

func TestDecodeTokenStr_expired(t *testing.T) {
	key := "abcdef"
	claims := jws.Claims{
		"hello": "world",
		"foo":   "bar",
	}
	claims.SetExpiration(time.Now().Add(-60 * time.Second)) // expired 60 seconds before
	jwtToken := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := jwtToken.Serialize([]byte(key))

	_, err := middleauth.DecodeTokenStr(
		key,
		string(serializedToken),
		crypto.SigningMethodHS256,
	)
	if err == nil {
		t.Errorf("expected error and got nil")
	}
	if want, have := "error validating token: token is expired", err.Error(); want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
}

func TestEncodeTokenStr(t *testing.T) {
	key := "tyuiop"
	claims := jws.Claims{
		"hello": "world",
		"foo":   "bar",
	}
	tokenStr, err := middleauth.EncodeTokenStr(
		key,
		claims,
		crypto.SigningMethodHS256,
	)
	if err != nil {
		t.Errorf("unexpected error %#v", err.Error())
	}

	parsedToken, err := middleauth.DecodeTokenStr(
		key,
		tokenStr,
		crypto.SigningMethodHS256,
	)

	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	for claimName, value := range claims {
		if !parsedToken.Claims().Has(claimName) {
			t.Errorf("result token does not have %#v claim", claimName)
		} else if want, have := value, parsedToken.Claims()[claimName]; want != have {
			t.Errorf("expected %#v for claim %#v, got %#v", want, claimName, have)
		}
	}
}

func TestJWTSession(t *testing.T) {
	jwtKey := "dummy-jwt-key"
	method := crypto.SigningMethodHS256

	var userID uuid.UUID
	userID, _ = uuid.NewV4()

	factory := middleauth.JWTSession("dummy-cookie", jwtKey, method)
	confirmedUser := middleauth.User{
		ID:   userID.String(),
		Name: "dummy user",
	}

	// generate cookie from factory
	cookie, err := factory(
		context.TODO(),
		&http.Cookie{
			Expires: time.Now().Add(1 * time.Hour),
		},
		&confirmedUser,
	)
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}

	// decode cookie value as token
	token, err := middleauth.DecodeTokenStr(jwtKey, cookie.Value, method)
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	claims := token.Claims()
	if haveRaw, ok := claims.Get("id").(string); !ok {
		have := claims.Get("id")
		t.Errorf("expected uuid string, got: %T(%#v)", have, have)
	} else if want, have := confirmedUser.ID, haveRaw; want != have {
		t.Errorf("expected: %#v, got: %#v", want, have)
	}
	if want, have := confirmedUser.Name, claims.Get("name"); want != have {
		t.Errorf("expected: %#v, got: %#v", want, have)
	}
}

func TestSessionExpires(t *testing.T) {
	m := middleauth.SessionExpires(123 * time.Hour)
	factory := func(ctx context.Context, in *http.Cookie, confirmedUser *middleauth.User) (cookie *http.Cookie, err error) {
		cookie = in
		return
	}
	factory = m(factory)

	factory(
		context.TODO(),
		&http.Cookie{
			Expires: time.Now().Add(1 * time.Hour),
		},
		nil,
	)
}
