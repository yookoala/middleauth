package middleauth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	uuid "github.com/satori/go.uuid"
	"gopkg.in/jose.v1/crypto"
)

func TestAuthJWTCookie(t *testing.T) {

	// parameter for creating cookie
	expiration := time.Now().Add(10 * time.Second)
	cookie := &http.Cookie{
		Expires: expiration,
		Domain:  "localhost",
	}
	jwtKey := fmt.Sprintf("%d", time.Now().UnixNano())

	var userID uuid.UUID
	userID, _ = uuid.NewV4()
	user := User{
		ID:           userID.String(),
		Name:         "Hello User",
		PrimaryEmail: "hello@foobar.com",
	}

	// assign cookie value
	cookie = authJWTCookie(cookie, jwtKey, crypto.SigningMethodHS256, user)

	token, err := DecodeTokenStr(jwtKey, cookie.Value, crypto.SigningMethodHS256)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}

	claims := token.Claims()

	if want, have := user.ID, claims.Get("id"); want != have {
		t.Errorf("expected %T(%#v), got %T(%#v)", want, want, have, have)
	}

	if want, have := user.Name, claims.Get("name"); want != have {
		t.Errorf("expected %T(%#v), got %T(%#v)", want, want, have, have)
	}

	if audiences, ok := claims.Audience(); !ok {
		t.Errorf("not audience set in claims")
	} else if len(audiences) != 1 {
		t.Errorf("expected 1 audience, got %#v", audiences)
	} else if want, have := cookie.Domain, audiences[0]; want != have {
		t.Errorf("expected %T(%#v), got %T(%#v)", want, want, have, have)
	}

	if have, ok := claims.Expiration(); !ok {
		t.Errorf("no expiration found")
	} else if want := expiration; want.Unix() != have.Unix() {
		t.Errorf("expected %s, got %s", want, have)
	}
}
