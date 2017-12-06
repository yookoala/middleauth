package middleauth_test

import (
	"fmt"
	"testing"

	"github.com/yookoala/middleauth"
)

func TestLoginErrorType(t *testing.T) {
	tests := []struct {
		err error
		str string
	}{
		{
			err: middleauth.ErrUnknown,
			str: "unknown error",
		},
		{
			err: middleauth.ErrNoEmail,
			str: "no email",
		},
		{
			err: middleauth.ErrDatabase,
			str: "database error",
		},
	}

	for _, test := range tests {
		if want, have := fmt.Sprintf("LoginError(%#v)", test.str), fmt.Sprintf("%#v", test.err); want != have {
			t.Errorf("expected %#v String() to give %#v, got %#v", test.err, want, have)
		}
		if want, have := "login error: "+test.str, fmt.Sprintf("%s", test.err); want != have {
			t.Errorf("expected %#v String() to give %#v, got %#v", test.err, want, have)
		}
	}
}

func TestLoginError(t *testing.T) {
	tests := []struct {
		err   middleauth.LoginError
		str   string
		gostr string
	}{
		{
			err:   middleauth.LoginError{},
			str:   "unknown error",
			gostr: `"unknown error"`,
		},
		{
			err: middleauth.LoginError{
				Type: middleauth.ErrNoEmail,
			},
			str:   "no email",
			gostr: `"no email"`,
		},
		{
			err: middleauth.LoginError{
				Type: middleauth.ErrDatabase,
			},
			str:   "database error",
			gostr: `"database error"`,
		},
		{
			err: middleauth.LoginError{
				Type: middleauth.ErrDatabase,
				Err:  fmt.Errorf("some dummy error"),
			},
			str:   `error="some dummy error"`,
			gostr: `error="some dummy error"`,
		},
		{
			err: middleauth.LoginError{
				Type:   middleauth.ErrDatabase,
				Action: "create dummy",
				Err:    fmt.Errorf("some dummy error"),
			},
			str:   `action="create dummy" error="some dummy error"`,
			gostr: `action="create dummy" error="some dummy error"`,
		},
	}

	for _, test := range tests {
		if want, have := fmt.Sprintf("LoginError(%s)", test.gostr), fmt.Sprintf("%#v", test.err); want != have {
			t.Errorf("expected %#v String() to give %#v, got %#v", test.err, want, have)
		}
		if want, have := "login error: "+test.str, fmt.Sprintf("%s", test.err); want != have {
			t.Errorf("expected %#v String() to give %#v, got %#v", test.err, want, have)
		}
	}

}
