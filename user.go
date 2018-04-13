package middleauth

import (
	"fmt"
	"time"
)

// User object
type User struct {
	ID           string `json:"id" gorm:"type:varchar(36);primary_key"`
	Name         string `json:"name" gorm:"type:varchar(255)"`
	PrimaryEmail string `json:"primary_email" gorm:"type:varchar(100);unique_index"`
	Verified     bool   `json:"verified"` // if the primary email is verified
	Emails       []UserEmail
	Password     string `gorm:"type:varchar(255)"`
	IsAdmin      bool

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `sql:"index"`
}

// UserEmail contains user and email relationship
type UserEmail struct {
	ID       string `json:"id" gorm:"type:varchar(36);primary_key"`
	UserID   string `json:"user_id" gorm:"type:varchar(36);index"`
	Email    string `json:"email" gorm:"type:varchar(100);unique_index"`
	Verified bool   `json:"verified"`
}

// UserIdentity stores OAuth2 vendor identity for a user
type UserIdentity struct {
	UserID       string   `json:"user_id" gorm:"type:varchar(36);index"`
	Name         string   `json:"name" gorm:"type:varchar(255)"`
	Type         string   `json:"type" gorm:"type:varchar(255)"`
	Provider     string   `json:"provider" gorm:"type:varchar(255);primary_key"`
	ProviderID   string   `json:"provider_id" gorm:"type:varchar(255);primary_key"`
	Verified     bool     `json:"verified"`
	PrimaryEmail string   `json:"primary_email" gorm:"type:varchar(255)"`
	Emails       []string `json:"-" gorm:"-"` // only to reference in account creation
}

// LoginErrorType represents the type of LoginError
type LoginErrorType int

// Error implements error interface
func (err LoginErrorType) Error() string {
	return "login error: " + err.String()
}

// String implements Stringer interface
func (err LoginErrorType) String() string {
	switch err {
	case ErrDatabase:
		return "database error"
	case ErrUserNotFound:
		return "user not found"
	case ErrNoEmail:
		return "no email"
	case ErrNoProvider:
		return "no provider"
	case ErrNoProviderID:
		return "no provider id"
	case ErrUserEmailNotVerified:
		return "user primary email is not verified"
	case ErrUserIdentityNotVerified:
		return "identity is not verified"
	}
	return "unknown error"
}

// GoString implements GoStringer interface
func (err LoginErrorType) GoString() string {
	return "LoginError(\"" + err.String() + "\")"
}

const (
	// ErrUnknown represents all unknown errors
	ErrUnknown LoginErrorType = iota

	// ErrDatabase represents database server errors
	ErrDatabase

	// ErrUserNotFound happens if the user of the given
	// login identity is deleted.
	ErrUserNotFound

	// ErrNoEmail happens if the UserIdentity decoded
	// has no primary email
	ErrNoEmail

	// ErrNoProvider happens if the UserIdentity decoded
	// has no provider defined
	ErrNoProvider

	// ErrNoProviderID happens if the UserIdentity decoded
	// has no provider id defined
	ErrNoProviderID

	// ErrUserEmailNotVerified happens if the login user is login
	// but his PrimaryEmail is not verified.
	ErrUserEmailNotVerified

	// ErrUserIdentityNotVerified happens if the login user is login
	// with OAuth2 provider but has not yet verified
	// the linking through primary e-mail.
	ErrUserIdentityNotVerified
)

// LoginError is a class of errors occurs in login
type LoginError struct {
	Type LoginErrorType

	// Action triggering of the error
	Action string

	// Err stores inner error type, if any
	Err error

	// User references the user, if any
	// for the error
	User *User
}

// Error implements error interface
func (err LoginError) Error() string {
	return "login error: " + err.String()
}

// String implements error interface
func (err LoginError) String() string {
	if err.Err == nil {
		return err.Type.String()
	}
	if err.Action == "" {
		return fmt.Sprintf(
			"error=%#v",
			err.Err.Error(),
		)
	}
	return fmt.Sprintf(
		"action=%#v error=%#v",
		err.Action,
		err.Err.Error(),
	)
}

// GoString implements GoStringer interface
func (err LoginError) GoString() string {
	if err.Err == nil {
		return "LoginError(\"" + err.String() + "\")"
	}
	return "LoginError(" + err.String() + ")"
}
