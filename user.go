package middleauth

import (
	"fmt"
	"time"
)

// User object
type User struct {
	ID            string `json:"id" gorm:"type:varchar(36);primary_key"`
	Name          string `json:"name" gorm:"type:varchar(255)"`
	PrimaryEmail  string `json:"primary_email" gorm:"type:varchar(100);unique_index"`
	VerifiedEmail bool   `json:"verified_email"`
	Emails        []UserEmail
	Password      string `gorm:"type:varchar(255)"`
	IsAdmin       bool

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
	case ErrNoEmail:
		return "no email"
	case ErrDatabase:
		return "database error"
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

	// ErrNoEmail happens if the login user did not provide email
	ErrNoEmail

	// ErrDatabase represents database server errors
	ErrDatabase
)

// LoginError is a class of errors occurs in login
type LoginError struct {
	Type LoginErrorType

	// Action triggering of the error
	Action string

	// Err stores inner error type, if any
	Err error
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
