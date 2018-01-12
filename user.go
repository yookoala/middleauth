package middleauth

import (
	"fmt"
	"time"
)

// User object
type User struct {
	ID            uint   `gorm:"primary_key"`
	Name          string `gorm:"type:varchar(255)"`
	PrimaryEmail  string `gorm:"type:varchar(100);unique_index"`
	VerifiedEmail bool
	Emails        []UserEmail
	Password      string `gorm:"type:varchar(255)"`
	IsAdmin       bool

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time `sql:"index"`
}

// UserEmail contains user and email relationship
type UserEmail struct {
	ID     uint   `gorm:"primary_key"`
	UserID uint   `gorm:"index"`
	Email  string `gorm:"type:varchar(100);unique_index"`
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
