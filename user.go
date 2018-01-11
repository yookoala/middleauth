package middleauth

import (
	"context"
	"fmt"

	"github.com/jinzhu/gorm"
)

// User object
type User struct {
	gorm.Model
	Name          string `gorm:"type:varchar(255)"`
	PrimaryEmail  string `gorm:"type:varchar(100);unique_index"`
	VerifiedEmail bool
	Emails        []UserEmail
	Password      string `gorm:"type:varchar(255)"`
	IsAdmin       bool
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

// UserCallback is the interface for authenticator
// to interact with, once acquired the user information.
//
// It is responsible to:
// 1. Search backend storage to see if the user already exists.
// 2. If not, create a user entry as appropriated.
// 3. Return a *User for cookie, or return nil with error.
type UserCallback func(ctx context.Context, authUser User, emails []string) (confirmedUser *User, err error)

func loadOrCreateUser(db *gorm.DB) UserCallback {

	return func(ctx context.Context, authUser User, verifiedEmails []string) (confirmedUser *User, err error) {

		// search existing user with the email
		var userEmail UserEmail
		var prevUser User

		if db.First(&prevUser, "primary_email = ?", authUser.PrimaryEmail); prevUser.PrimaryEmail != "" {
			// TODO: log this?
			authUser = prevUser
		} else if db.First(&userEmail, "email = ?", authUser.PrimaryEmail); userEmail.Email != "" {
			// TODO: log this?
			db.First(&authUser, "id = ?", userEmail.UserID)
		} else if authUser.PrimaryEmail == "" {
			err = &LoginError{Type: ErrNoEmail}
		} else {

			tx := db.Begin()

			// create user
			if res := tx.Create(&authUser); res.Error != nil {
				// append authUser to error info
				err = &LoginError{
					Type:   ErrDatabase,
					Action: "create user",
					Err:    res.Error,
				}
				tx.Rollback()
				return
			}

			// create user-email relation
			newUserEmail := UserEmail{
				UserID: authUser.ID,
				Email:  authUser.PrimaryEmail,
			}
			if res := tx.Create(&newUserEmail); res.Error != nil {
				// append newUserEmail to error info
				err = &LoginError{
					Type:   ErrDatabase,
					Action: "create user-email relation " + newUserEmail.Email,
					Err:    res.Error,
				}
				tx.Rollback()
				return
			}

			// also input UserEmail from verifiedEmails, if len not 0
			for _, email := range verifiedEmails {
				newUserEmail := UserEmail{
					UserID: authUser.ID,
					Email:  email,
				}
				if res := tx.Create(&newUserEmail); res.Error != nil {
					// append newUserEmail to error info
					err = &LoginError{
						Type:   ErrDatabase,
						Action: "create user-email relation " + newUserEmail.Email,
						Err:    res.Error,
					}
					tx.Rollback()
					return
				}
			}

			tx.Commit()
		}

		if err == nil {
			confirmedUser = &authUser
		}
		return
	}
}
