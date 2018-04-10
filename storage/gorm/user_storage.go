package gormstorage

import (
	"context"
	"fmt"

	"github.com/jinzhu/gorm"
	uuid "github.com/satori/go.uuid"
	"github.com/yookoala/middleauth"
)

// AutoMigrate automatically migrate all entities in database
func AutoMigrate(db *gorm.DB) *gorm.DB {
	return db.AutoMigrate(
		middleauth.User{},
		middleauth.UserEmail{},
		middleauth.UserIdentity{},
	)
}

// UserStorageCallback generates implementation of middleauth.UserCallback
// with gorm backed storage.
func UserStorageCallback(db *gorm.DB) middleauth.UserStorageCallback {

	return func(ctx context.Context, authUser *middleauth.User) (ctxNext context.Context, confirmedUser *middleauth.User, err error) {

		// search existing user with the email
		var userEmail middleauth.UserEmail
		var prevUser middleauth.User

		if db.First(&prevUser, "primary_email = ?", authUser.PrimaryEmail); prevUser.PrimaryEmail != "" {
			// TODO: log this?
			authUser = &prevUser
		} else if db.First(&userEmail, "email = ?", authUser.PrimaryEmail); userEmail.Email != "" {
			// TODO: log this?
			db.First(&authUser, "id = ?", userEmail.UserID)
		} else if authUser.PrimaryEmail == "" {
			err = &middleauth.LoginError{Type: middleauth.ErrNoEmail}
		} else {

			tx := db.Begin()
			var userID uuid.UUID
			userID, err = uuid.NewV4()
			if err != nil {
				err = fmt.Errorf("error generating userID (%s)", err.Error())
			}

			authUser.ID = userID.String()

			// create user
			if res := tx.Create(&authUser); res.Error != nil {
				// append authUser to error info
				err = &middleauth.LoginError{
					Type:   middleauth.ErrDatabase,
					Action: "create user",
					Err:    res.Error,
				}
				tx.Rollback()
				return
			}

			// create user-email relation
			newUserEmail := middleauth.UserEmail{
				UserID: authUser.ID,
				Email:  authUser.PrimaryEmail,
			}
			if res := tx.Create(&newUserEmail); res.Error != nil {
				// append newUserEmail to error info
				err = &middleauth.LoginError{
					Type:   middleauth.ErrDatabase,
					Action: "create user-email relation " + newUserEmail.Email,
					Err:    res.Error,
				}
				tx.Rollback()
				return
			}

			// also input UserEmail from verifiedEmails, if len not 0
			/*
				for _, email := range verifiedEmails {
					newUserEmail := middleauth.UserEmail{
						UserID: authUser.ID,
						Email:  email,
					}
					if res := tx.Create(&newUserEmail); res.Error != nil {
						// append newUserEmail to error info
						err = &middleauth.LoginError{
							Type:   middleauth.ErrDatabase,
							Action: "create user-email relation " + newUserEmail.Email,
							Err:    res.Error,
						}
						tx.Rollback()
						return
					}
				}
			*/

			tx.Commit()
		}

		if err == nil {
			confirmedUser = authUser
		}
		ctxNext = ctx
		return
	}
}
