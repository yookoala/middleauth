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

	return func(ctx context.Context, authIdentity *middleauth.UserIdentity) (ctxNext context.Context, confirmedUser *middleauth.User, err error) {

		ctxNext = ctx // default passing

		// search existing user with the email
		var prevUser middleauth.User
		var prevIdentity middleauth.UserIdentity

		if authIdentity.PrimaryEmail == "" {
			err = &middleauth.LoginError{Type: middleauth.ErrNoEmail}
			return
		}
		if authIdentity.Provider == "" {
			err = &middleauth.LoginError{Type: middleauth.ErrNoProvider}
			return
		}
		if authIdentity.ProviderID == "" {
			err = &middleauth.LoginError{Type: middleauth.ErrNoProviderID}
			return
		}

		//
		// A. if your identity (provider, provider_id) is found in database
		//
		if db.First(&prevIdentity, "provider = ? and provider_id = ?", authIdentity.Provider, authIdentity.ProviderID); prevIdentity.UserID != "" {

			// if user not found, return error
			if db.First(&prevUser, "id = ?", authIdentity.UserID); prevUser.ID == "" {
				err = &middleauth.LoginError{
					Type: middleauth.ErrUserNotFound,
					Action: fmt.Sprintf(
						"find user (id=%s) for identity (provider=%s, provider_id=%s)",
						prevIdentity.UserID,
						prevIdentity.Provider,
						prevIdentity.ProviderID,
					),
					Err: fmt.Errorf("User of the identity not found. Probably deleted."),
				}
				return
			}

			// if user found but is not verified
			if !prevUser.Verified {
				err = &middleauth.LoginError{
					Type: middleauth.ErrUserEmailNotVerified,
					Action: fmt.Sprintf(
						"login user (id = %s) for identity (provider = %s, provider_id = %s)",
						prevIdentity.UserID,
						prevIdentity.Provider,
						prevIdentity.ProviderID,
					),
					User: &prevUser,
				}
				return
			}

			// if email is not verified
			if !prevIdentity.Verified {
				err = &middleauth.LoginError{
					Type: middleauth.ErrUserIdentityNotVerified,
					Action: fmt.Sprintf(
						"login user (id = %s) for identity (provider = %s, provider_id = %s)",
						prevIdentity.UserID,
						prevIdentity.Provider,
						prevIdentity.ProviderID,
					),
					User: &prevUser,
				}
				return
			}

			// no issue found, use the prevUser as confirmedUser
			confirmedUser = &prevUser
			return

		}

		//
		// B. if the identity (provider, provider_id) is not found in the database
		// but the primary email matches another user
		//
		if db.First(&prevUser, "primary_email = ?", authIdentity.PrimaryEmail); prevUser.PrimaryEmail != "" {

			// add identity to database
			authIdentity.UserID = prevUser.ID
			if res := db.Create(&authIdentity); res.Error != nil {
				// append UserIdentity to error info
				err = &middleauth.LoginError{
					Type: middleauth.ErrDatabase,
					Action: fmt.Sprintf(
						"create user-identity relation Provider=%s ProviderID=%s",
						authIdentity.Provider,
						authIdentity.ProviderID,
					),
					Err: res.Error,
				}
				return
			}

			// if authIdentity is not verified
			if !authIdentity.Verified {
				err = &middleauth.LoginError{
					Type: middleauth.ErrUserIdentityNotVerified,
					Action: fmt.Sprintf(
						"login user (id = %s) for identity (provider = %s, provider_id = %s)",
						authIdentity.UserID,
						authIdentity.Provider,
						authIdentity.ProviderID,
					),
					User: &prevUser,
				}
				return
			}

			// no issue found, use the prevUser as confirmedUser
			confirmedUser = &prevUser
			return
		}

		//
		// C. handler new users
		//

		// generate random UUID as the ID of new User
		var userID uuid.UUID
		userID, err = uuid.NewV4()
		if err != nil {
			err = fmt.Errorf("error generating userID (%s)", err.Error())
			return
		}
		newUser := middleauth.User{
			ID:           userID.String(),
			Name:         authIdentity.Name,
			PrimaryEmail: authIdentity.PrimaryEmail,
			Verified:     authIdentity.Verified,
		}

		// begin transaction to create new user
		tx := db.Begin()

		// create user
		if res := tx.Create(&newUser); res.Error != nil {
			// append newUser to error info
			err = &middleauth.LoginError{
				Type:   middleauth.ErrDatabase,
				Action: "create user",
				Err:    res.Error,
			}
			tx.Rollback()
			return
		}

		// add identity to database
		authIdentity.UserID = newUser.ID
		if res := tx.Create(&authIdentity); res.Error != nil {
			// append UserIdentity to error info
			err = &middleauth.LoginError{
				Type: middleauth.ErrDatabase,
				Action: fmt.Sprintf(
					"create user-identity relation Provider=%s ProviderID=%s",
					authIdentity.Provider,
					authIdentity.ProviderID,
				),
				Err: res.Error,
			}
			tx.Rollback()
			return
		}

		// commit change and return new user
		tx.Commit()
		confirmedUser = &newUser
		return
	}
}
