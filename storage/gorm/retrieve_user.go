package gormstorage

import (
	"context"

	"github.com/jinzhu/gorm"
	"github.com/yookoala/middleauth"
)

// RetrieveUser create a middleauth.RetrieveUser implementation
// by the given db.
func RetrieveUser(db *gorm.DB) middleauth.RetrieveUser {
	return func(ctx context.Context, id string) (user *middleauth.User, err error) {
		users := []middleauth.User{}
		db.First(&users, "id = ?", id)
		if len(users) < 1 {
			err = db.Error
		}

		user = &users[0]
		return
	}
}
