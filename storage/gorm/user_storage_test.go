package gormstorage_test

import (
	"context"
	"testing"

	uuid "github.com/gofrs/uuid"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/yookoala/middleauth"
	gormstorage "github.com/yookoala/middleauth/storage/gorm"
)

type NopLogwriter int

func (logger NopLogwriter) Println(v ...interface{}) {
	// don't give a damn
}

func randID() string {
	if id, err := uuid.NewV4(); err == nil {
		return id.String()
	}
	return "failed-to-generate-uuid-v4"
}

func TestLoadOrCreateUser_normalFlow(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	gormstorage.AutoMigrate(db)

	callback := gormstorage.UserStorageCallback(db)

	// attempt to create user on first login
	// with provider 1
	identity1 := middleauth.UserIdentity{
		Name:         "dummy user",
		PrimaryEmail: "dummy@foobar.com",
		Provider:     "dummy-provider-1",
		ProviderID:   randID(),
		Verified:     false,
	}
	// should create a user with Verified set to false
	// (following identity1)
	//
	// also identity1.UserID will be set properly
	_, u1, err := callback(
		context.TODO(),
		&identity1,
	)

	if err != nil {
		t.Errorf("unexpected error: %#v", err)
	}
	if u1 == nil {
		t.Errorf("expected user, got nil")
	}
	if want, have := u1.ID, identity1.UserID; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := identity1.Name, u1.Name; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := identity1.PrimaryEmail, u1.PrimaryEmail; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := identity1.Verified, u1.Verified; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

	u1db := middleauth.User{}
	db.First(&u1db, "id = ?", u1.ID)
	if want, have := u1.ID, u1db.ID; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.Name, u1db.Name; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.PrimaryEmail, u1db.PrimaryEmail; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := false, u1db.Verified; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

	// attempt to login with another provider
	//
	// should retrieve the same user on second login
	// regardless of the name
	identity2 := middleauth.UserIdentity{
		Name:         "dummy user another time",
		PrimaryEmail: "dummy@foobar.com",
		Provider:     "dummy-provider-2",
		ProviderID:   randID(),
		Verified:     true,
	}
	_, u2, err := callback(
		context.TODO(),
		&identity2,
	)
	if want, have := u1.ID, u2.ID; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.Name, u2.Name; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.PrimaryEmail, u2.PrimaryEmail; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

	// attempt to login with identity2
	//
	// Since User has Verified set to true (by identity1),
	// this should raise an error of such and containing
	// a User field referencing the user.
	_, u3, err := callback(
		context.TODO(),
		&identity2,
	)

	if u3 != nil {
		t.Errorf("expected u3 to be nil, got %#v", *u3)
		return
	}

	lerr, ok := err.(*middleauth.LoginError)
	if !ok {
		t.Errorf("expected error to be *middleauth.LoginError, got %#v", err)
		return
	}
	if want, have := middleauth.ErrUserEmailNotVerified, lerr.Type; want != have {
		t.Errorf("expected error to be %#v, got %#v", want, have)
	}
	if lerr.User == nil {
		t.Errorf("expected lerr.User to be not nil, got nil")
	} else {
		u := *lerr.User
		if want, have := u1.ID, u.ID; want != have {
			t.Errorf("expected %#v, got %#v", want, have)
		}
		if want, have := u1.Name, u.Name; want != have {
			t.Errorf("expected %#v, got %#v", want, have)
		}
		if want, have := u1.PrimaryEmail, u.PrimaryEmail; want != have {
			t.Errorf("expected %#v, got %#v", want, have)
		}
	}

	// manually set user to verified and try again
	db.Model(u1).Update("verified", true)
	_, u4, err := callback(
		context.TODO(),
		&identity2,
	)
	if err != nil {
		t.Errorf("unexpected error: %s", err)
		return
	}
	if u4 == nil {
		t.Errorf("expected u4 to be *middleauth.User, got nil")
		return
	}

	// check if the user matches
	if want, have := u1.ID, u4.ID; want != have {
		t.Logf("u4: %#v", u4)
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.Name, u4.Name; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.PrimaryEmail, u4.PrimaryEmail; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := true, u4.Verified; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

	// attempt to login with identity1
	//
	// Since identity1 is marked Verified to false,
	// it will raise error.
	_, u5, err := callback(
		context.TODO(),
		&identity1,
	)
	if u5 != nil {
		t.Errorf("expected u5 to be nil, got %#v", *u5)
	}
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	lerr, ok = err.(*middleauth.LoginError)
	if !ok {
		t.Errorf("expected error to be *middleauth.LoginError, got %#v", err)
		return
	}
	if want, have := middleauth.ErrUserIdentityNotVerified, lerr.Type; want != have {
		t.Errorf("expected error to be %#v, got %#v", want, have)
	}
	if lerr.User == nil {
		t.Errorf("expected lerr.User to be not nil, got nil")
		return
	} else {
		u := *lerr.User
		if want, have := u1.ID, u.ID; want != have {
			t.Errorf("expected %#v, got %#v", want, have)
		}
		if want, have := u1.Name, u.Name; want != have {
			t.Errorf("expected %#v, got %#v", want, have)
		}
		if want, have := u1.PrimaryEmail, u.PrimaryEmail; want != have {
			t.Errorf("expected %#v, got %#v", want, have)
		}
	}
}

func TestLoadOrCreateUser_autoVerifyFlow(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	gormstorage.AutoMigrate(db)

	callback := gormstorage.UserStorageCallback(db)

	// attempt to create user on first login
	// with provider 1
	identity1 := middleauth.UserIdentity{
		Name:         "dummy user",
		PrimaryEmail: "dummy@foobar.com",
		Provider:     "dummy-provider-1",
		ProviderID:   randID(),
		Verified:     true, // login with Verified hard code to true
	}
	// should create a user with Verified set to false
	// (following identity1)
	//
	// also identity1.UserID will be set properly
	_, u1, err := callback(
		context.TODO(),
		&identity1,
	)

	u1db := middleauth.User{}
	db.First(&u1db, "id = ?", u1.ID)
	if want, have := u1.ID, u1db.ID; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.Name, u1db.Name; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.PrimaryEmail, u1db.PrimaryEmail; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := true, u1db.Verified; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

	// attempt to login with another provider
	//
	// should retrieve the same user on second login
	// regardless of the name
	identity2 := middleauth.UserIdentity{
		Name:         "dummy user another time",
		PrimaryEmail: "dummy@foobar.com",
		Provider:     "dummy-provider-2",
		ProviderID:   randID(),
		Verified:     true,
	}
	_, u2, err := callback(
		context.TODO(),
		&identity2,
	)
	if want, have := u1.ID, u2.ID; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.Name, u2.Name; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.PrimaryEmail, u2.PrimaryEmail; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := true, u2.Verified; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

}

func TestLoadOrCreateUser_userDeleted(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	gormstorage.AutoMigrate(db)

	callback := gormstorage.UserStorageCallback(db)

	// attempt to create user on first login
	// with provider 1
	identity1 := middleauth.UserIdentity{
		Name:         "dummy user",
		PrimaryEmail: "dummy@foobar.com",
		Provider:     "dummy-provider-1",
		ProviderID:   randID(),
		Verified:     true,
	}

	// should create a user with Verified set to false
	// (following identity1)
	//
	// also identity1.UserID will be set properly
	_, u1, err := callback(
		context.TODO(),
		&identity1,
	)

	if err != nil {
		t.Errorf("unexpected error: %#v", err)
	}
	if u1 == nil {
		t.Errorf("expected user, got nil")
	}
	if want, have := u1.ID, identity1.UserID; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := identity1.Name, u1.Name; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := identity1.PrimaryEmail, u1.PrimaryEmail; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := identity1.Verified, u1.Verified; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

	u1db := middleauth.User{}
	db.First(&u1db, "id = ?", u1.ID)
	if want, have := u1.ID, u1db.ID; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.Name, u1db.Name; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
	if want, have := u1.PrimaryEmail, u1db.PrimaryEmail; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}

	db.Delete(&u1db) // delete the record

	// should create a user with Verified set to false
	// (following identity1)
	//
	// also identity1.UserID will be set properly
	_, u2, err := callback(
		context.TODO(),
		&identity1,
	)
	if u2 != nil {
		t.Errorf("expected u2 to be nil, got %#v", *u2)
	}
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	lerr, ok := err.(*middleauth.LoginError)
	if !ok {
		t.Errorf("expected error to be *middleauth.LoginError, got %#v", err)
		return
	}
	if want, have := middleauth.ErrUserNotFound, lerr.Type; want != have {
		t.Errorf("expected error to be %#v, got %#v", want, have)
	}
	if lerr.User != nil {
		t.Errorf("expected lerr.User to be nil, got %#v", *lerr.User)
		return
	}
}

func TestLoadOrCreateUser_noPrimaryEmail(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	gormstorage.AutoMigrate(db)

	callback := gormstorage.UserStorageCallback(db)

	// attempt to create user on first login
	// with provider 1
	identity1 := middleauth.UserIdentity{
		Name:         "dummy user",
		PrimaryEmail: "", // no primary email
		Provider:     "dummy-provider-1",
		ProviderID:   randID(),
		Verified:     true,
	}
	// should create a user with Verified set to false
	// (following identity1)
	//
	// also identity1.UserID will be set properly
	_, u1, err := callback(
		context.TODO(),
		&identity1,
	)
	if u1 != nil {
		t.Errorf("expected u1 to be nil, got %#v", *u1)
	}
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	lerr, ok := err.(*middleauth.LoginError)
	if !ok {
		t.Errorf("expected error to be *middleauth.LoginError, got %#v", err)
		return
	}
	if want, have := middleauth.ErrNoEmail, lerr.Type; want != have {
		t.Errorf("expected error to be %#v, got %#v", want, have)
	}
	if lerr.User != nil {
		t.Errorf("expected lerr.User to be nil, got %#v", *lerr.User)
		return
	}
}

func TestLoadOrCreateUser_noProvider(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	gormstorage.AutoMigrate(db)

	callback := gormstorage.UserStorageCallback(db)

	// attempt to create user on first login
	// with provider 1
	identity1 := middleauth.UserIdentity{
		Name:         "dummy user",
		PrimaryEmail: "me@email.com",
		Provider:     "", // no provider name
		ProviderID:   randID(),
		Verified:     true,
	}
	// should create a user with Verified set to false
	// (following identity1)
	//
	// also identity1.UserID will be set properly
	_, u1, err := callback(
		context.TODO(),
		&identity1,
	)
	if u1 != nil {
		t.Errorf("expected u1 to be nil, got %#v", *u1)
	}
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	lerr, ok := err.(*middleauth.LoginError)
	if !ok {
		t.Errorf("expected error to be *middleauth.LoginError, got %#v", err)
		return
	}
	if want, have := middleauth.ErrNoProvider, lerr.Type; want != have {
		t.Errorf("expected error to be %#v, got %#v", want, have)
	}
	if lerr.User != nil {
		t.Errorf("expected lerr.User to be nil, got %#v", *lerr.User)
		return
	}
}

func TestLoadOrCreateUser_noProviderID(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	gormstorage.AutoMigrate(db)

	callback := gormstorage.UserStorageCallback(db)

	// attempt to create user on first login
	// with provider 1
	identity1 := middleauth.UserIdentity{
		Name:         "dummy user",
		PrimaryEmail: "me@email.com",
		Provider:     "dummy-provider",
		ProviderID:   "", // no provider id
		Verified:     true,
	}
	// should create a user with Verified set to false
	// (following identity1)
	//
	// also identity1.UserID will be set properly
	_, u1, err := callback(
		context.TODO(),
		&identity1,
	)
	if u1 != nil {
		t.Errorf("expected u1 to be nil, got %#v", *u1)
	}
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	lerr, ok := err.(*middleauth.LoginError)
	if !ok {
		t.Errorf("expected error to be *middleauth.LoginError, got %#v", err)
		return
	}
	if want, have := middleauth.ErrNoProviderID, lerr.Type; want != have {
		t.Errorf("expected error to be %#v, got %#v", want, have)
	}
	if lerr.User != nil {
		t.Errorf("expected lerr.User to be nil, got %#v", *lerr.User)
		return
	}
}

func TestLoadOrCreateUser_databaseError(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	db.SetLogger(gorm.Logger{LogWriter: NopLogwriter(0)})

	// test inserting with a missing table
	gormstorage.AutoMigrate(db)
	db.Exec("DROP TABLE user_identities;")
	callback := gormstorage.UserStorageCallback(db)
	_, u1, err := callback(
		context.TODO(),
		&middleauth.UserIdentity{
			Name:         "dummy user",
			PrimaryEmail: "dummy@foobar.com",
			Provider:     "dummy-provider",
			ProviderID:   randID(),
		},
	)
	if u1 != nil {
		t.Errorf("expected u1 to be nil, got %#v", u1)
	}
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	u1db := middleauth.User{}
	db.First(&u1db, "email = ?", "dummy@foobar.com")
	if u1db.ID != "" {
		t.Errorf("expected u1db to have empty id, got %#v", u1db)
	}

	db.Exec("DROP TABLE users;")
	_, u2, err := callback(
		context.TODO(),
		&middleauth.UserIdentity{
			Name:         "dummy user",
			PrimaryEmail: "dummy3@foobar.com",
			Provider:     "dummy-provider",
			ProviderID:   randID(),
		},
	)
	if u2 != nil {
		t.Errorf("expected u1 to be nil, got %#v", u1)
	}
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	u2db := middleauth.User{}
	db.First(&u2db, "email = ?", "dummy@foobar.com")
	if u2db.ID != "" {
		t.Errorf("expected u3db to have empty id, got %#v", u2db)
	}

}
