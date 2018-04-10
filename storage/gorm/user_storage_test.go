package gormstorage_test

import (
	"context"
	"testing"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/yookoala/middleauth"
	gormstorage "github.com/yookoala/middleauth/storage/gorm"
)

type NopLogwriter int

func (logger NopLogwriter) Println(v ...interface{}) {
	// don't give a damn
}

func TestLoadOrCreateUser(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	gormstorage.AutoMigrate(db)

	callback := gormstorage.UserStorageCallback(db)

	// attempt to create user on first login
	_, u1, err := callback(
		context.TODO(),
		&middleauth.User{
			Name:         "dummy user",
			PrimaryEmail: "dummy@foobar.com",
		},
	)

	if err != nil {
		t.Errorf("unexpected error: %#v", err)
	}
	if u1 == nil {
		t.Errorf("expected user, got nil")
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

	// should retrieve the same user on second login
	// regardless of the name
	_, u2, err := callback(
		context.TODO(),
		&middleauth.User{
			Name:         "dummy user another time",
			PrimaryEmail: "dummy@foobar.com",
		},
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

	// try to login with no email
	_, u3, err := callback(
		context.TODO(),
		&middleauth.User{
			Name:         "dummy user",
			PrimaryEmail: "",
		},
	)
	if u3 != nil {
		t.Errorf("expected u3 to be nil, got %#v", u3)
	}
	if want, have := middleauth.ErrNoEmail, err.(*middleauth.LoginError).Type; want != have {
		t.Errorf("expected %#v, got %#v", want, have)
	}
}

func TestLoadOrCreateUser_DatabaseError(t *testing.T) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		t.Errorf("unexpected error: %s", err.Error())
	}
	defer db.Close()
	db.SetLogger(gorm.Logger{LogWriter: NopLogwriter(0)})

	// test inserting with a missing table
	gormstorage.AutoMigrate(db)
	db.Exec("DROP TABLE user_emails;")
	callback := gormstorage.UserStorageCallback(db)
	_, u1, err := callback(
		context.TODO(),
		&middleauth.User{
			Name:         "dummy user",
			PrimaryEmail: "dummy@foobar.com",
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
		&middleauth.User{
			Name:         "dummy user",
			PrimaryEmail: "dummy3@foobar.com",
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
