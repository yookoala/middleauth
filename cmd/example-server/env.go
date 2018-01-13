package main

import (
	"log"
	"os"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/joho/godotenv"
	"github.com/yookoala/middleauth"
)

func varFromEnv() (host, port, cookieName, publicURL string) {

	// (optional) load variables in .env as environment variavbles
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// hard code these 2 here
	host, cookieName = "localhost", "middleauth-example"

	// get port and public url here
	if port = os.Getenv("PORT"); port == "" {
		port = "8080"
	}
	if publicURL = os.Getenv("PUBLIC_URL"); publicURL == "" {
		publicURL = "http://localhost:8080"
	}

	return
}

func getDB() (db *gorm.DB) {
	db, err := gorm.Open("sqlite3", "example-server.db")
	if err != nil {
		log.Fatalf("unexpected error: %s", err.Error())
	}

	db.AutoMigrate(
		middleauth.User{},
		middleauth.UserEmail{},
	)
	return
}
