package client

import (
	"log"
	"os"
	"testing"

	"github.com/joho/godotenv"
)

func Test_getAccessToken(t *testing.T) {
	err := godotenv.Load("../.env")
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	_, err = New(testhost, testRefreshToken)
	if err != nil {
		t.Fatalf("%+v", err)
	}

}
