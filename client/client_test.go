package client

import (
	// "os"
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
	client, err := New(testhost, testRefreshToken)
	if err != nil {
		t.Fatalf("%+v", err)
	}
	_, err = client.GetOidcSettings()
	if err != nil {
		t.Fatalf("%+v", err)
	}
}
