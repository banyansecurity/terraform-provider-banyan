package client

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_Authentication(t *testing.T) {
	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	testApiToken := os.Getenv("BANYAN_API_TOKEN")

	t.Run("get access token from refresh token", func(t *testing.T) {
		client, err := New(testhost, testRefreshToken)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		assert.NotEqual(t, testRefreshToken, client.accessToken)
	})

	t.Run("use api token as access token", func(t *testing.T) {
		client, err := New(testhost, testApiToken)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		assert.Equal(t, testApiToken, client.accessToken)
	})

	t.Run("Use invalid token raises error", func(t *testing.T) {
		client, err := New(testhost, "thisIsInvalid")
		if err == nil {
			t.Fatalf("Expected an error, got none %q", client.accessToken)
		}
		assert.Contains(t, err.Error(), "Unauthorized access")
	})

}
