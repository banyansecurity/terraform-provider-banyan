package restclient

import (
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func Test_Authentication(t *testing.T) {
	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	testApiToken := os.Getenv("BANYAN_API_KEY")

	t.Run("get access token from refresh token", func(t *testing.T) {
		client, err := New(testhost, testRefreshToken, testApiToken)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		assert.NotEqual(t, testRefreshToken, client.accessToken)
	})

	t.Run("use api token as access token", func(t *testing.T) {
		client, err := New(testhost, testApiToken, testApiToken)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		assert.Equal(t, testApiToken, client.accessToken)
	})

}
