package restclient

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/testenv"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Authentication(t *testing.T) {
	testhost := testenv.GetBanyanHostUrl()
	testApiToken := testenv.GetApiKey()

	t.Run("use api token as access token", func(t *testing.T) {
		myClient, err := New(testhost, testApiToken)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		assert.Equal(t, testApiToken, myClient.accessToken)
	})

}
