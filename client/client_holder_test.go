package client_test

import (
	"os"
	"testing"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/stretchr/testify/assert"
)

func Test_GetNonexistentService(t *testing.T) {
	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	_, err := client.NewClientHolder(testhost, testRefreshToken, "")
	assert.NoError(t, err, "Expected to not get an error here")
}
