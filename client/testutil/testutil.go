package testutil

import (
	"os"

	"github.com/banyansecurity/terraform-banyan-provider/client"
)

func GetClientHolderForTest() (newClient *client.ClientHolder, err error) {
	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	newClient, err = client.NewClientHolder(testhost, testRefreshToken)
	return
}
