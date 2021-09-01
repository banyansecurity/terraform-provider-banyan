package testutil

import (
	"os"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/joho/godotenv"
)

func GetClientHolderForTest() (newClient *client.ClientHolder, err error) {
	err = godotenv.Load("../../.env")
	if err != nil {
		return
	}

	testhost := os.Getenv("BANYAN_HOST")
	testRefreshToken := os.Getenv("BANYAN_REFRESH_TOKEN")
	newClient, err = client.NewClientHolder(testhost, testRefreshToken)
	return
}
