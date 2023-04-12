package testutil

import (
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/testenv"
	"log"
)

func GetClientHolderForTest() (newClient *client.Holder, err error) {
	newClient, err = client.NewClientHolder(testenv.GetBanyanHostUrl(), testenv.GetApiKey())
	if err != nil {
		log.Fatal("Could not create the test client")
	}
	return
}
