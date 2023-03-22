package testutil

import (
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"log"
)

func GetClientHolderForTest() (newClient *client.Holder, err error) {
	newClient, err = client.NewClientHolder(client.GetBanyanHostUrl(), client.GetApiKey())
	if err != nil {
		log.Fatal("Could not create the test client")
	}
	return
}
