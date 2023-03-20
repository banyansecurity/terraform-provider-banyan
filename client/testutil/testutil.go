package testutil

import (
	"log"
	"net/url"
	"os"

	"github.com/banyansecurity/terraform-banyan-provider/client"
)

func GetClientHolderForTest() (newClient *client.Holder, err error) {
	envUrl, err := url.Parse(client.GetBanyanHostUrl())
	if err != nil {
		log.Println(err)
		log.Fatal("Could not create the test client")
		return
	}
	if envUrl.Scheme != "https" {
		envUrl.Scheme = "https"
	}
	newClient, err = client.NewClientHolder(envUrl.String(), os.Getenv("BANYAN_API_TOKEN"))
	if err != nil {
		log.Fatal("Could not create the test client")
	}
	return
}
