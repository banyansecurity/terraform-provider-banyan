package testutil

import (
	"log"
	"os"

	"github.com/banyansecurity/terraform-banyan-provider/client"
)

func GetClientHolderForTest() (newClient *client.Holder, err error) {
	newClient, err = client.NewClientHolder(os.Getenv("BANYAN_HOST"), "", os.Getenv("BANYAN_API_KEY"))
	if err != nil {
		log.Fatal("Could not create the test client")
	}
	return
}
