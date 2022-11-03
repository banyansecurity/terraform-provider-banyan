package client

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstier"
	admin "github.com/banyansecurity/terraform-banyan-provider/client/admin"
	"github.com/banyansecurity/terraform-banyan-provider/client/apikey"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/banyansecurity/terraform-banyan-provider/client/satellite"
	service "github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/banyansecurity/terraform-banyan-provider/client/shield"
	"log"
	"os"
)

type Holder struct {
	Service          service.Client
	Policy           policy.Client
	Role             role.Client
	PolicyAttachment policyattachment.Clienter
	Admin            admin.Admin
	Satellite        satellite.Clienter
	ApiKey           apikey.Clienter
	AccessTier       accesstier.Client
	Shield           shield.Clienter
	RestClient       *restclient.RestClient
}

// NewClientHolder returns a new client which is used to perform CRUD operations on all Banyan resources.
func NewClientHolder(hostUrl string, refreshToken string, apiToken string) (client *Holder, err error) {
	restClient, err := restclient.New(hostUrl, refreshToken, apiToken)
	if err != nil {
		log.Fatalf("could not create client %s", err)
	}
	c := Holder{
		Service:          service.NewClient(restClient),
		Policy:           policy.NewClient(restClient),
		Role:             role.NewClient(restClient),
		PolicyAttachment: policyattachment.NewClient(restClient),
		Satellite:        satellite.NewClient(restClient),
		ApiKey:           apikey.NewClient(restClient),
		AccessTier:       accesstier.NewClient(restClient),
		Admin:            admin.NewClient(restClient),
		Shield:           shield.NewClient(restClient),
		RestClient:       restClient,
	}
	return &c, err
}

func GetClientHolderForTest() (newClient *Holder, err error) {
	newClient, err = NewClientHolder(os.Getenv("BANYAN_HOST"), "", os.Getenv("BANYAN_API_KEY"))
	if err != nil {
		log.Fatal("Could not create the test client")
	}
	return
}
