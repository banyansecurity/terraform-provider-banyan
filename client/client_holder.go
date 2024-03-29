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
	"github.com/banyansecurity/terraform-banyan-provider/client/servicetunnel"
	"github.com/banyansecurity/terraform-banyan-provider/client/shield"
	"log"
)

type Holder struct {
	Service          service.Client
	ServiceTunnel    servicetunnel.Client
	Policy           policy.Client
	Role             role.Client
	PolicyAttachment policyattachment.Client
	Admin            admin.Client
	Satellite        satellite.Client
	ApiKey           apikey.Client
	AccessTier       accesstier.Client
	Shield           shield.Client
	RestClient       *restclient.Client
}

// NewClientHolder returns a new client which is used to perform operations on all Banyan resources.
func NewClientHolder(hostUrl string, apiKey string) (client *Holder, err error) {
	restClient, err := restclient.New(hostUrl, apiKey)
	if err != nil {
		log.Fatalf("could not create client %s", err)
	}
	c := Holder{
		Service:          service.NewClient(restClient),
		ServiceTunnel:    servicetunnel.NewClient(restClient),
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
