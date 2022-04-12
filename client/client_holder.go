package client

import (
	admin "github.com/banyansecurity/terraform-banyan-provider/client/admin"
	"github.com/banyansecurity/terraform-banyan-provider/client/apikey"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/banyansecurity/terraform-banyan-provider/client/satellite"
	service "github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/banyansecurity/terraform-banyan-provider/client/servicetunnel"
	"log"
)

type Holder struct {
	Service          service.ServiceClienter
	Policy           policy.PolicyClienter
	Role             role.RoleClienter
	PolicyAttachment policyattachment.Clienter
	Admin            *admin.Admin
	Satellite        satellite.Clienter
	ServiceTunnel    servicetunnel.Clienter
	ApiKey           apikey.Clienter
}

// NewClientHolder returns a new client which is used to perform CRUD operations on all Banyan resources.
func NewClientHolder(hostUrl string, refreshToken string, apiToken string) (client *Holder, err error) {
	restClient, err := restclient.New(hostUrl, refreshToken, apiToken)
	if err != nil {
		log.Fatalf("could not create client %s", err)
	}
	client2 := Holder{}
	client = &client2
	service := service.NewClient(restClient)
	client.Service = service
	client.Policy = policy.NewClient(restClient)
	client.Role = role.NewClient(restClient)
	client.PolicyAttachment = policyattachment.NewClient(restClient)
	client.Satellite = satellite.NewClient(restClient)
	client.ServiceTunnel = servicetunnel.NewClient(restClient)
	client.ApiKey = apikey.NewClient(restClient)
	admin := admin.NewClient(restClient)
	client.Admin = admin
	return
}
