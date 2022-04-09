package client

import (
	admin "github.com/banyansecurity/terraform-banyan-provider/client/admin"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	service "github.com/banyansecurity/terraform-banyan-provider/client/service"
	"log"
)

type ClientHolder struct {
	Service          service.ServiceClienter
	Policy           policy.PolicyClienter
	Role             role.RoleClienter
	PolicyAttachment policyattachment.Clienter
	Admin            *admin.Admin
}

// NewClientHolder returns a new client which is used to perform CRUD operations on all Banyan resources.
func NewClientHolder(hostUrl string, refreshToken string, apiToken string) (client *ClientHolder, err error) {
	restClient, err := restclient.New(hostUrl, refreshToken, apiToken)
	if err != nil {
		log.Fatalf("could not create client %s", err)
	}
	client2 := ClientHolder{}
	client = &client2
	service := service.NewClient(restClient)
	client.Service = service
	client.Policy = policy.NewClient(restClient)
	client.Role = role.NewClient(restClient)
	client.PolicyAttachment = policyattachment.NewClient(restClient)
	admin := admin.NewClient(restClient)
	client.Admin = admin
	return
}
