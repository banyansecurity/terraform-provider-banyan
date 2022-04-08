package client

import (
	admin "github.com/banyansecurity/terraform-banyan-provider/client/admin"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/policyattachment"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	"github.com/banyansecurity/terraform-banyan-provider/client/role"
	"github.com/banyansecurity/terraform-banyan-provider/client/satellite"
	service "github.com/banyansecurity/terraform-banyan-provider/client/service"
)

type ClientHolder struct {
	Service          service.ServiceClienter
	Policy           policy.PolicyClienter
	Role             role.RoleClienter
	PolicyAttachment policyattachment.Clienter
	Admin            *admin.Admin
	Satellite        satellite.SatelliteClienter
}

// NewClientHolder returns a new client which is used to perform CRUD operations on all Banyan resources.
func NewClientHolder(hostUrl string, refreshToken string) (client *ClientHolder, err error) {
	restClient, err := restclient.New(hostUrl, refreshToken)
	if err != nil {
		return
	}
	client2 := ClientHolder{}
	client = &client2
	service := service.NewClient(restClient)
	client.Service = service
	client.Policy = policy.NewClient(restClient)
	client.Role = role.NewClient(restClient)
	client.PolicyAttachment = policyattachment.NewClient(restClient)
	client.Satellite = satellite.NewClient(restClient)
	admin := admin.NewClient(restClient)
	client.Admin = admin
	return
}
