package client

import (
	admin "github.com/banyansecurity/terraform-banyan-provider/client/admin"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	service "github.com/banyansecurity/terraform-banyan-provider/client/service"
)

type ClientHolder struct {
	Service service.ServiceClienter
	Policy  policy.PolicyClienter
	Admin   *admin.Admin
}

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
	admin := admin.NewClient(restClient)
	client.Admin = admin
	return
}
