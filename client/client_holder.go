package client

import (
	admin "github.com/banyansecurity/terraform-banyan-provider/client/admin"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
	service "github.com/banyansecurity/terraform-banyan-provider/client/service"
)

type ClientHolder struct {
	Service service.ServiceClienter
	Admin   *admin.Admin
	
}

func NewClientHolder(hostUrl string, refreshToken string) (client *ClientHolder, err error) {
	restClient, err := restclient.New(hostUrl, refreshToken)
	if err != nil {
		return
	}
	service := service.NewClient(restClient)
	client.Service = service
	admin := admin.NewClient(restClient)
	client.Admin = admin
	return
}
