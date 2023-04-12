package admin

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/admin/oidcsettings"
	"github.com/banyansecurity/terraform-banyan-provider/client/admin/orgidpconfig"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type Client struct {
	OidcSettings oidcsettings.Client
	OrgIdpConfig orgidpconfig.Clienter
}

func NewClient(restClient *restclient.Client) (admin Client) {
	oidcSettingsClient := oidcsettings.NewClient(restClient)
	admin.OidcSettings = oidcSettingsClient
	admin.OrgIdpConfig = orgidpconfig.Client(restClient)
	return
}
