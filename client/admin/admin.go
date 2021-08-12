package admin

import (
	"github.com/banyansecurity/terraform-banyan-provider/client/admin/oidcsettings"
	"github.com/banyansecurity/terraform-banyan-provider/client/admin/orgidpconfig"
	"github.com/banyansecurity/terraform-banyan-provider/client/restclient"
)

type Admin struct {
	OidcSettings oidcsettings.OidcSettingsClienter
	OrgIdpConfig orgidpconfig.OrgIdpConfigClienter
}

func NewClient(restClient *restclient.RestClient) (admin *Admin) {
	oidcSettingsClient := oidcsettings.Client(restClient)
	admin = &Admin{}
	admin.OidcSettings = oidcSettingsClient
	admin.OrgIdpConfig = orgidpconfig.Client(restClient)
	return
}
