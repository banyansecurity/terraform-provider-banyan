package main

import (
	"github.com/banyansecurity/terraform-banyan-provider/banyan"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() *schema.Provider {
			return banyan.Provider()
		},
	})
}
