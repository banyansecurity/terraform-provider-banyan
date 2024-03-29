package banyan

import (
	"context"
	"fmt"
	"strings"

	bnnClient "github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider for Banyan
func Provider() *schema.Provider {
	var provider = schema.Provider{
		Schema: map[string]*schema.Schema{
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The Banyan Command Center API URL",
				DefaultFunc: schema.EnvDefaultFunc("BANYAN_HOST", "https://net.banyanops.com/"),
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "An admin scoped API key",
				DefaultFunc: schema.EnvDefaultFunc("BANYAN_API_KEY", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"banyan_service_ssh":    resourceServiceSsh(),
			"banyan_service_rdp":    resourceServiceRdp(),
			"banyan_service_tcp":    resourceServiceTcp(),
			"banyan_service_k8s":    resourceServiceK8s(),
			"banyan_service_db":     resourceServiceDb(),
			"banyan_service_web":    resourceServiceWeb(),
			"banyan_service_tunnel": resourceServiceTunnel(),
			"banyan_policy_web":     resourcePolicyWeb(),
			"banyan_policy_infra":   resourcePolicyInfra(),
			"banyan_policy_tunnel":  resourcePolicyTunnel(),
			"banyan_role":           resourceRole(),
			"banyan_api_key":        resourceApiKey(),
			"banyan_connector":      resourceConnector(),
			"banyan_accesstier":     resourceAccessTier(),

			"banyan_accesstier_group": resourceAccessTierGroup(),
			"banyan_scim":             resourceSCIM(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"banyan_oidc_settings": dataSourceOidcSettings(),
			"banyan_policy_web":    dataSourcePolicyWeb(),
			"banyan_policy_tunnel": dataSourcePolicyTunnel(),
			"banyan_policy_infra":  dataSourcePolicyInfra(),
			"banyan_role":          dataSourceRole(),
		},
		ConfigureContextFunc: providerConfigure,
	}
	return &provider
}

// Configures the Banyan provider with the given refresh / API token and host url
func providerConfigure(ctx context.Context, d *schema.ResourceData) (client interface{}, diagnostic diag.Diagnostics) {
	host := d.Get("host").(string)
	if !strings.HasSuffix(host, "/") {
		host = host + "/"
	}
	client, err := bnnClient.NewClientHolder(host, d.Get("api_key").(string))
	if err != nil {
		diagnostic = append(diagnostic, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to create Banyan client",
			Detail:   "Unable to authenticate to the Banyan API" + fmt.Sprintf("%+v", err),
		})
	}
	return
}
