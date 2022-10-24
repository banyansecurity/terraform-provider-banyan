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
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("BANYAN_HOST", "https://net.banyanops.com/"),
			},
			"api_token": {
				Type:          schema.TypeString,
				Optional:      true,
				Deprecated:    "Configure api_key instead. This attribute will be removed\n   in the 1.0 release of the provider.",
				ConflictsWith: []string{"api_key", "refresh_token"},
			},
			"api_key": {
				Type:          schema.TypeString,
				Required:      true,
				DefaultFunc:   schema.EnvDefaultFunc("BANYAN_API_KEY", nil),
				ConflictsWith: []string{"api_token", "refresh_token"},
			},
			"refresh_token": {
				Type:          schema.TypeString,
				Optional:      true,
				DefaultFunc:   schema.EnvDefaultFunc("BANYAN_REFRESH_TOKEN", nil),
				Deprecated:    "Configure api_key instead. This attribute will be removed\n   in the 1.0 release of the provider.",
				ConflictsWith: []string{"api_key", "api_token"},
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"banyan_service_infra_ssh": resourceServiceInfraSsh(),
			"banyan_service_infra_rdp": resourceServiceInfraRdp(),
			"banyan_service_infra_tcp": resourceServiceInfraTcp(),
			"banyan_service_infra_k8s": resourceServiceInfraK8s(),
			"banyan_service_infra_db":  resourceServiceInfraDb(),
			"banyan_service_web":       resourceServiceWeb(),
			"banyan_policy_web":        resourcePolicyWeb(),
			"banyan_policy_infra":      resourcePolicyInfra(),
			"banyan_role":              resourceRole(),
			"banyan_policy_attachment": resourcePolicyAttachment(),
			"banyan_api_key":           resourceApiKey(),
			"banyan_connector":         resourceConnector(),
			"banyan_accesstier":        resourceAccessTier(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"banyan_oidc_settings": dataSourceOidcSettings(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

// Remove once fully depreciated
func chooseApiKey(d *schema.ResourceData) (apikey string) {
	k, ok := d.GetOk("api_key")
	if !ok {
		return d.Get("api_token").(string)
	}
	return k.(string)
}

// Configures the Banyan provider with the given refresh / API token and host url
func providerConfigure(ctx context.Context, d *schema.ResourceData) (client interface{}, diagnostic diag.Diagnostics) {
	host := d.Get("host").(string)
	if !strings.HasSuffix(host, "/") {
		host = host + "/"
	}
	client, err := bnnClient.NewClientHolder(host, d.Get("refresh_token").(string), chooseApiKey(d))
	if err != nil {
		diagnostic = append(diagnostic, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to create Banyan client",
			Detail:   "Unable to authenticate to the Banyan API" + fmt.Sprintf("%+v", err),
		})
	}
	return
}
