package banyan

import (
	"context"
	"fmt"

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
				DefaultFunc: schema.EnvDefaultFunc("BANYAN_HOST", "https://console.banyanops.com"),
			},
			"api_token": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("BANYAN_API_TOKEN", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"banyan_service_custom":    resourceServiceCustom(),
			"banyan_service_infra_ssh": resourceServiceInfraSsh(),
			"banyan_service_infra_rdp": resourceServiceInfraRdp(),
			"banyan_service_infra_tcp": resourceServiceInfraTcp(),
			"banyan_service_infra_k8s": resourceServiceInfraK8s(),
			"banyan_service_infra_db":  resourceServiceInfraDb(),
			"banyan_service_web":       resourceServiceInfraWeb(),
			"banyan_policy":            resourcePolicy(),
			"banyan_role":              resourceRole(),
			"banyan_policy_attachment": resourcePolicyAttachment(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"banyan_oidc_settings": dataSourceOidcSettings(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

// Configures the Banyan provider with the given refresh / API token and host url
func providerConfigure(ctx context.Context, d *schema.ResourceData) (client interface{}, diagnostic diag.Diagnostics) {
	refreshToken := d.Get("api_token").(string)
	var domain string
	unAssertedDomain := d.Get("host")
	if unAssertedDomain == nil {
		domain = "https://net.banyanops.com/"
	} else {
		domainTypeAsserted, ok := unAssertedDomain.(string)
		if !ok {
			diagnostic = append(diagnostic, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  "Unable to create Banyan client",
				Detail:   "Unable to authenticate against the provided banyan host url with the given API token",
			})
		}
		domain = domainTypeAsserted
	}

	client, err := bnnClient.NewClientHolder(domain, refreshToken)
	if err != nil {
		diagnostic = append(diagnostic, diag.Diagnostic{
			Severity: diag.Error,
			Summary:  "Unable to create Banyan client",
			Detail:   "Unable to authenticate with the given API token" + fmt.Sprintf("%+v", err),
		})
		return
	}
	return
}
