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
				Type:       schema.TypeString,
				Optional:   true,
				Deprecated: "Configure api_key instead. This attribute will be removed\n   in the 1.0 release of the provider.",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("BANYAN_API_KEY", nil),
			},
			"refresh_token": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("BANYAN_REFRESH_TOKEN", nil),
				Deprecated:  "Configure api_key instead. This attribute will be removed\n   in the 1.0 release of the provider.",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"banyan_service_infra_ssh": resourceServiceInfraSshDepreciated(),
			"banyan_service_infra_rdp": resourceServiceInfraRdpDepreciated(),
			"banyan_service_infra_tcp": resourceServiceInfraTcpDepreciated(),
			"banyan_service_infra_k8s": resourceServiceInfraK8sDepreciated(),
			"banyan_service_infra_db":  resourceServiceInfraDbDepreciated(),
			"banyan_service_ssh":       resourceServiceInfraSsh(),
			"banyan_service_rdp":       resourceServiceInfraRdp(),
			"banyan_service_tcp":       resourceServiceInfraTcp(),
			"banyan_service_k8s":       resourceServiceInfraK8s(),
			"banyan_service_db":        resourceServiceInfraDb(),
			"banyan_service_web":       resourceServiceWeb(),
			"banyan_policy_web":        resourcePolicyWeb(),
			"banyan_policy_infra":      resourcePolicyInfra(),
			"banyan_role":              resourceRole(),
			"banyan_policy_attachment": resourcePolicyAttachment(),
			"banyan_api_key":           resourceApiKey(),
			"banyan_connector":         resourceConnector(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"banyan_oidc_settings": dataSourceOidcSettings(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

// Configures the Banyan provider with the given refresh / API token and host url
func providerConfigure(ctx context.Context, d *schema.ResourceData) (client interface{}, diagnostic diag.Diagnostics) {
	refreshToken := d.Get("refresh_token").(string)
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
	client, err := bnnClient.NewClientHolder(domain, refreshToken, d.Get("api_token").(string))
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
