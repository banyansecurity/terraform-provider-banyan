package banyan

import (
	"context"

	"github.com/banyansecurity/terraform-banyan-provider/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type oidcSettings struct {
	IssuerUrl                   string `json:"issuer_url"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	JwksEndpoint                string `json:"jwks_endpoint"`
	RedirectUrl                 string `json:"redirect_url"`
	Scope                       string `json:"scope"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
	OpenidConfigurationEndpoint string `json:"openid_configuration_endpoint"`
}

// data source to retrieve information for oidc settings
func dataSourceOidcSettings() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceOidcSettingsRead,
		Schema: map[string]*schema.Schema{
			"issuer_url": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"authorization_endpoint": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"token_endpoint": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"jwks_endpoint": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"redirect_url": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"scope": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"userinfo_endpoint": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"openid_configuration_endpoint": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceOidcSettingsRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.Holder)
	oidcSettings, err := client.Admin.OidcSettings.Get()
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.Set("issuer_url", oidcSettings.IssuerUrl)
	d.Set("authorization_endpoint", oidcSettings.AuthorizationEndpoint)
	d.Set("token_endpoint", oidcSettings.TokenEndpoint)
	d.Set("jwks_endpoint", oidcSettings.JwksEndpoint)
	d.Set("redirect_url", oidcSettings.IssuerUrl+"/callback")
	d.Set("scope", oidcSettings.Scope)
	d.Set("userinfo _endpoint", oidcSettings.UserinfoEndpoint)
	d.Set("openid_configuration_endpoint", oidcSettings.OpenidConfigurationEndpoint)
	d.SetId("singleton")
	return
}
