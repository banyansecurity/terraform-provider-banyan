package banyan

import (
	"context"

	"github.com/banyansecurity/terraform-banyan-provider/client"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// data source to retrieve information for oidc settings
func dataSourceOidcSettings() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceOidcSettingsRead,
		Description: "Obtains information describing the OIDC settings from banyan",
		Schema: map[string]*schema.Schema{
			"issuer_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"authorization_endpoint": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"token_endpoint": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"jwks_endpoint": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"redirect_url": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"scope": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"userinfo_endpoint": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"openid_configuration_endpoint": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourceOidcSettingsRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	myClient := m.(*client.Holder)
	oidcSettings, err := myClient.Admin.OidcSettings.Get()
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("issuer_url", oidcSettings.IssuerUrl)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("authorization_endpoint", oidcSettings.AuthorizationEndpoint)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("token_endpoint", oidcSettings.TokenEndpoint)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("jwks_endpoint", oidcSettings.JwksEndpoint)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("redirect_url", oidcSettings.IssuerUrl+"/callback")
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("scope", oidcSettings.Scope)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("userinfo _endpoint", oidcSettings.UserinfoEndpoint)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("openid_configuration_endpoint", oidcSettings.OpenidConfigurationEndpoint)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("singleton")
	return
}
