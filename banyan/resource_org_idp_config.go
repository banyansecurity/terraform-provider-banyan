package banyan

import (
	"context"
	"fmt"
	"log"
	"reflect"

	"github.com/pkg/errors"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/admin/orgidpconfig"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceOrgIdpConfig() *schema.Resource {
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
		CreateContext: resourceOrgIdpConfigCreate,
		ReadContext:   resourceOrgIdpConfigRead,
		UpdateContext: resourceOrgIdpConfigUpdate,
		DeleteContext: resourceOrgIdpConfigDelete,
		Schema: map[string]*schema.Schema{
			"idp_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of your IdP service",
			},
			"idp_protocol": {
				Type:         schema.TypeString,
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"OIDC"}, false),
				Description:  "The protocol your IdP uses. Only Supports OIDC currently",
			},

			"idp_config": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "The details regarding setting up an idp. Currently only supports OIDC. SAML support is planned.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"redirect_url": {
							Type:        schema.TypeString,
							Optional:    true,
							Description: "**ADVANCED USAGE ONLY** No need to set, banyan sets up your default for you.",
						},
						"issuer_url": {
							Type:     schema.TypeString,
							Required: true,
						},
						"client_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"client_secret": {
							Type:      schema.TypeString,
							Required:  true,
							Sensitive: true,
						},
					},
				},
			},
		},
	}
}

func resourceOrgIdpConfigCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("#### creating org\n")
	client := m.(*client.ClientHolder)
	idpName, ok := d.Get("idp_name").(string)
	if !ok {
		err := errors.New("Couldn't type assert idp_name")
		diagnostics = diag.FromErr(err)
		return
	}
	idpProtocol, ok := d.Get("idp_protocol").(string)
	if !ok {
		err := errors.New("Couldn't type assert ipd_protocol")
		diagnostics = diag.FromErr(err)
		return
	}
	idpConfigResource, ok := d.Get("idp_config").([]interface{})
	if !ok {
		idpConfigType := reflect.TypeOf(d.Get("idp_config"))
		err := errors.New("Couldn't type assert idp_config, type is " + fmt.Sprintf("%+v", idpConfigType))
		diagnostics = diag.FromErr(err)
		return
	}
	var issuerUrl string
	var redirectUrl string
	var clientId string
	var clientSecret string
	for _, item := range idpConfigResource {
		ii, ok := item.(map[string]interface{})
		if !ok {
			err := errors.New("Couldn't type assert element in idpConfig")
			diagnostics = diag.FromErr(err)
			return
		}
		issuerUrl, ok = ii["issuer_url"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert issuerUrl"))
			return
		}
		redirectUrl, ok = ii["redirect_url"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert redirectUrl"))
			return
		}
		clientId, ok = ii["client_id"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert clientId"))
			return
		}
		clientSecret, ok = ii["client_secret"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert clientSecret"))
			return
		}
	}

	// make sure we don't overwrite the existing one
	if redirectUrl == "" {
		originalOrgIdpConfig, err := client.Admin.OrgIdpConfig.Get()
		if err != nil {
			diagnostics = diag.FromErr(err)
			return
		}
		redirectUrl = originalOrgIdpConfig.IdpConfig.RedirectUrl
	}

	orgIdpConfig := orgidpconfig.Spec{
		IdpName:     idpName,
		IdpProtocol: idpProtocol,
		IdpConfig: orgidpconfig.IdpConfig{
			RedirectUrl:  redirectUrl,
			IssuerUrl:    issuerUrl,
			ClientId:     clientId,
			ClientSecret: clientSecret,
		},
	}
	client.Admin.OrgIdpConfig.CreateOrUpdate(orgIdpConfig)
	// read to get the final state
	return resourceOrgIdpConfigRead(ctx, d, m)
}

func resourceOrgIdpConfigUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	return resourceOrgIdpConfigCreate(ctx, d, m)
}

func resourceOrgIdpConfigRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.ClientHolder)
	orgIdpConfig, err := client.Admin.OrgIdpConfig.Get()
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.SetId("singleton")
	d.Set("idp_protocol", orgIdpConfig.IdpProtocol)
	d.Set("idp_name", orgIdpConfig.IdpName)
	idpConfig := map[string]interface{}{
		"redirect_url":  orgIdpConfig.IdpConfig.RedirectUrl,
		"issuer_url":    orgIdpConfig.IdpConfig.IssuerUrl,
		"client_id":     orgIdpConfig.IdpConfig.ClientId,
		"client_secret": orgIdpConfig.IdpConfig.ClientSecret,
	}
	d.Set("idp_config", idpConfig)

	return
}

func resourceOrgIdpConfigDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {

	return
}
