package banyan

import (
	"context"
	"fmt"
	"reflect"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	bnnClient "github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/admin/orgidpconfig"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

func resourceService() *schema.Resource {
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
		CreateContext: resourceServiceCreate,
		ReadContext:   resourceServiceRead,
		UpdateContext: resourceServiceUpdate,
		DeleteContext: resourceServiceDelete,
		Schema: map[string]*schema.Schema{
			"attributes": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"tls_sni": {
							Type:        schema.TypeList,
							Description: "",
							Elem:        schema.TypeString,
						},
						"host_tag_selector": {
							Type:        schema.TypeMap,
							Description: "",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"frontend_addresses": {
							Type: schema.TypeList,
							Elem: &schema.Resource{},
						},
					},
				},
			},
		},
	}
}

func resourceServiceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.ClientHolder)
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
	var CreateServiceSpec service.CreateService
	client.Service.Create()
	// read to get the final state
	return resourceOrgIdpConfigRead(ctx, d, m)
}

func resourceServiceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	return resourceOrgIdpConfigCreate(ctx, d, m)
}

func resourceServiceRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*bnnClient.Client)
	orgIdpConfig, err := client.GetOrgIdpConfig()
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

func resourceServiceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {

	return
}
