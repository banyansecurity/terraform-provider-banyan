package banyan

import (
	"context"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/registereddomain"
	"github.com/banyansecurity/terraform-banyan-provider/constants"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRegisteredDomain() *schema.Resource {
	return &schema.Resource{
		Description:   "Registered domain resource allows for configuration of the registered domain API object",
		CreateContext: resourceRegisteredDomainCreate,
		ReadContext:   resourceRegisteredDomainRead,
		DeleteContext: resourceRegisteredDomainDelete,
		Schema:        RegisteredDomainSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func RegisteredDomainSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Unique ID for a registered domain",
			ForceNew:    true,
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the registered domain",
			ForceNew:    true,
		},
		"cluster": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "cluster name used to identify if cluster type is private edge or global edge",
			ForceNew:    true,
		},
		"cname": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "CNAME of the access-tier",
			ForceNew:    true,
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "description of registered domain",
			Default:     "",
			ForceNew:    true,
		},
		"cname_setting_name": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "CNAME type dns setting name",
			ForceNew:    true,
			Computed:    true,
		},
		"cname_setting_value": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "CNAME type dns setting value ",
			ForceNew:    true,
			Computed:    true,
		},
		"txt_setting_name": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "TXT type dns setting name",
			ForceNew:    true,
			Computed:    true,
		},
		"txt_setting_value": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "TXT type dns setting value",
			ForceNew:    true,
			Computed:    true,
		},
		"cname_acme_setting_name": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "CNAME type acme dns setting name",
			ForceNew:    true,
			Computed:    true,
		},
		"cname_acme_setting_value": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "CNAME type acme dns setting value",
			ForceNew:    true,
			Computed:    true,
		},
	}

	return s
}

func resourceRegisteredDomainCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostic diag.Diagnostics) {

	c := m.(*client.Holder)

	rdReqBody := rdFromState(d)

	// if org is global edge create domain challenge first
	if rdReqBody.ClusterName == constants.GlobalEdgeCluster {

		challengeID, err := c.RegisteredDomain.CreateRDChallenge(registereddomain.RegisteredDomainChallengeRequest{
			RegisteredDomainName: rdReqBody.Name,
		})
		if err != nil {
			return
		}

		rdReqBody.RegisteredDomainChallengeID = &challengeID
	}

	rd, err := c.RegisteredDomain.Create(rdReqBody)
	if err != nil {
		return diag.FromErr(err)
	}

	err = setDNSSettingsValues(d, c, rd)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(rd.ID)

	return
}

func rdFromState(d *schema.ResourceData) registereddomain.RegisteredDomainRequest {

	return registereddomain.RegisteredDomainRequest{
		RegisteredDomainInfo: registereddomain.RegisteredDomainInfo{
			Name:        d.Get("name").(string),
			ClusterName: d.Get("cluster").(string),
			Cname:       d.Get("cname").(string),
			Description: d.Get("description").(string),
		},
	}

}

func resourceRegisteredDomainRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostic diag.Diagnostics) {

	id := d.Get("id").(string)
	c := m.(*client.Holder)
	resp, err := c.RegisteredDomain.Get(id)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("name", resp.Name)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("cluster", resp.ClusterName)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("cname", resp.Cname)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("description", resp.Description)
	if err != nil {
		return diag.FromErr(err)
	}

	err = setDNSSettingsValues(d, c, resp)
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceRegisteredDomainDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostic diag.Diagnostics) {

	id := d.Get("id").(string)
	c := m.(*client.Holder)

	err := c.RegisteredDomain.Delete(id)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId("")

	return
}

func setDNSSettingsValues(d *schema.ResourceData, c *client.Holder, resp registereddomain.RegisteredDomainInfo) (err error) {

	// cname acme is only created for wildcard domains
	if strings.HasPrefix(resp.Name, "*.") {
		err = d.Set("cname_acme_setting_name", resp.DomainName)
		if err != nil {
			return
		}

		err = d.Set("cname_acme_setting_value", resp.ACME_cname)
		if err != nil {
			return
		}

	}

	err = d.Set("cname_setting_name", resp.Name)
	if err != nil {
		return
	}

	err = d.Set("cname_setting_value", resp.Cname)
	if err != nil {
		return
	}

	// challenge is only created for global edge network.
	if resp.ClusterName == constants.GlobalEdgeCluster {

		var challengeInfo registereddomain.RegisteredDomainChallengeInfo
		challengeInfo, err = c.RegisteredDomain.GetRDChallenge(*resp.RegisteredDomainChallengeID)
		if err != nil {
			return
		}

		err = d.Set("txt_setting_name", challengeInfo.Label)
		if err != nil {
			return
		}

		err = d.Set("txt_setting_value", challengeInfo.Value)
		if err != nil {
			return
		}

	}

	return
}
