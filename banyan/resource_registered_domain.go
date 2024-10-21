package banyan

import (
	"context"

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
	}

	return s
}

func resourceRegisteredDomainCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostic diag.Diagnostics) {

	c := m.(*client.Holder)

	rdReqBody := rdFromState(d)

	if rdReqBody.ClusterName == constants.GlobalEdgeCluster {

		challengeID, err := c.RegisteredDomain.CreateRDChallenge(registereddomain.RegisteredDomainChallengeRequest{
			RegisteredDomainName: rdReqBody.Name,
		})
		if err != nil {
			return
		}

		rdReqBody.RegisteredDomainChallengeID = &challengeID
	}

	atg, err := c.RegisteredDomain.Create(rdReqBody)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(atg.ID)

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
