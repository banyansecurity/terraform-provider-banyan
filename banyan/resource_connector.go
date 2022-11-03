package banyan

import (
	"context"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/satellite"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
	"time"
)

func resourceConnector() *schema.Resource {
	return &schema.Resource{
		Description:   "",
		CreateContext: resourceConnectorCreate,
		ReadContext:   resourceConnectorRead,
		UpdateContext: resourceConnectorUpdate,
		DeleteContext: resourceConnectorDelete,
		Schema: map[string]*schema.Schema{
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the connector in Banyan",
			},
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the connector",
			},
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of a satellite scoped API key to be used for connector authentication",
			},
			"keepalive": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Keepalive value for the connector",
				Default:     20,
			},
			"cidrs": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Specifies the IPv4 address ranges of your private network in CIDR notation, ex: 192.168.1.0/24. Note that you can only specify private IP address ranges as defined in RFC-1918.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"access_tiers": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Name of the access tier the connector will use to establish a secure dial-out connection. Set to \"global-edge\" for a global-edge connector",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"domains": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Specifies the domains that should resolve at a DNS server in your private network, ex: mycompany.local.",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
		},
	}
}

func connectorFromState(d *schema.ResourceData) (info satellite.Info) {
	spec := satellite.Info{
		Kind:       "BanyanConnector",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "attribute-based",
		Metadata: satellite.Metadata{
			Name:        d.Get("name").(string),
			DisplayName: d.Get("name").(string),
		},
		Spec: satellite.Spec{
			APIKeyID:  d.Get("api_key").(string),
			Keepalive: int64(d.Get("keepalive").(int)),
			CIDRs:     convertSchemaSetToStringSlice(d.Get("cidrs").(*schema.Set)),
			PeerAccessTiers: []satellite.PeerAccessTier{
				{
					Cluster:     "global-edge",
					AccessTiers: []string{"access-tier"},
				},
			},
			DisableSnat: false,
			Domains:     convertSchemaSetToStringSlice(d.Get("domains").(*schema.Set)),
		},
	}
	return spec
}

func resourceConnectorCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	created, err := c.Satellite.Create(connectorFromState(d))
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new connector"))
	}
	d.SetId(created.ID)
	diagnostics = resourceConnectorRead(ctx, d, m)
	return
}

func resourceConnectorRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	sat, err := c.Satellite.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("name", sat.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("id", sat.ID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("api_key", sat.APIKeyID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("keepalive", sat.Keepalive)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourceConnectorUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	_, err := c.Satellite.Update(d.Id(), connectorFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}
	diagnostics = resourceConnectorRead(ctx, d, m)
	return
}

func resourceConnectorDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.Satellite.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = resource.RetryContext(ctx, 180*time.Second, func() *resource.RetryError {
		err = c.Satellite.Delete(d.Id())
		if err != nil {
			if err.Error() == "" {
				return nil
			}
			return resource.RetryableError(err)
		}
		return nil
	})

	if err != nil {
		return diag.Errorf("timed out deleting connector: %s", d.Get("name").(string))
	}
	d.SetId("")
	return
}
