package banyan

import (
	"context"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/satellite"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
	"log"
)

// Schema for the connector resource. For more information on Banyan policies, see the documentation:
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
			"cluster": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ID of the connector in Banyan. Defaults to banyan global-edge",
				Default:     "global-edge",
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

func resourceConnectorCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[CONNECTOR|RES|CREATE] creating connector %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)

	c := satellite.Info{
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
					Cluster:     d.Get("cluster").(string),
					AccessTiers: []string{"access-tier"},
				},
			},
			DisableSnat: false,
			Domains:     convertSchemaSetToStringSlice(d.Get("domains").(*schema.Set)),
		},
	}
	created, err := client.Satellite.Create(c)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new connector"))
	}
	log.Printf("[CONNECTOR|RES|CREATE] created connector %s : %s", d.Get("name"), d.Id())
	d.SetId(created.ID)
	diagnostics = resourceConnectorRead(ctx, d, m)
	return
}

func resourceConnectorUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[CONNECTOR|RES|UPDATE] updating connector %s : %s", d.Get("name"), d.Id())
	diagnostics = resourceConnectorCreate(ctx, d, m)
	log.Printf("[CONNECTOR|RES|UPDATE] updated connector %s : %s", d.Get("name"), d.Id())
	return
}

func resourceConnectorRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[CONNECTOR|RES|READ] reading connector %sat : %sat", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	sat, err := client.Satellite.Get(d.Id())
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
	d.SetId(d.Id())
	log.Printf("[CONNECTOR|RES|READ] read connector %sat : %sat", d.Get("name"), d.Id())
	return
}

func resourceConnectorDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[CONNECTOR|RES|DELETE] deleting connector")
	client := m.(*client.Holder)
	err := client.Satellite.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Println("[CONNECTOR|RES|DELETE] deleted connector")
	d.SetId("")
	return
}
