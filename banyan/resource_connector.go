package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/satellite"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
	"log"
)

// Schema for the connector resource. For more information on Banyan policies, see the documentation:
func resourceConnector() *schema.Resource {
	log.Println("[CONNECTOR|RES] getting resource schema")
	return &schema.Resource{
		Description:   "",
		CreateContext: resourceConnectorCreate,
		ReadContext:   resourceConnectorRead,
		UpdateContext: resourceConnectorUpdate,
		DeleteContext: resourceConnectorDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the connector",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the connector in Banyan",
			},
			"satellite_api_key_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "ID of the connector in Banyan",
			},
			"keepalive": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "ID of the connector in Banyan",
				Default:     20,
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
			APIKeyID:  d.Get("satellite_api_key_id").(string),
			Keepalive: int64(d.Get("keepalive").(int)),
			CIDRs:     []string{},
			PeerAccessTiers: []satellite.PeerAccessTier{
				{
					Cluster:     "global-edge",
					AccessTiers: []string{"access-tier"},
				},
			},
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
	if err != nil {
		return handleNotFoundError(d, fmt.Sprintf("connector %q", d.Id()))
	}
	err = d.Set("name", sat.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("id", sat.ID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("satellite_api_key_id", sat.APIKeyID)
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
