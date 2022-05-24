package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/servicetunnel"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/pkg/errors"
	"log"
)

// Schema for the access tier resource. For more information on Banyan policies, see the documentation:
func resourceAccessTier() *schema.Resource {
	return &schema.Resource{
		Description:   "",
		CreateContext: resourceAccessTierCreate,
		ReadContext:   resourceAccessTierRead,
		UpdateContext: resourceAccessTierUpdate,
		DeleteContext: resourceAccessTierDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the access tier",
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the access tier in Banyan",
			},
			"cluster": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Cluster the access tier belongs to",
			},
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Public address of the access tier",
			},
			"domains": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Domains which are pointed to the access tier",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"connector_tunnel_port": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Port for connectors to this access tier to utilize",
				Default:      51821,
				ValidateFunc: validatePort(),
			},
			"end_user_tunnel_port": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "Port for end users of this access tier to utilize",
				Default:      51820,
				ValidateFunc: validatePort(),
			},
			"end_user_tunnel_backend_cidrs": {
				Type:        schema.TypeSet,
				Optional:    true,
				MinItems:    1,
				Description: "",
				Elem: &schema.Schema{
					Type:         schema.TypeString,
					ValidateFunc: validation.IsCIDRNetwork(0, 32),
				},
			},
			"end_user_tunnel_private_domains": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Port for connectors to this access tier to utilize",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"end_user_tunnel_enable_private_dns": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Port for connectors to this access tier to utilize",
				Default:     false,
			},
		},
	}
}

func accessTier(d *schema.ResourceData) servicetunnel.AccessTierInfo {
	tunnelSatellite := servicetunnel.AccessTierTunnelInfo{
		Keepalive:     20,
		UDPPortNumber: int64(d.Get("connector_tunnel_port").(int)),
	}
	tunnelEnduser := servicetunnel.AccessTierTunnelInfo{
		DNSSearchDomains: "",
		UDPPortNumber:    int64(d.Get("end_user_tunnel_port").(int)),
		DNSEnabled:       d.Get("end_user_tunnel_enable_private_dns").(bool),
		Keepalive:        20,
		CIDRs:            convertSchemaSetToStringSlice(d.Get("end_user_tunnel_backend_cidrs").(*schema.Set)),
		Domains:          convertSchemaSetToStringSlice(d.Get("end_user_tunnel_private_domains").(*schema.Set)),
	}
	s := servicetunnel.AccessTierInfo{
		ID:              d.Get("id").(string),
		Name:            d.Get("name").(string),
		Address:         d.Get("address").(string),
		Domains:         convertSchemaSetToStringSlice(d.Get("domains").(*schema.Set)),
		TunnelSatellite: &tunnelSatellite,
		TunnelEnduser:   &tunnelEnduser,
		ClusterName:     d.Get("cluster").(string),
	}
	return s
}

func resourceAccessTierCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[ACCESSTIER|RES|CREATE] creating access tier %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	updated, err := client.AccessTier.Create(accessTier(d))
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new access tier"))
	}
	log.Printf("[ACCESSTIER|RES|CREATE] updated access tier %s : %s", d.Get("name"), d.Id())
	d.SetId(updated.ID)
	diagnostics = resourceAccessTierRead(ctx, d, m)
	return
}

func resourceAccessTierUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[ACCESSTIER|RES|UPDATE] updating access tier %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	updated, err := client.AccessTier.Update(accessTier(d))
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new access tier"))
	}
	log.Printf("[ACCESSTIER|RES|CREATE] updated access tier %s : %s", d.Get("name"), d.Id())
	d.SetId(updated.ID)
	diagnostics = resourceAccessTierRead(ctx, d, m)
	return
}

func resourceAccessTierRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[ACCESSTIER|RES|READ] reading access tier %sat : %sat", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	at, err := client.AccessTier.Get(d.Id())
	if err != nil {
		return handleNotFoundError(d, fmt.Sprintf("access tier %q", d.Id()))
	}
	err = d.Set("name", at.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("id", at.ID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("cluster", at.ClusterName)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("address", at.Address)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("domains", at.Domains)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("connector_tunnel_port", at.TunnelSatellite.UDPPortNumber)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("end_user_tunnel_port", at.TunnelEnduser.UDPPortNumber)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("end_user_tunnel_backend_cidrs", at.TunnelEnduser.CIDRs)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("end_user_tunnel_private_domains", at.TunnelEnduser.Domains)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("end_user_tunnel_enable_private_dns", at.TunnelEnduser.DNSEnabled)
	if err != nil {
		return diag.FromErr(err)
	}
	log.Printf("[ACCESSTIER|RES|READ] read access tier %sat : %sat", d.Get("name"), d.Id())
	return
}

func resourceAccessTierDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[ACCESSTIER|RES|DELETE] deleting access tier")
	client := m.(*client.Holder)
	err := client.AccessTier.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Println("[ACCESSTIER|RES|DELETE] deleted access tier")
	d.SetId("")
	return
}
