package banyan

import (
	"context"
	"reflect"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstier"
	"github.com/banyansecurity/terraform-banyan-provider/client/accesstiregroup"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAccessTierGroup() *schema.Resource {
	return &schema.Resource{
		Description:   "The access tier group resource allows for configuration of the access tier group API object. ",
		CreateContext: resourceAccessTierGroupCreate,
		ReadContext:   resourceAccessTierGroupRead,
		DeleteContext: resourceAccessTierGroupDelete,
		UpdateContext: resourceAccessTierGroupUpdate,
		Schema:        AccessTierGroupSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func AccessTierGroupSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the access tier group in Banyan",
			ForceNew:    true,
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the access tier",
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "description of access tier group",
		},
		"cluster": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Cluster / shield name in Banyan",
		},
		"dns_search_domains": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "",
		},
		"cidrs": {
			Type:        schema.TypeSet,
			Required:    true,
			Description: "CIDR range",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"dns_enabled": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Enable DNS for Service Tunnels (needed to work properly with both private and public targets)",
		},
		"udp_port_number": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "UDP port",
		},
		"keepalive": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "keepalive",
		},
		"domains": {
			Type:        schema.TypeSet,
			Required:    true,
			Description: "Any internal domains that can only be resolved on your internal network’s private DNS",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"advanced_settings": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Advanced settings",
		},
		"shared_fqdn": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "shared fqdn",
		},
		"attach_access_tier_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Access tier IDs to attach to access tier group",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"detach_access_tier_ids": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Access tier IDs to detach from access tier group",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
	}
	return s
}

func resourceAccessTierGroupCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	spec, err := c.AccessTierGroup.Create(atgFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(spec.ID)

	attachIDs := convertSchemaSetToStringSlice(d.Get("attach_access_tier_ids").(*schema.Set))
	if len(attachIDs) != 0 {
		err = attachAccessTier(c, d.Get("id").(string), attachIDs)
		if err != nil {
			return
		}
	}

	return
}

func resourceAccessTierGroupRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	key, err := c.AccessTierGroup.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	d.SetId(key.ID)
	err = d.Set("name", key.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", key.Description)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("cluster", key.ClusterName)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("cidrs", key.TunnelConfig.CIDRs)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("domains", key.TunnelConfig.Domains)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("dns_enabled", key.TunnelConfig.DNSEnabled)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("shared_fqdn", key.TunnelConfig.SharedFQDN)
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceAccessTierGroupUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	_, err := c.AccessTierGroup.Update(d.Id(), atgFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}

	attachIDs := convertSchemaSetToStringSlice(d.Get("attach_access_tier_ids").(*schema.Set))
	if len(attachIDs) != 0 {
		err = attachAccessTier(c, d.Get("id").(string), attachIDs)
		if err != nil {
			return
		}
	}

	detachIDs := convertSchemaSetToStringSlice(d.Get("detach_access_tier_ids").(*schema.Set))
	if len(detachIDs) != 0 {
		err = detachAccessTier(c, d.Get("id").(string), detachIDs)
		if err != nil {
			return
		}
	}

	return
}

func resourceAccessTierGroupDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.AccessTierGroup.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.SetId("")
	return
}

// creates an access tier group from the terraform state
func atgFromState(d *schema.ResourceData) accesstiregroup.AccessTierGroupPost {
	at := accesstiregroup.AccessTierGroupPost{
		Name:             d.Get("name").(string),
		Description:      d.Get("description").(string),
		SharedFQDN:       d.Get("shared_fqdn").(string),
		ClusterName:      d.Get("cluster").(string),
		TunnelEnduser:    setATGTunnelConfigEndUserRequest(d),
		AdvancedSettings: d.Get("advanced_settings").(string),
	}
	return at
}

func setATGTunnelConfigEndUserRequest(d *schema.ResourceData) (expanded *accesstier.AccessTierTunnelInfoPost) {
	e := accesstier.AccessTierTunnelInfoPost{
		UDPPortNumber: d.Get("udp_port_number").(int),
		DNSEnabled:    d.Get("dns_enabled").(bool),
		CIDRs:         convertSchemaSetToStringSlice(d.Get("cidrs").(*schema.Set)),
		Domains:       convertSchemaSetToStringSlice(d.Get("domains").(*schema.Set)),
	}
	if reflect.DeepEqual(e, accesstier.AccessTierTunnelInfoPost{}) {
		return nil
	}
	return &e
}

func attachAccessTier(c *client.Holder, atgID string, atIDs []string) (err error) {

	attachReqBody := accesstiregroup.AccessTierList{
		AccessTierIDs: atIDs,
	}
	_, err = c.AccessTierGroup.AttachAccessTier(atgID, attachReqBody)
	if err != nil {
		return
	}

	return
}

func detachAccessTier(c *client.Holder, atgID string, atIDs []string) (err error) {
	attachReqBody := accesstiregroup.AccessTierList{
		AccessTierIDs: atIDs,
	}
	_, err = c.AccessTierGroup.DetachAccessTier(atgID, attachReqBody)
	if err != nil {
		return
	}

	return
}
