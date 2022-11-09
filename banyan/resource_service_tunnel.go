package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/servicetunnel"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceServiceTunnel() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of service tunnels. In order to properly function this resource must be utilized with the banyan_accesstier resource or banyan_accesstier2 terraform registry modules. Please see the examples. For more information on SSH services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/service-tunnels/)",
		CreateContext: resourceServiceTunnelCreate,
		ReadContext:   resourceServiceTunnelRead,
		UpdateContext: resourceServiceTunnelUpdate,
		DeleteContext: resourceServiceTunnelDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the service tunnel",
				ForceNew:    true,
			},
			"id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "ID of the service tunnel key in Banyan",
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Description of the service tunnel",
			},
			"access_tier": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the access_tier which the service tunnel should be associated with",
			},
			"policy": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Policy ID to be attached to this service tunnel",
			},
		},
	}
}

func tunFromState(d *schema.ResourceData, cluster string) (tun servicetunnel.Info) {
	tun = servicetunnel.Info{
		Kind:       "BanyanAccessTier",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "attribute-based",
		Metadata: servicetunnel.Metadata{
			Name:         d.Get("name").(string),
			FriendlyName: d.Get("name").(string),
			Description:  d.Get("description").(string),
		},
		Spec: expandServiceTunnelSpec(d, cluster),
	}
	return
}

func resourceServiceTunnelCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	cluster, err := determineCluster(c, d)
	if err != nil {
		return diag.FromErr(err)
	}
	tun, err := c.ServiceTunnel.Create(tunFromState(d, cluster))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(tun.ID)
	err = attachPolicy(c, d)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourceServiceTunnelUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	cluster, err := determineCluster(c, d)
	if err != nil {
		return diag.FromErr(err)
	}
	tun, err := c.ServiceTunnel.Update(d.Id(), tunFromState(d, cluster))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(tun.ID)
	err = attachPolicy(c, d)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func attachPolicy(c *client.Holder, d *schema.ResourceData) (err error) {
	policy := d.Get("policy")
	if policy == nil {
		return
	}
	_, err = c.ServiceTunnel.AttachPolicy(d.Id(), servicetunnel.PolicyAttachmentPost{
		PolicyID: policy.(string),
		Enabled:  true,
	})
	if err != nil {
		return fmt.Errorf("failed to attach policy to service tunnel: %s", err)
	}
	return
}

func resourceServiceTunnelRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	tun, err := c.ServiceTunnel.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	d.SetId(tun.ID)
	err = d.Set("name", tun.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", tun.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = flattenServiceTunnelSpec(d, tun)
	if err != nil {
		return diag.FromErr(err)
	}

	return
}

func resourceServiceTunnelDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	policy, ok := d.GetOk("policy")
	if ok {
		err := c.PolicyAttachment.Delete(policy.(string))
		if err != nil {
			return diag.FromErr(err)
		}
		err = c.ServiceTunnel.DeletePolicy(d.Id(), policy.(string))
	}
	err := c.ServiceTunnel.Delete(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return
}

func expandServiceTunnelSpec(d *schema.ResourceData, cluster string) (expanded servicetunnel.Spec) {
	var peerAccessTiers []servicetunnel.PeerAccessTier
	p := servicetunnel.PeerAccessTier{
		Cluster:     cluster,
		AccessTiers: []string{"", d.Get("access_tier").(string)},
	}
	expanded = servicetunnel.Spec{
		PeerAccessTiers: append(peerAccessTiers, p),
	}
	return
}

func flattenServiceTunnelSpec(d *schema.ResourceData, tun servicetunnel.ServiceTunnelInfo) (err error) {
	if len(tun.Spec.PeerAccessTiers) == 0 {
		return
	}
	err = d.Set("access_tier", tun.Spec.PeerAccessTiers[0].AccessTiers[1])
	return
}
