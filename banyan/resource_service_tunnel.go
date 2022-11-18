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
		Description:   "Resource used for lifecycle management of service tunnels. In order to properly function this resource must be utilized with the banyan_accesstier resource or banyan_accesstier2 terraform registry modules. Please see the example below and in the terraform modules for the respective cloud provider. For more information on service tunnels see the documentation https://docs.banyansecurity.io/docs/feature-guides/service-tunnels/",
		CreateContext: resourceServiceTunnelCreate,
		ReadContext:   resourceServiceTunnelRead,
		UpdateContext: resourceServiceTunnelUpdate,
		DeleteContext: resourceServiceTunnelDelete,
		Schema:        TunnelSchema(),
	}
}

func TunnelSchema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the service tunnel key in Banyan",
			ForceNew:    true,
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the service tunnel",
			ForceNew:    true,
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Description of the service tunnel",
		},
		"access_tiers": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Names of the access_tiers which the service tunnel should be associated with",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			ConflictsWith: []string{"connectors"},
		},
		"connectors": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Names of the connectors which the service tunnel should be associated with",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			ConflictsWith: []string{"access_tiers"},
		},
		"public_cidrs_include": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Specifies public IP addresses in CIDR notation that should be included in the tunnel, ex: 8.8.0.0/16.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"public_cidrs_exclude": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Specifies public IP addresses in CIDR notation that should be excluded from the tunnel, ex: 8.8.12.0/24.",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"public_domains_include": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Specifies the domains that should be that should be included in the tunnel, ex: cnn.com",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"public_domains_exclude": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Specifies the domains that should be that should be excluded from the tunnel, ex: zoom.us",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"policy": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Policy ID to be attached to this service tunnel",
		},
		"cluster": {
			Type:        schema.TypeString,
			Description: "(Depreciated) Sets the cluster / shield for the service",
			Computed:    true,
			Optional:    true,
			Deprecated:  "This attribute is now configured automatically. This attribute will be removed in a future release of the provider.",
			ForceNew:    true,
		},
	}
	return
}

func TunFromState(d *schema.ResourceData) (tun servicetunnel.Info) {
	icon := ""
	descriptionLink := ""

	tun = servicetunnel.Info{
		Kind:       "BanyanServiceTunnel",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Metadata: servicetunnel.Metadata{
			Name:         d.Get("name").(string),
			FriendlyName: d.Get("name").(string),
			Description:  d.Get("description").(string),
			Tags: servicetunnel.Tags{
				Icon:            &icon,
				DescriptionLink: &descriptionLink,
			},
		},
		Spec: expandServiceTunnelSpec(d),
	}
	return
}

func resourceServiceTunnelCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	c := m.(*client.Holder)
	tun, err := c.ServiceTunnel.Create(TunFromState(d))
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
	tun, err := c.ServiceTunnel.Update(d.Id(), TunFromState(d))
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
		if err != nil {
			return diag.FromErr(err)
		}
	}
	err := c.ServiceTunnel.Delete(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return
}

func expandServiceTunnelSpec(d *schema.ResourceData) (expanded servicetunnel.Spec) {
	ats := convertSchemaSetToStringSlice(d.Get("access_tiers").(*schema.Set))
	conns := convertSchemaSetToStringSlice(d.Get("connectors").(*schema.Set))
	incl_cidrs := convertSchemaSetToStringSlice(d.Get("public_cidrs_include").(*schema.Set))
	excl_cidrs := convertSchemaSetToStringSlice(d.Get("public_cidrs_exclude").(*schema.Set))
	incl_domains := convertSchemaSetToStringSlice(d.Get("public_domains_include").(*schema.Set))
	excl_domains := convertSchemaSetToStringSlice(d.Get("public_domains_exclude").(*schema.Set))

	// 1st peer
	var p1 servicetunnel.PeerAccessTier

	// if access_tiers not set => global-edge, use ["*"]
	if len(ats) == 0 {
		p1 = servicetunnel.PeerAccessTier{
			Cluster:     d.Get("cluster").(string),
			AccessTiers: []string{"*"},
			Connectors:  conns,
		}
	} else {
		p1 = servicetunnel.PeerAccessTier{
			Cluster:     d.Get("cluster").(string),
			AccessTiers: []string{ats[0]},
			Connectors:  nil,
		}
	}

	// 1st peer always gets public CIDR and Domain logic
	if (incl_cidrs != nil) || (excl_cidrs != nil) || (incl_domains != nil) || (excl_domains != nil) {
		p1.PublicCIDRs = &servicetunnel.PublicCIDRDomain{
			Include: incl_cidrs,
			Exclude: excl_cidrs,
		}
		p1.PublicDomains = &servicetunnel.PublicCIDRDomain{
			Include: incl_domains,
			Exclude: excl_domains,
		}
	}

	var peerAccessTiers []servicetunnel.PeerAccessTier
	peerAccessTiers = append(peerAccessTiers, p1)

	// if multiple ATs, add individually to peerAccessTiers
	if len(ats) > 1 {
		for _, atSec := range ats[1:] {
			pSec := servicetunnel.PeerAccessTier{
				Cluster:     d.Get("cluster").(string),
				AccessTiers: []string{atSec},
			}
			peerAccessTiers = append(peerAccessTiers, pSec)
		}

	}

	expanded = servicetunnel.Spec{
		PeerAccessTiers: peerAccessTiers,
	}
	return
}

func flattenServiceTunnelSpec(d *schema.ResourceData, tun servicetunnel.ServiceTunnelInfo) (err error) {
	if len(tun.Spec.PeerAccessTiers) == 0 {
		return
	}

	// 1st peer
	p1 := tun.Spec.PeerAccessTiers[0]

	// if connectors set => global-edge
	if len(p1.Connectors) > 0 {
		d.Set("cluster", p1.Cluster)
		d.Set("connectors", p1.Connectors)
		d.Set("access_tiers", nil)
	} else {
		// 1st peer
		d.Set("cluster", p1.Cluster)
		d.Set("connectors", nil)
		ats := p1.AccessTiers
		// if multiple ATs, add later
		if len(tun.Spec.PeerAccessTiers) > 1 {
			for _, pSec := range tun.Spec.PeerAccessTiers[1:] {
				atSec := pSec.AccessTiers
				ats = append(ats, atSec...)
			}
		}
		d.Set("access_tiers", ats)
	}

	if p1.PublicCIDRs != nil {
		d.Set("public_cidrs_include", p1.PublicCIDRs.Include)
		d.Set("public_cidrs_exclude", p1.PublicCIDRs.Exclude)
		d.Set("public_domains_include", p1.PublicDomains.Include)
		d.Set("public_domains_exclude", p1.PublicDomains.Exclude)
	}

	return
}
