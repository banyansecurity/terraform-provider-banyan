package banyan

import (
	"context"
	"fmt"
	"strings"

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
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
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
		"description_link": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Link shown to the end user of the banyan app for this service",
		},
		"autorun": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Autorun for the service, if set true service would autorun on the app",
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
		"access_tiers": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Names of the access_tiers which the service tunnel should be associated with",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			ConflictsWith: []string{"connectors"},
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
		"public_traffic_tunnel_via_access_tier": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Access Tier to be used to tunnel through public traffic",
		},
		"policy": {
			Type:        schema.TypeString,
			Required:    true,
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
		"applications_include": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Specifies the applications ids that should be that should be included in the tunnel, ex: 905a72d3-6216-4ffc-ad18-db1593782915",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"applications_exclude": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Specifies the applications ids that should be that should be included in the tunnel, ex: 633301ab-fd20-439b-b5ae-47153ec7fbf2",
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
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
			Autorun: expandAutorun(d),
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
	policy, err := c.ServiceTunnel.GetPolicy(tun.ID)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("policy", policy.PolicyID)
	if err != nil {
		return diag.FromErr(err)
	}
	return
}

func resourceServiceTunnelDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := resourceServiceTunnelDetachPolicy(d, c)
	if err != nil {
		return diag.FromErr(err)
	}
	err = c.ServiceTunnel.Delete(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId("")
	return
}

func resourceServiceTunnelDetachPolicy(d *schema.ResourceData, c *client.Holder) (err error) {
	_, ok := d.GetOk("policy")
	if !ok {
		return nil
	}
	attachedPolicy, err := c.ServiceTunnel.GetPolicy(d.Id())
	if err != nil {
		return err
	}
	err = c.ServiceTunnel.DeletePolicy(d.Id(), attachedPolicy.PolicyID)
	if err != nil {
		return
	}
	// This may not be necessary after policy refactor
	err = c.PolicyAttachment.Delete(attachedPolicy.PolicyID)
	if err != nil {
		return
	}
	return
}

func expandServiceTunnelSpec(d *schema.ResourceData) (expanded servicetunnel.Spec) {
	ats := convertSchemaSetToStringSlice(d.Get("access_tiers").(*schema.Set))
	conns := convertSchemaSetToStringSlice(d.Get("connectors").(*schema.Set))
	inclCidrs := convertSchemaSetToStringSlice(d.Get("public_cidrs_include").(*schema.Set))
	exclCidrs := convertSchemaSetToStringSlice(d.Get("public_cidrs_exclude").(*schema.Set))
	inclDomains := convertSchemaSetToStringSlice(d.Get("public_domains_include").(*schema.Set))
	exclDomains := convertSchemaSetToStringSlice(d.Get("public_domains_exclude").(*schema.Set))
	inclApplications := convertSchemaSetToStringSlice(d.Get("applications_include").(*schema.Set))
	exclApplications := convertSchemaSetToStringSlice(d.Get("applications_exclude").(*schema.Set))

	var peers []servicetunnel.PeerAccessTier

	// if access_tiers not set => global-edge, use ["*"]
	if len(ats) == 0 {
		peers = append(peers, servicetunnel.PeerAccessTier{
			Cluster:     d.Get("cluster").(string),
			AccessTiers: []string{"*"},
			Connectors:  conns,
		})
	} else {
		// If multiple accessTiers are set create peer foreach.
		for i, eachAts := range ats {
			peer := servicetunnel.PeerAccessTier{
				Cluster:     d.Get("cluster").(string),
				AccessTiers: []string{eachAts},
				Connectors:  nil,
			}
			if (inclCidrs != nil) || (exclCidrs != nil) || (inclDomains != nil) || (exclDomains != nil) || (inclApplications != nil) || (exclApplications != nil) {
				publicTrafficAccessTier, ok := d.GetOk("public_traffic_tunnel_via_access_tier")

				if strings.EqualFold(publicTrafficAccessTier.(string), eachAts) ||
					/* if only one access tier */ len(ats) == 1 ||
					/* backward compatibility */ (!ok && i == 0) {
					peer.PublicCIDRs = &servicetunnel.IncludeExclude{
						Include: inclCidrs,
						Exclude: exclCidrs,
					}
					peer.PublicDomains = &servicetunnel.IncludeExclude{
						Include: inclDomains,
						Exclude: exclDomains,
					}
					peer.Applications = &servicetunnel.IncludeExclude{
						Include: inclApplications,
						Exclude: exclApplications,
					}
				}
			}
			peers = append(peers, peer)
		}
	}

	expanded = servicetunnel.Spec{
		PeerAccessTiers: peers,
	}
	return
}

func flattenServiceTunnelSpec(d *schema.ResourceData, tun servicetunnel.ServiceTunnelInfo) (err error) {
	if len(tun.Spec.PeerAccessTiers) == 0 {
		return
	}
	// set common parameters using first peer.
	p1 := tun.Spec.PeerAccessTiers[0]
	err = d.Set("cluster", p1.Cluster)
	if err != nil {
		return err
	}
	// if connectors set => global-edge
	if len(p1.Connectors) > 0 {
		err = d.Set("connectors", p1.Connectors)
		if err != nil {
			return err
		}
		err = d.Set("access_tiers", nil)
		if err != nil {
			return err
		}
	} else {
		var ats []string
		err = d.Set("connectors", nil)
		if err != nil {
			return err
		}
		for _, eachPeer := range tun.Spec.PeerAccessTiers {
			ats = append(ats, eachPeer.AccessTiers...)
			if eachPeer.PublicCIDRs != nil {
				if len(eachPeer.PublicCIDRs.Include) > 0 {
					err = d.Set("public_cidrs_include", eachPeer.PublicCIDRs.Include)
					if err != nil {
						return err
					}
				}
				if len(eachPeer.PublicCIDRs.Exclude) > 0 {
					err = d.Set("public_cidrs_exclude", eachPeer.PublicCIDRs.Exclude)
					if err != nil {
						return err
					}
				}
				if len(eachPeer.AccessTiers) > 0 {
					err = d.Set("public_traffic_tunnel_via_access_tier", eachPeer.AccessTiers[0])
					if err != nil {
						return err
					}
				}

			}
			if eachPeer.PublicDomains != nil {
				if len(eachPeer.PublicDomains.Include) > 0 {
					err = d.Set("public_domains_include", eachPeer.PublicDomains.Include)
					if err != nil {
						return err
					}
				}
				if len(eachPeer.PublicDomains.Exclude) > 0 {
					err = d.Set("public_domains_exclude", eachPeer.PublicDomains.Exclude)
					if err != nil {
						return err
					}
				}
				if len(eachPeer.AccessTiers) > 0 {
					err = d.Set("public_traffic_tunnel_via_access_tier", eachPeer.AccessTiers[0])
					if err != nil {
						return err
					}
				}
			}
			if eachPeer.Applications != nil {
				if len(eachPeer.Applications.Include) > 0 {
					err = d.Set("applications_include", eachPeer.Applications.Include)
					if err != nil {
						return err
					}
				}
				if len(eachPeer.Applications.Exclude) > 0 {
					err = d.Set("applications_exclude", eachPeer.Applications.Exclude)
					if err != nil {
						return err
					}
				}
				if len(eachPeer.AccessTiers) > 0 {
					err = d.Set("public_traffic_tunnel_via_access_tier", eachPeer.AccessTiers[0])
					if err != nil {
						return err
					}
				}
			}
		}
		err = d.Set("access_tiers", ats)
		if err != nil {
			return err
		}
	}
	return
}
