package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client/dns"
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
		"lock_autorun": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Lock autorun for the service, if set true service tunnel will be always autorun. end user cannot set it off",
		},

		"peer_access_tiers": {
			Type:        schema.TypeSet,
			Optional:    true,
			Description: "Add a network that will be accessible via this Service Tunnel.",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"cluster": {
						Type:        schema.TypeString,
						Computed:    true,
						Optional:    true,
						Description: "cluster name where access-tier belongs to",
					},
					"access_tiers": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"connectors": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"public_cidrs": {
						Type:     schema.TypeSet,
						Optional: true,
						MaxItems: 1,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"include": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"exclude": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
							},
						},
					},
					"public_domains": {
						Type:     schema.TypeSet,
						Optional: true,
						MaxItems: 1,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"include": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"exclude": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
							},
						},
					},
					"applications": {
						Type:     schema.TypeSet,
						Optional: true,
						MaxItems: 1,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"include": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
								"exclude": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Schema{
										Type: schema.TypeString,
									},
								},
							},
						},
					},
					"access_tier_group": {
						Type:        schema.TypeString,
						Optional:    true,
						Default:     "",
						Description: "AccessTier group name",
					},
				},
			},
		},
		"name_resolution": {
			Type:        schema.TypeSet,
			Optional:    true,
			MaxItems:    1,
			Description: "Private Search Domains",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"name_servers": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"dns_search_domains": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
				},
			},
		},
		"policy": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Policy ID to be attached to this service tunnel",
		},
		"policy_enforcing": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Policy Enforcing / Permissive",
		},
	}
	return
}

func TunFromState(d *schema.ResourceData) (tun servicetunnel.Info, err error) {
	icon := ""
	descriptionLink := ""
	spec, err := expandServiceTunnelSpec(d)
	if err != nil {
		return
	}
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
			Autorun:     expandAutorun(d),
			LockAutoRun: expandLockAutorun(d),
		},
		Spec: spec,
	}
	return
}
func resourceServiceTunnelCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	state, err := TunFromState(d)
	if err != nil {
		return diag.FromErr(err)
	}
	tun, err := c.ServiceTunnel.Create(state)
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
	state, err := TunFromState(d)
	if err != nil {
		return diag.FromErr(err)
	}
	tun, err := c.ServiceTunnel.Update(d.Id(), state)
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
	policyEnforcing := d.Get("policy_enforcing")
	if policyEnforcing == nil {
		return
	}

	_, err = c.ServiceTunnel.AttachPolicy(d.Id(), servicetunnel.PolicyAttachmentPost{
		PolicyID: policy.(string),
		Enabled:  policyEnforcing.(bool),
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
	err = flattenServiceTunnelSpec(d, tun.Spec.Spec)
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

	policyEnforcing := false
	if "TRUE" == strings.ToUpper(policy.Enabled) {
		policyEnforcing = true
	}
	err = d.Set("policy_enforcing", policyEnforcing)
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
	err = c.PolicyAttachment.Delete(attachedPolicy.PolicyID)
	if err != nil {
		return
	}
	return
}

func expandServiceTunnelSpec(d *schema.ResourceData) (expanded servicetunnel.Spec, err error) {
	peers, err := expandPeerAccessTiers(d)
	if err != nil {
		return
	}

	expanded = servicetunnel.Spec{
		PeerAccessTiers: peers,
	}
	nameResolution, err := expandNameResolution(d)
	if err != nil {
		return
	}
	if nameResolution != nil {
		expanded.NameResolution = nameResolution
	}
	return
}

func expandNameResolution(d *schema.ResourceData) (nameResolutionRef *dns.NameResolutionInfo, err error) {
	nameResolutionSet := d.Get("name_resolution").(*schema.Set)
	var nameResolution dns.NameResolutionInfo
	nameResolution.NameServers = make([]string, 0)
	nameResolution.DnsSearchDomains = make([]string, 0)
	for _, eachNameResolution := range nameResolutionSet.List() {
		eachNameResolutionItem, ok := eachNameResolution.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("unable to read name_resolution")
			return
		}
		nameServer, ok := eachNameResolutionItem["name_servers"].([]interface{})
		if !ok {
			err = fmt.Errorf("unable to read name_servers")
			return
		}
		for _, eachNameServer := range nameServer {
			eachNameServerString, ok := eachNameServer.(string)
			if ok {
				nameResolution.NameServers = append(nameResolution.NameServers, eachNameServerString)
			}
		}
		dnsSearchDomains, ok := eachNameResolutionItem["dns_search_domains"].([]interface{})
		if !ok {
			err = fmt.Errorf("unable to read dns_search_domains")
			return
		}
		for _, eachDnsSearchDomains := range dnsSearchDomains {
			eachDnsSearchDomainsString, ok := eachDnsSearchDomains.(string)
			if ok {
				nameResolution.DnsSearchDomains = append(nameResolution.DnsSearchDomains, eachDnsSearchDomainsString)
			}
		}
	}
	if len(nameResolution.NameServers) > 0 || len(nameResolution.NameServers) > 0 {
		nameResolutionRef = &nameResolution
	}
	return
}

func expandPeerAccessTiers(d *schema.ResourceData) (peers []servicetunnel.PeerAccessTier, err error) {
	peers = make([]servicetunnel.PeerAccessTier, 0)
	peerAccessTierConfigs := d.Get("peer_access_tiers").(*schema.Set)
	for _, eachPeer := range peerAccessTierConfigs.List() {
		var peer servicetunnel.PeerAccessTier
		eachPeerAccessTier, ok := eachPeer.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("unable to parse PeerAccessTier")
			return
		}
		if len(eachPeerAccessTier) == 0 {
			continue
		}

		if connectorsRaw, ok := eachPeerAccessTier["connectors"]; ok {
			connectors, ok := connectorsRaw.([]interface{})
			if !ok {
				err = fmt.Errorf("unable to parse connectors")
				return
			}

			for _, eachConnector := range connectors {
				connectorString, ok := eachConnector.(string)
				if ok {
					peer.Connectors = append(peer.Connectors, connectorString)
				}
			}

		}

		if len(peer.Connectors) > 0 {
			peer.AccessTiers = []string{"*"}
		}

		atsRaw, ok := eachPeerAccessTier["access_tiers"]
		// Ignore access_tier if set if there is connector set and set as {*} as it would be a global edge access_tier
		if ok && len(peer.Connectors) == 0 {
			ats, ok := atsRaw.([]interface{})
			if !ok {
				err = fmt.Errorf("unable to parse access_tiers")
				return
			}
			for _, eachAt := range ats {
				eachAtString, ok := eachAt.(string)
				if ok {
					peer.AccessTiers = append(peer.AccessTiers, eachAtString)
				}
			}
		}

		if atGroupRaw, ok := eachPeerAccessTier["access_tier_group"]; ok {
			atGroup, ok := atGroupRaw.(string)
			if !ok {
				err = fmt.Errorf("unable to parse access_tier_group")
				return
			}
			if atGroup != "" && len(peer.AccessTiers) > 0 {
				err = fmt.Errorf("invalid configuration cannot set both access_tier_group and access_tiers")
				return
			}
			if atGroup != "" {
				peer.AccessTierGroup = atGroup
			}
		}

		if clusterNameRaw, ok := eachPeerAccessTier["cluster"]; ok {
			clusterName, ok := clusterNameRaw.(string)
			if !ok {
				err = fmt.Errorf("unable to parse cluster")
				return
			}
			peer.Cluster = clusterName
		}

		if publicCIDRsRaw, ok := eachPeerAccessTier["public_cidrs"]; ok {
			publicCIDRs, myErr := extractIncludeExclude("public_cidrs", publicCIDRsRaw)
			if myErr != nil {
				err = myErr
				return
			}
			peer.PublicCIDRs = publicCIDRs
		}

		if publicDomainsRaw, ok := eachPeerAccessTier["public_domains"]; ok {
			publicDomains, myErr := extractIncludeExclude("public_domains", publicDomainsRaw)
			if myErr != nil {
				err = myErr
				return
			}
			peer.PublicDomains = publicDomains
		}

		if applicationsRaw, ok := eachPeerAccessTier["applications"]; ok {
			applications, myErr := extractIncludeExclude("applications", applicationsRaw)
			if myErr != nil {
				err = myErr
				return
			}
			peer.Applications = applications
		}
		peers = append(peers, peer)
	}
	return
}

func extractIncludeExclude(key string, inputRaw interface{}) (extracted *servicetunnel.IncludeExclude, err error) {
	var inputBlock servicetunnel.IncludeExclude
	inputRawSet, ok := inputRaw.(*schema.Set)
	if !ok {
		err = fmt.Errorf("unable to parse " + key)
		return
	}
	inputList := inputRawSet.List()
	if len(inputList) > 1 {
		err = fmt.Errorf("max length is 1 for " + key)
		return
	}
	for _, eachInput := range inputList {
		input, ok := eachInput.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("unable to read " + key + " block")
			return
		}
		if inputInclude, ok := input["include"]; ok {
			inputIncludeList, ok := inputInclude.([]interface{})
			if !ok {
				err = fmt.Errorf("unable to read " + key + "inlude ist")
			}
			for _, eachInputInclude := range inputIncludeList {
				eachInputIncludeString, ok := eachInputInclude.(string)
				if ok {
					inputBlock.Include = append(inputBlock.Include, eachInputIncludeString)
				}
			}
		}
		if inputExclude, ok := input["exclude"]; ok {
			inputExcludeList, ok := inputExclude.([]interface{})
			if !ok {
				err = fmt.Errorf("unable to read " + key + "exclude ist")
			}

			for _, eachInputExclude := range inputExcludeList {
				eachInputExcludeString, ok := eachInputExclude.(string)
				if ok {
					inputBlock.Exclude = append(inputBlock.Exclude, eachInputExcludeString)
				}
			}
		}
		extracted = &inputBlock
	}
	return
}

func flattenServiceTunnelSpec(d *schema.ResourceData, spec servicetunnel.Spec) (err error) {
	if len(spec.PeerAccessTiers) == 0 {
		return
	}

	flattened := make([]interface{}, 0)
	for _, eachPeerAccessTier := range spec.PeerAccessTiers {
		eachPeerAccessTierMap := make(map[string]interface{})
		if len(eachPeerAccessTier.AccessTiers) > 0 {
			eachPeerAccessTierMap["access_tiers"] = eachPeerAccessTier.AccessTiers
		}
		if len(eachPeerAccessTier.Connectors) > 0 {
			eachPeerAccessTierMap["connectors"] = eachPeerAccessTier.Connectors
		}
		if eachPeerAccessTier.AccessTierGroup != "" {
			eachPeerAccessTierMap["access_tier_group"] = eachPeerAccessTier.AccessTierGroup
		}
		if eachPeerAccessTier.Cluster != "" {
			eachPeerAccessTierMap["cluster"] = eachPeerAccessTier.Cluster
		}
		if eachPeerAccessTier.PublicCIDRs != nil {
			publicCIDRs := make(map[string]interface{})
			publicCIDRs["include"] = eachPeerAccessTier.PublicCIDRs.Include
			publicCIDRs["exclude"] = eachPeerAccessTier.PublicCIDRs.Exclude
			eachPeerAccessTierMap["public_cidrs"] = []map[string]interface{}{publicCIDRs}
		}

		if eachPeerAccessTier.PublicDomains != nil {
			publicDomains := make(map[string]interface{})
			publicDomains["include"] = eachPeerAccessTier.PublicDomains.Include
			publicDomains["exclude"] = eachPeerAccessTier.PublicDomains.Exclude
			eachPeerAccessTierMap["public_domains"] = []map[string]interface{}{publicDomains}
		}

		if eachPeerAccessTier.Applications != nil {
			applications := make(map[string]interface{})
			applications["include"] = eachPeerAccessTier.Applications.Include
			applications["exclude"] = eachPeerAccessTier.Applications.Exclude
			eachPeerAccessTierMap["applications"] = applications
		}
		if len(eachPeerAccessTierMap) > 0 {
			flattened = append(flattened, eachPeerAccessTierMap)
		}
	}
	err = d.Set("peer_access_tiers", flattened)
	if err != nil {
		return err
	}
	return
}

func expandLockAutorun(d *schema.ResourceData) bool {
	lockAutorun, exists := d.GetOk("lock_autorun")
	if exists {
		return lockAutorun.(bool)
	}
	return false
}
