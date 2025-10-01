package banyan

import (
	"context"
	"net"
	"strings"

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
			Optional:    true,
			Computed:    true,
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
		"dns_setting": {
			Type:        schema.TypeList,
			Computed:    true, // read only user cannot specify custom values.
			Description: "List of dns settings required for registered domain",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"type": {
						Type:        schema.TypeString,
						Computed:    true,
						Description: "type of DNS setting ex: CNAME , A or TXT",
					},
					"name": {
						Type:        schema.TypeString,
						Computed:    true,
						Description: "name of DNS setting ",
					},
					"value": {
						Type:        schema.TypeString,
						Computed:    true,
						Description: "value of the dns setting",
					},
				},
			},
		},
	}

	return s
}

func resourceRegisteredDomainCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostic diag.Diagnostics) {

	c := m.(*client.Holder)

	rdReqBody := rdFromState(d)

	// if org is global edge create domain challenge first
	if rdReqBody.ClusterName == constants.GlobalEdgeCluster {

		challengeID, err := c.RegisteredDomain.CreateRDChallenge(registereddomain.RegisteredDomainChallengeRequest{
			RegisteredDomainName: rdReqBody.Name,
		})
		if err != nil {
			return diag.FromErr(err)
		}

		rdReqBody.RegisteredDomainChallengeID = &challengeID
	}

	rd, err := c.RegisteredDomain.Create(rdReqBody)
	if err != nil {
		return diag.FromErr(err)
	}

	dnsSettings, err := flattenDnsSettings(d, c, rd)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("dns_setting", dnsSettings)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(rd.ID)

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

	dnsSettings, err := flattenDnsSettings(d, c, resp)
	if err != nil {
		return diag.FromErr(err)
	}

	err = d.Set("dns_setting", dnsSettings)
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

func flattenDnsSettings(d *schema.ResourceData, c *client.Holder, resp registereddomain.RegisteredDomainInfo) (dnsSettings []interface{}, err error) {

	// cname acme is only created for wildcard domains
	if strings.HasPrefix(resp.Name, "*.") {

		dnsSetting := map[string]interface{}{
			"type":  "CNAME",
			"name":  resp.DomainName,
			"value": resp.ACME_cname,
		}

		dnsSettings = append(dnsSettings, dnsSetting)
	}

	// challenge is only created for global edge network.
	if resp.ClusterName == constants.GlobalEdgeCluster {

		var challengeInfo registereddomain.RegisteredDomainChallengeInfo
		challengeInfo, err = c.RegisteredDomain.GetRDChallenge(*resp.RegisteredDomainChallengeID)
		if err != nil {
			return
		}

		dnsSetting := map[string]interface{}{
			"type":  "TXT",
			"name":  challengeInfo.Label,
			"value": challengeInfo.Value,
		}

		dnsSettings = append(dnsSettings, dnsSetting)

	}

	dnsSetting := map[string]interface{}{
		"name":  resp.Name,
		"value": resp.Cname,
	}

	// if cname has ip value then need to create A type of dns setting else CNAME type
	if isIPv4Address(resp.Cname) {
		dnsSetting["type"] = "A"
	} else {
		dnsSetting["type"] = "CNAME"
	}

	dnsSettings = append(dnsSettings, dnsSetting)

	return
}

func isIPv4Address(ip string) bool {
	// Parse the IP address
	parsedIP := net.ParseIP(ip)

	// Check if it's a valid IPv4 address and not empty
	return parsedIP != nil && strings.Contains(ip, ".") && parsedIP.To4() != nil
}
