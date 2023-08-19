package banyan

import (
	"context"

	"github.com/pkg/errors"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourcePolicyTunnelSchema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the policy",
		},
		"id": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "ID of the policy in Banyan",
		},
		"description": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Description of the policy",
		},
		"access": {
			Type:        schema.TypeList,
			Computed:    true,
			Description: "Access describes the access rights for a set of roles",
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"roles": {
						Type:        schema.TypeSet,
						Description: "Role names to include ",
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
						Computed: true,
					},
					"trust_level": {
						Type:        schema.TypeString,
						Description: "The trust level of the end user device, must be one of: \"High\", \"Medium\", \"Low\", or \"\"",
						Required:    true,
					},
					"l4_access": {
						Type:        schema.TypeList,
						Computed:    true,
						Description: "L4 access rules",
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"allow": {
									Type:        schema.TypeList,
									Description: "Role names to include ",
									Computed:    true,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"cidrs": {
												Type:        schema.TypeSet,
												Description: "Allowed CIDRs through the service tunnel",
												Computed:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
											"protocols": {
												Type:        schema.TypeSet,
												Description: "Allowed protocols through the service tunnel. Set to \"TCP\", \"UDP\", \"ICMP\", or \"ALL\"",
												Computed:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
											"ports": {
												Type:        schema.TypeSet,
												Description: "Allowed ports through the service tunnel",
												Computed:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
											"fqdns": {
												Type:        schema.TypeSet,
												Description: "Allowed FQDNs through the service tunnel",
												Computed:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
										},
									},
								},
								"deny": {
									Type:        schema.TypeList,
									Description: "Role names to include ",
									Computed:    true,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"cidrs": {
												Type:        schema.TypeSet,
												Description: "Denied CIDRs through the service tunnel",
												Optional:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
											"protocols": {
												Type:        schema.TypeSet,
												Description: "Denied protocols through the service tunnel. Set to \"TCP\", \"UDP\", \"ICMP\", or \"ALL\"",
												Optional:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
											"ports": {
												Type:        schema.TypeSet,
												Description: "Denied ports through the service tunnel",
												Optional:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
											"fqdns": {
												Type:        schema.TypeSet,
												Description: "Allowed FQDNs through the service tunnel",
												Optional:    true,
												Elem: &schema.Schema{
													Type: schema.TypeString,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	return
}

func dataSourcePolicyTunnel() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourcePolicyTunnelRead,
		Schema:      dataSourcePolicyTunnelSchema(),
	}
}

// /v1/security_policies
func dataSourcePolicyTunnelRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {

	client := m.(*client.Holder)
	tunnelPolicy, err := client.Policy.GetName(d.Get("name").(string))

	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}

	if tunnelPolicy.ID == "" {
		err = errors.New("Could not find role with name: " + d.Get("name").(string))
		return diag.FromErr(err)
	}

	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("name", tunnelPolicy.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", tunnelPolicy.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("access", flattenPolicyTunnelAccess(tunnelPolicy.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(tunnelPolicy.ID)
	return
}
