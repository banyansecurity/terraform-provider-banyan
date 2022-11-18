package banyan

import (
	"context"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/pkg/errors"
)

func resourcePolicyTunnel() *schema.Resource {
	return &schema.Resource{
		Description:   "The tunnel policy resource is used to manage the lifecycle of policies which will be attached to services of the type \"banyan_service_tunnel\". For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)",
		CreateContext: resourcePolicyTunnelCreate,
		ReadContext:   resourcePolicyTunnelRead,
		UpdateContext: resourcePolicyTunnelUpdate,
		DeleteContext: resourcePolicyTunnelDelete,
		Schema: map[string]*schema.Schema{
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
				Required:    true,
				Description: "Description of the policy",
			},
			"access": {
				Type:        schema.TypeList,
				MinItems:    1,
				Required:    true,
				Description: "Access describes the access rights for a set of roles",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"roles": {
							Type:        schema.TypeSet,
							Description: "Roles that all have the access rights given by rules",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Required: true,
						},
						"trust_level": {
							Type:         schema.TypeString,
							Description:  "The trust level of the end user device, must be one of: \"High\", \"Medium\", \"Low\", or \"\"",
							Required:     true,
							ValidateFunc: validateTrustLevel(),
						},
						"l4_access_allow": {
							Type:        schema.TypeList,
							Description: "Roles that all have the access rights given by rules",
							Optional:    true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"cidrs": {
										Type:        schema.TypeSet,
										Description: "Allowed CIDRs through the service tunnel",
										Optional:    true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"protocols": {
										Type:        schema.TypeSet,
										Description: "Allowed protocols through the service tunnel",
										Optional:    true,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.StringInSlice([]string{"TCP", "UDP", "ICMP", "ALL"}, false),
										},
									},
									"ports": {
										Type:        schema.TypeSet,
										Description: "Allowed ports through the service tunnel",
										Optional:    true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
								},
							},
						},
						"l4_access_deny": {
							Type:        schema.TypeList,
							Description: "Roles that all have the access rights given by rules",
							Optional:    true,
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
										Description: "Denied protocols through the service tunnel",
										Optional:    true,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.StringInSlice([]string{"TCP", "UDP", "ICMP", "ALL"}, false),
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
								},
							},
						},
					},
				},
			},
		},
	}
}

func policyTunnelFromState(d *schema.ResourceData) (pol policy.Object) {
	pol = policy.Object{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanPolicy",
		Metadata: policy.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			Tags: policy.Tags{
				Template: "USER",
			},
		},
		Type: "USER",
		Spec: policy.Spec{
			Access:    expandPolicyTunnelAccess(d.Get("access").([]interface{})),
			Exception: policy.Exception{},
			Options:   policy.Options{},
		},
	}
	return
}

func resourcePolicyTunnelCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	createdPolicy, err := c.Policy.Create(policyTunnelFromState(d))
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new tunnel policy"))
	}
	d.SetId(createdPolicy.ID)
	diagnostics = resourcePolicyTunnelRead(ctx, d, m)
	return
}

func resourcePolicyTunnelUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourcePolicyTunnelCreate(ctx, d, m)
	return
}

func resourcePolicyTunnelRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	id := d.Id()
	resp, err := c.Policy.Get(id)
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("name", resp.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", resp.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("access", flattenPolicyTunnelAccess(resp.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	return
}

func resourcePolicyTunnelDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.Policy.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = c.Policy.Detach(c.PolicyAttachment, resp.ID)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = c.Policy.Delete(resp.ID)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	return
}

func expandPolicyTunnelAccess(m []interface{}) (access []policy.Access) {
	for _, raw := range m {
		data := raw.(map[string]interface{})

		a := policy.Access{
			Roles: convertSchemaSetToStringSlice(data["roles"].(*schema.Set)),
			Rules: policy.Rules{
				L4Access: expandL4Access(data),
			},
		}
		a.Rules.Conditions.TrustLevel = data["trust_level"].(string)

		access = append(access, a)
	}
	return
}

func expandL4Access(data map[string]interface{}) *policy.L4Access {
	allow := expandL4Rules(data["l4_access_allow"].([]interface{}))
	deny := expandL4Rules(data["l4_access_deny"].([]interface{}))
	p := policy.L4Access{
		Allow: allow,
		Deny:  deny,
	}
	return &p
}

func expandL4Rules(m interface{}) (l4Rules []policy.L4Rule) {
	for _, r := range m.([]interface{}) {
		rule := r.(map[string]interface{})
		cidrs := convertSchemaSetToStringSlice(rule["cidrs"].(*schema.Set))
		if cidrs == nil {
			cidrs = []string{"*"}
		}
		protocols := convertSchemaSetToStringSlice(rule["protocols"].(*schema.Set))
		if protocols == nil {
			protocols = []string{"*"}
		}
		ports := convertSchemaSetToStringSlice(rule["ports"].(*schema.Set))
		if ports == nil {
			ports = []string{"ALL"}
		}
		l4Rules = append(l4Rules, policy.L4Rule{
			CIDRs:     cidrs,
			Protocols: protocols,
			Ports:     ports,
		})
	}
	return
}

func flattenPolicyTunnelAccess(toFlatten []policy.Access) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))
	for idx, accessItem := range toFlatten {
		ai := make(map[string]interface{})
		ai["roles"] = accessItem.Roles
		ai["trust_level"] = accessItem.Rules.Conditions.TrustLevel
		ai["l4_access_allow"] = flattenL4Rules(accessItem.L4Access.Allow)
		ai["l4_access_deny"] = flattenL4Rules(accessItem.L4Access.Deny)
		flattened[idx] = ai
	}
	return
}

func flattenL4Rules(l4Rules []policy.L4Rule) (flattened []interface{}) {
	for _, rule := range l4Rules {
		flattened = append(flattened, map[string]interface{}{
			"cidrs":     rule.CIDRs,
			"protocols": rule.Protocols,
			"ports":     rule.Ports,
		})
	}
	return
}