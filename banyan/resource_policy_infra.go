package banyan

import (
	"context"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourcePolicyInfra() *schema.Resource {
	return &schema.Resource{
		Description:   "The infrastructure policy resource is used to manage the lifecycle of policies which will be attached to services of the type \"banyan_service_db\" \"banyan_service_k8s\" \"banyan_service_rdp\" \"banyan_service_ssh\" and \"banyan_service_tunnel\". For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)",
		CreateContext: resourcePolicyInfraCreate,
		ReadContext:   resourcePolicyInfraRead,
		UpdateContext: resourcePolicyInfraUpdate,
		DeleteContext: resourcePolicyInfraDelete,
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
					},
				},
			},
		},
	}
}

func resourcePolicyInfraCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	policyToCreate := policy.CreatePolicy{
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
			Access:    expandPolicyInfraAccess(d.Get("access").([]interface{})),
			Exception: policy.Exception{},
			Options: policy.Options{
				DisableTLSClientAuthentication: false,
				L7Protocol:                     "",
			},
		},
	}
	resp, err := c.Policy.Create(policyToCreate)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	diagnostics = resourcePolicyInfraRead(ctx, d, m)
	return
}

func resourcePolicyInfraRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.Policy.Get(d.Id())
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
	err = d.Set("access", flattenPolicyInfraAccess(resp.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	return
}

func resourcePolicyInfraUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourcePolicyInfraCreate(ctx, d, m)
	return
}

func resourcePolicyInfraDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	err := c.Policy.Detach(c.PolicyAttachment, d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = c.Policy.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	d.SetId("")
	return
}

func expandPolicyInfraAccess(m []interface{}) (access []policy.Access) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		a := policy.Access{
			Roles: convertSchemaSetToStringSlice(data["roles"].(*schema.Set)),
		}
		a.Rules.Conditions.TrustLevel = data["trust_level"].(string)
		access = append(access, a)
	}
	return
}

func flattenPolicyInfraAccess(toFlatten []policy.Access) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))
	for idx, accessItem := range toFlatten {
		ai := make(map[string]interface{})
		ai["roles"] = accessItem.Roles
		ai["trust_level"] = accessItem.Rules.Conditions.TrustLevel
		flattened[idx] = ai
	}
	return
}
