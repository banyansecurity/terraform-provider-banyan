package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
	"log"
)

func resourcePolicyInfra() *schema.Resource {
	return &schema.Resource{
		Description:   "Banyan policies control access to a service. For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)",
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
	log.Printf("[POLICY_INFRA|RES|CREATE] creating infra policy %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)

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
	createdPolicy, err := client.Policy.Create(policyToCreate)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new infra policy"))
	}
	log.Printf("[POLICY_INFRA|RES|CREATE] created infra policy %s : %s", d.Get("name"), d.Id())
	d.SetId(createdPolicy.ID)
	diagnostics = resourcePolicyInfraRead(ctx, d, m)
	return
}

func resourcePolicyInfraUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY_INFRA|RES|UPDATE] updating infra policy %s : %s", d.Get("name"), d.Id())
	diagnostics = resourcePolicyInfraCreate(ctx, d, m)
	log.Printf("[POLICY_INFRA|RES|UPDATE] updated infra policy %s : %s", d.Get("name"), d.Id())
	return
}

func resourcePolicyInfraRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY_INFRA|RES|READ] reading infra policy %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	id := d.Id()
	policy, ok, err := client.Policy.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get infra policy with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("infra policy %q", d.Id()))
	}
	err = d.Set("name", policy.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", policy.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("access", flattenPolicyInfraAccess(policy.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(policy.ID)
	log.Printf("[POLICY_INFRA|RES|READ] read infra policy %s : %s", d.Get("name"), d.Id())
	return
}

func resourcePolicyInfraDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICY_INFRA|RES|DELETE] deleting infra policy")

	client := m.(*client.Holder)
	err := client.Policy.Detach(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = client.Policy.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	log.Println("[POLICY_INFRA|RES|DELETE] deleted infra policy")
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
