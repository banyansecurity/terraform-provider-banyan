package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/pkg/errors"
	"log"
	"reflect"
)

func resourcePolicyWeb() *schema.Resource {
	return &schema.Resource{
		Description:   "Banyan policies control access to a service. For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)",
		CreateContext: resourcePolicyWebCreate,
		ReadContext:   resourcePolicyWebRead,
		UpdateContext: resourcePolicyWebUpdate,
		DeleteContext: resourcePolicyWebDelete,
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
						"l7_resources": {
							Type: schema.TypeSet,
							Description: `
								Resources are a list of application level resources.
								Each resource can have wildcard prefix or suffix, or both.
								A resource can be prefixed with "!", meaning DENY.
								Any DENY rule overrides any other rule that would allow the access.`,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"l7_actions": {
							Type:        schema.TypeSet,
							Description: "Actions are a list of application-level actions: \"CREATE\", \"READ\", \"UPDATE\", \"DELETE\", \"*\"",
							Optional:    true,
							Elem: &schema.Schema{
								Type:         schema.TypeString,
								ValidateFunc: validation.StringInSlice([]string{"CREATE", "READ", "UPDATE", "DELETE", "*"}, false),
							},
						},
					},
				},
			},
		},
	}
}

func resourcePolicyWebCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY WEB|RES|CREATE] creating web policy %s : %s", d.Get("name"), d.Id())
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
			Access:    expandPolicyWebAccess(d.Get("access").([]interface{})),
			Exception: policy.Exception{},
			Options: policy.Options{
				DisableTLSClientAuthentication: true,
				L7Protocol:                     "http",
			},
		},
	}
	createdPolicy, err := client.Policy.Create(policyToCreate)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new web policy"))
	}
	log.Printf("[POLICY WEB|RES|CREATE] created web policy %s : %s", d.Get("name"), d.Id())
	d.SetId(createdPolicy.ID)
	diagnostics = resourcePolicyWebRead(ctx, d, m)
	return
}

func resourcePolicyWebUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY WEB|RES|UPDATE] updating web policy %s : %s", d.Get("name"), d.Id())
	diagnostics = resourcePolicyWebCreate(ctx, d, m)
	log.Printf("[POLICY WEB|RES|UPDATE] updated web policy %s : %s", d.Get("name"), d.Id())
	return
}

func resourcePolicyWebRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY WEB|RES|READ] reading web policy %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	id := d.Id()
	policy, ok, err := client.Policy.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get web policy with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("web policy %q", d.Id()))
	}
	err = d.Set("name", policy.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", policy.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("access", flattenPolicyWebAccess(policy.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(policy.ID)
	log.Printf("[POLICY WEB|RES|READ] read policy %s : %s", d.Get("name"), d.Id())
	return
}

func resourcePolicyWebDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICY WEB|RES|DELETE] deleting web policy")

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
	log.Println("[POLICY WEB|RES|DELETE] deleted web policy")
	return
}

func expandPolicyWebAccess(m []interface{}) (access []policy.Access) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		a := policy.Access{
			Roles: convertSchemaSetToStringSlice(data["roles"].(*schema.Set)),
		}
		a.Rules.Conditions.TrustLevel = data["trust_level"].(string)
		a.Rules.L7Access = expandPolicyWebL7Access(data)
		access = append(access, a)
	}
	return
}

func expandPolicyWebL7Access(data map[string]interface{}) (l7Access []policy.L7Access) {
	actions := convertSchemaSetToStringSlice(data["l7_actions"].(*schema.Set))
	if actions == nil {
		actions = []string{"*"}
	}
	resources := convertSchemaSetToStringSlice(data["l7_resources"].(*schema.Set))
	if resources == nil {
		resources = []string{"*"}
	}
	l7Access = append(l7Access, policy.L7Access{
		Actions:   actions,
		Resources: resources,
	})
	return
}

func flattenPolicyWebAccess(toFlatten []policy.Access) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))
	for idx, accessItem := range toFlatten {
		ai := make(map[string]interface{})
		ai["roles"] = accessItem.Roles
		ai["trust_level"] = accessItem.Rules.Conditions.TrustLevel

		l7Resources := accessItem.Rules.L7Access[0].Resources
		if reflect.DeepEqual(l7Resources, []string{"*"}) {
			l7Resources = nil
		}
		ai["l7_resources"] = l7Resources

		l7Actions := accessItem.Rules.L7Access[0].Actions
		if reflect.DeepEqual(l7Actions, []string{"*"}) {
			l7Actions = nil
		}
		ai["l7_actions"] = l7Actions
		flattened[idx] = ai
	}
	return
}
