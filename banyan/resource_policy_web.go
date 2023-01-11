package banyan

import (
	"context"
	"reflect"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/pkg/errors"
)

func resourcePolicyWeb() *schema.Resource {
	return &schema.Resource{
		Description:   "The web policy resource is used to manage the lifecycle of policies which will be attached to services of the type \"banyan_service_web\". For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)",
		CreateContext: resourcePolicyWebCreate,
		ReadContext:   resourcePolicyWebRead,
		UpdateContext: resourcePolicyWebUpdate,
		DeleteContext: resourcePolicyWebDelete,
		Schema:        PolicyWebSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func PolicyWebSchema() (s map[string]*schema.Schema) {
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
						MinItems:    1,
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
					"l7_access": {
						Type:        schema.TypeList,
						Description: "Indicates whether the end user device is allowed to use L7",
						Optional:    true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"resources": {
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
								"actions": {
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
			},
		},
	}
	return
}

func policyWebFromState(d *schema.ResourceData) (pol policy.Object) {
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
			Access: expandPolicyWebAccess(d.Get("access").([]interface{})),
			Exception: policy.Exception{
				SrcAddr: []string{},
			},
			Options: policy.Options{
				DisableTLSClientAuthentication: true,
				L7Protocol:                     "http",
			},
		},
	}
	return
}

func resourcePolicyWebCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)

	// 	ValidateFunc is not supported on lists or sets, so use this method instead
	err := invalidL7AccessRules(d)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "invalid l7_access block"))
	}

	createdPolicy, err := c.Policy.Create(policyWebFromState(d))
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new web policy"))
	}
	d.SetId(createdPolicy.ID)
	diagnostics = resourcePolicyWebRead(ctx, d, m)
	return
}

func resourcePolicyWebUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourcePolicyWebCreate(ctx, d, m)
	return
}

func resourcePolicyWebRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
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
	err = d.Set("access", flattenPolicyWebAccess(resp.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ID)
	return
}

func resourcePolicyWebDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourcePolicyInfraDelete(ctx, d, m)
	return
}

func invalidL7AccessRules(d *schema.ResourceData) error {
	allow_all := policy.L7Access{Resources: []string{"*"}, Actions: []string{"*"}}

	m := d.Get("access").([]interface{})
	for _, raw := range m {
		data := raw.(map[string]interface{})
		l7_access := data["l7_access"].([]interface{})
		if len(l7_access) == 0 || l7_access[0] == nil || len(l7_access) != 1 {
			continue
		}
		l7_rules := l7_access[0].(map[string]interface{})
		actions := convertSchemaSetToStringSlice(l7_rules["actions"].(*schema.Set))
		resources := convertSchemaSetToStringSlice(l7_rules["resources"].(*schema.Set))
		allow_l7 := policy.L7Access{Resources: resources, Actions: actions}
		if reflect.DeepEqual(allow_l7, allow_all) {
			return errors.New("redundant l7_access block with allow_all rules; remove l7_access block entirely")
		}
	}

	return nil
}

func expandPolicyWebAccess(m []interface{}) (access []policy.Access) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		a := policy.Access{
			Roles: convertSchemaSetToStringSlice(data["roles"].(*schema.Set)),
		}
		a.Rules.Conditions.TrustLevel = data["trust_level"].(string)
		a.Rules.L7Access = expandPolicyWebL7Access(data["l7_access"].([]interface{}))
		access = append(access, a)
	}
	return
}

func expandPolicyWebL7Access(m []interface{}) (l7Access []policy.L7Access) {
	if len(m) == 0 {
		l7Access = append(l7Access, policy.L7Access{
			Actions:   []string{"*"},
			Resources: []string{"*"},
		})
	}
	for _, raw := range m {
		data := raw.(map[string]interface{})
		actions := convertSchemaSetToStringSlice(data["actions"].(*schema.Set))
		if actions == nil {
			actions = []string{"*"}
		}
		resources := convertSchemaSetToStringSlice(data["resources"].(*schema.Set))
		if resources == nil {
			resources = []string{"*"}
		}
		l7Access = append(l7Access, policy.L7Access{
			Actions:   actions,
			Resources: resources,
		})
	}
	return
}

func flattenPolicyWebAccess(toFlatten []policy.Access) (flattened []interface{}) {
	for _, accessItem := range toFlatten {
		ai := make(map[string]interface{})
		ai["roles"] = accessItem.Roles
		ai["trust_level"] = accessItem.Rules.Conditions.TrustLevel
		ai["l7_access"] = flattenPolicyWebL7Access(accessItem.L7Access)
		flattened = append(flattened, ai)
	}
	return
}

func flattenPolicyWebL7Access(toFlatten []policy.L7Access) (flattened []interface{}) {
	omitted := []policy.L7Access{{Resources: []string{"*"}, Actions: []string{"*"}}}
	if reflect.DeepEqual(omitted, toFlatten) {
		// will set these value to nil in the state but leave in API
		/*
			L7 DENY rules are written in "!" format and require the "resources: *, actions: *" at the end

			"l7_access": [
				{
					"resources": [
						"!/wp-admin*"
					],
					"actions": [
						"*"
					]
				},
				{
					"resources": [
						"*"
					],
					"actions": [
						"*"
					]
				}
			],
		*/

		return
	}

	flattened = make([]interface{}, len(toFlatten), len(toFlatten))
	for idx, l7access := range toFlatten {
		l7 := make(map[string]interface{})
		l7["resources"] = l7access.Resources
		l7["actions"] = l7access.Actions
		flattened[idx] = l7
	}
	if len(flattened) == 1 && flattened[0] == nil {
		return nil
	}
	return
}
