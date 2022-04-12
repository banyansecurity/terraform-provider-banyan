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

// Schema for the policy resource. For more information on Banyan policies, see the documentation:
func resourcePolicy() *schema.Resource {
	log.Println("[POLICY|RES] getting resource schema")
	return &schema.Resource{
		Description:   "Banyan policies control access to a service. For more information on Banyan policies, see the [documentation.](https://docs.banyanops.com/docs/feature-guides/administer-security-policies/policies/manage-policies/)",
		CreateContext: resourcePolicyCreate,
		ReadContext:   resourcePolicyRead,
		UpdateContext: resourcePolicyUpdate,
		DeleteContext: resourcePolicyDelete,
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
						"l7_access": {
							Type:        schema.TypeList,
							MinItems:    1,
							Optional:    true,
							Description: "Specifies a set of access rights to application level (OSI Layer-7) resources.\n\n",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"resources": {
										Type: schema.TypeSet,
										Description: `
														Resources are a list of application level resources.
														Each resource can have wildcard prefix or suffix, or both.
														A resource can be prefixed with "!", meaning DENY.
														Any DENY rule overrides any other rule that would allow the access.
														`,
										Required: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"actions": {
										Type:        schema.TypeSet,
										Description: "Actions are a list of application-level actions: \"READ\", \"WRITE\", \"CREATE\", \"UPDATE\", \"*\"",
										Required:    true,
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
			"disable_tls_client_authentication": {
				Type:        schema.TypeBool,
				Description: "Prevents the service from asking for a client TLS cert",
				Optional:    true,
			},
			"l7_protocol": {
				Type: schema.TypeString,
				Description: `
					L7Protocol specifies the application-level protocol: "http", "kafka", or empty string.
					If L7Protocol is not empty, then all Access rules must have L7Access entries.`,
				Optional:     true,
				ValidateFunc: validateL7Protocol(),
			},
		},
	}
}

func resourcePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY|RES|CREATE] creating policy %s : %s", d.Get("name"), d.Id())
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
			Access: expandPolicyAccess(d.Get("access").([]interface{})),
			// TODO: implement workaround or fix api for this returning empty list after creation
			Exception: policy.Exception{},
			Options:   expandPolicyOptions(d),
		},
	}
	createdPolicy, err := client.Policy.Create(policyToCreate)
	if err != nil {
		return diag.FromErr(errors.WithMessage(err, "couldn't create new policy"))
	}
	log.Printf("[POLICY|RES|CREATE] created policy %s : %s", d.Get("name"), d.Id())
	d.SetId(createdPolicy.ID)
	diagnostics = resourcePolicyRead(ctx, d, m)
	return
}

func resourcePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY|RES|UPDATE] updating policy %s : %s", d.Get("name"), d.Id())
	diagnostics = resourcePolicyCreate(ctx, d, m)
	log.Printf("[POLICY|RES|UPDATE] updated policy %s : %s", d.Get("name"), d.Id())
	return
}

func resourcePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY|RES|READ] reading policy %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	id := d.Id()
	policy, ok, err := client.Policy.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get policy with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	err = d.Set("name", policy.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description", policy.Description)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("access", flattenPolicyAccess(policy.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("disable_tls_client_authentication", policy.UnmarshalledPolicy.Spec.Options.DisableTLSClientAuthentication)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("l7_protocol", policy.UnmarshalledPolicy.Spec.Options.L7Protocol)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(policy.ID)
	log.Printf("[POLICY|RES|READ] read policy %s : %s", d.Get("name"), d.Id())
	return
}

func resourcePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICY|RES|DELETE] deleting policy")

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
	log.Println("[POLICY|RES|DELETE] deleted policy")
	return
}

func expandPolicyAccess(m []interface{}) (access []policy.Access) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		a := policy.Access{
			Roles: convertSchemaSetToStringSlice(data["roles"].(*schema.Set)),
		}
		a.Rules.Conditions.TrustLevel = data["trust_level"].(string)
		a.Rules.L7Access = expandPolicyL7Access(data["l7_access"].([]interface{}))
		access = append(access, a)
	}
	return
}

func expandPolicyL7Access(m []interface{}) (l7Access []policy.L7Access) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		l7Access = append(l7Access, policy.L7Access{
			Actions:   convertSchemaSetToStringSlice(data["actions"].(*schema.Set)),
			Resources: convertSchemaSetToStringSlice(data["resources"].(*schema.Set)),
		})
	}
	return
}

func expandPolicyOptions(d *schema.ResourceData) (options policy.Options) {
	options = policy.Options{
		DisableTLSClientAuthentication: d.Get("disable_tls_client_authentication").(bool),
		L7Protocol:                     d.Get("l7_protocol").(string),
	}
	return
}

func flattenPolicyAccess(toFlatten []policy.Access) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))
	for idx, accessItem := range toFlatten {
		ai := make(map[string]interface{})
		ai["roles"] = accessItem.Roles
		ai["trust_level"] = accessItem.Rules.Conditions.TrustLevel
		ai["l7_access"] = flattenPolicyL7Access(accessItem.Rules.L7Access)
		flattened[idx] = ai
	}
	return
}

func flattenPolicyL7Access(toFlatten []policy.L7Access) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))
	for idx, accessItem := range toFlatten {
		ai := make(map[string]interface{})
		ai["resources"] = accessItem.Resources
		ai["actions"] = accessItem.Actions
		flattened[idx] = ai
	}
	return
}
