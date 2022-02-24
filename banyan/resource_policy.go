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
		Description:   "Banyan policy for controlling access to a service",
		CreateContext: resourcePolicyCreate,
		ReadContext:   resourcePolicyRead,
		UpdateContext: resourcePolicyUpdate,
		DeleteContext: resourcePolicyDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of your service",
			},
			"description": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "description of your service",
			},
			"metadatatags": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "The details regarding setting up an idp. Currently only supports OIDC. SAML support is planned.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"template": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validatePolicyTemplate(),
						},
					},
				},
			},
			"access": {
				Type:        schema.TypeList,
				MinItems:    0,
				Optional:    true,
				Description: "access",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"roles": {
							Type: schema.TypeSet,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
							Optional: true,
						},
						"rules": {
							Type:        schema.TypeList,
							MinItems:    1,
							MaxItems:    1,
							Optional:    true,
							Description: "rules for enforcing security policy",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"conditions": {
										Type:     schema.TypeList,
										MinItems: 1,
										MaxItems: 1,
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"trust_level": {
													Type:         schema.TypeString,
													Required:     true,
													ValidateFunc: validateTrustLevel(),
												},
											},
										},
									},
									"l7_access": {
										Type:        schema.TypeList,
										MinItems:    1,
										Optional:    true,
										Description: "ha",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"resources": {
													Type:     schema.TypeSet,
													Required: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"actions": {
													Type:     schema.TypeSet,
													Required: true,
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
			"exception": {
				Type:        schema.TypeList,
				MaxItems:    1,
				MinItems:    1,
				Optional:    true,
				Description: "HTTP settings used for x",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"source_address": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"disable_tls_client_authentication": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"l7_protocol": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validateL7Protocol(),
			},
		},
	}
}

func validateL7Protocol() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v != "http" && v != "" {
			errs = append(errs, fmt.Errorf("%q must be %q or \"\", got: %q", key, "WEB_USER", v))
		}
		return
	}
}

func validateTrustLevel() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v != "High" && v != "Medium" && v != "Low" && v != "" {
			// this error message might need to be cleaned up to handle the empty trustlevel
			errs = append(errs, fmt.Errorf("%q must be one of the following %q, got: %q", key, []string{"High", "Medium", "Low", ""}, v))
		}
		return
	}
}

func validatePolicyTemplate() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v != "USER" && v != "" {
			errs = append(errs, fmt.Errorf("%q must be %q or \"\", got: %q", key, "WEB_USER", v))
		}
		return
	}
}

func resourcePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[POLICY|RES|CREATE] creating policy %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)

	policyToCreate := policy.CreatePolicy{
		APIVersion: "rbac.banyanops.com/v1",
		Kind:       "BanyanPolicy",
		Metadata: policy.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			Tags:        expandPolicyMetatdataTags(d.Get("metadatatags").([]interface{})),
		},
		Type: "USER",
		Spec: policy.Spec{
			Access:    expandPolicyAccess(d.Get("access").([]interface{})),
			Exception: expandPolicyException(d.Get("exception").([]interface{})),
			Options:   expandPolicyOptions(d),
		},
	}
	createdPolicy, err := client.Policy.Create(policyToCreate)
	if err != nil {
		diag.FromErr(errors.WithMessage(err, "couldn't create new policy"))
		return
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
	client := m.(*client.ClientHolder)
	id := d.Id()
	policy, ok, err := client.Policy.Get(id)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessagef(err, "couldn't get policy with id: %s", id))
		return
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
	metadatatags := map[string]interface{}{
		"template": policy.UnmarshalledPolicy.Metadata.Tags.Template,
	}
	err = d.Set("metadatatags", []interface{}{metadatatags})
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("access", flattenPolicyAccess(policy.UnmarshalledPolicy.Spec.Access))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("exception", flattenPolicyException(policy.UnmarshalledPolicy.Spec.Exception))
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

	client := m.(*client.ClientHolder)
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

func expandPolicyMetatdataTags(m []interface{}) (metadatatags policy.Tags) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	metadatatags = policy.Tags{
		Template: itemMap["template"].(string),
	}
	return
}

func expandPolicyAccess(m []interface{}) (access []policy.Access) {
	for _, raw := range m {
		data := raw.(map[string]interface{})
		access = append(access, policy.Access{
			Roles: convertSchemaSetToStringSlice(data["roles"].(*schema.Set)),
			Rules: expandPolicyRules(data["rules"].([]interface{})),
		})
	}
	return
}

func expandPolicyRules(m []interface{}) (rules policy.Rules) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	rules = policy.Rules{
		Conditions: expandPolicyConditions(itemMap["conditions"].([]interface{})),
		L7Access:   expandPolicyL7Access(itemMap["l7_access"].([]interface{})),
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

func expandPolicyConditions(m []interface{}) (conditions policy.Conditions) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	conditions = policy.Conditions{
		TrustLevel: itemMap["trust_level"].(string),
	}
	return
}

func expandPolicyException(m []interface{}) (exception policy.Exception) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	exception = policy.Exception{
		SourceAddress: convertSchemaSetToStringSlice(itemMap["source_address"].(*schema.Set)),
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

func flattenPolicySpec(toFlatten policy.Spec) (flattened []interface{}) {
	s := make(map[string]interface{})
	s["options"] = flattenPolicyOptions(toFlatten.Options)
	s["exception"] = flattenPolicyException(toFlatten.Exception)
	s["access"] = flattenPolicyAccess(toFlatten.Access)
	flattened = append(flattened, s)
	return
}

func flattenPolicyOptions(toFlatten policy.Options) (flattened []interface{}) {
	o := make(map[string]interface{})
	o["disable_tls_client_authentication"] = toFlatten.DisableTLSClientAuthentication
	o["l7_protocol"] = toFlatten.L7Protocol
	flattened = append(flattened, o)
	return
}

func flattenPolicyException(toFlatten policy.Exception) (flattened []interface{}) {
	e := make(map[string]interface{})
	e["source_address"] = toFlatten.SourceAddress
	flattened = append(flattened, e)
	return
}

func flattenPolicyAccess(toFlatten []policy.Access) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))
	for idx, accessItem := range toFlatten {
		ai := make(map[string]interface{})
		ai["roles"] = accessItem.Roles
		ai["rules"] = flattenPolicyRules(accessItem.Rules)
		flattened[idx] = ai
	}
	return
}

func flattenPolicyRules(toFlatten policy.Rules) (flattened []interface{}) {
	r := make(map[string]interface{})
	r["conditions"] = flattenPolicyConditions(toFlatten.Conditions)
	r["l7_access"] = flattenPolicyL7Access(toFlatten.L7Access)
	flattened = append(flattened, r)
	return
}

func flattenPolicyConditions(toFlatten policy.Conditions) (flattened []interface{}) {
	c := make(map[string]interface{})
	c["trust_level"] = toFlatten.TrustLevel
	flattened = append(flattened, c)
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
