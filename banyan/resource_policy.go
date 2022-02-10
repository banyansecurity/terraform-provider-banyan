package banyan

import (
	"context"
	"fmt"
	"log"
	"reflect"
	"regexp"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

func resourcePolicy() *schema.Resource {
	log.Println("[POLICY|RES] getting resource schema")
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
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
			"spec": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "The spec",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
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
							Required:    true,
							Description: "HTTP settings used for x",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"src_addr": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
								},
							},
						},
						"options": {
							Type:        schema.TypeList,
							MaxItems:    1,
							MinItems:    1,
							Required:    true,
							Description: "options for policy",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"disable_tls_client_authentication": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"l7_protocol": {
										Type:         schema.TypeString,
										Required:     true,
										ValidateFunc: validateL7Protocol(),
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

var onlyLettersAndNumbersRegex = regexp.MustCompile("^[A-Za-z0-9-_]+$")
var domainRegex = regexp.MustCompile(`^(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?$`)
var ipRegex = regexp.MustCompile(`^[0-9\/\.]+$`)

func resourcePolicyCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICY|RES|CREATE] creating policy")
	client := m.(*client.ClientHolder)
	name, ok := d.Get("name").(string)
	if !ok {
		diagnostics = diag.Errorf("Couldn't type assert name")
		return
	}
	description, ok := d.Get("description").(string)
	if !ok {
		diagnostics = diag.Errorf("Couldn't type assert description")
		return
	}
	policyToCreate := policy.CreatePolicy{
		Metadata: policy.Metadata{
			Name:        name,
			Description: description,
		},
		Kind:       "BanyanPolicy",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "USER",
	}

	metadatatags, ok := d.Get("metadatatags").([]interface{})
	if !ok {
		metadatatags := reflect.TypeOf(d.Get("metadatatags"))
		diagnostics = diag.Errorf("Couldn't type assert metadatags, type is " + fmt.Sprintf("%+v", metadatatags))
		return
	}
	for _, item := range metadatatags {
		ii, ok := item.(map[string]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert element in metadatatags")
			return
		}

		policyToCreate.Metadata.Tags.Template, ok = ii["template"].(string)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert template")
			return
		}
	}

	spec, ok := d.Get("spec").([]interface{})
	if !ok {
		spec := reflect.TypeOf(d.Get("spec"))
		err := errors.New("Couldn't type assert spec, type is " + fmt.Sprintf("%+v", spec))
		diagnostics = diag.FromErr(err)
		return
	}
	for _, item := range spec {
		ii, ok := item.(map[string]interface{})
		if !ok {
			err := errors.New("Couldn't type assert element in spec")
			diagnostics = diag.FromErr(err)
			return
		}

		exception, ok := ii["exception"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert exception")
			return
		}
		for _, exceptionItem := range exception {
			exceptionItemMap, ok := exceptionItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert exception item map")
				return
			}
			srcAddr, ok := exceptionItemMap["src_addr"].(*schema.Set)
			if !ok {
				diagnostics = diag.Errorf("couldn't type assert src_addr to type: %+v", reflect.TypeOf(exceptionItemMap["src_addr"]))
				return
			}
			for _, srcAddr := range srcAddr.List() {
				srcAddrValue, ok := srcAddr.(string)
				if !ok {
					diagnostics = diag.FromErr(errors.New("couldn't type assert srcAddrValue"))
					return
				}
				if !ipRegex.MatchString(srcAddrValue) && !domainRegex.MatchString(srcAddrValue) {
					diagnostics = append(diagnostics, diag.Errorf("src_addr: %q didn't match expected pattern for ip address or domain", srcAddrValue)...)
				}
				policyToCreate.Spec.Exception.SourceAddress = append(policyToCreate.Spec.Exception.SourceAddress, srcAddrValue)
			}
			// check if there is more than one error and return an error. Terraform cannot validate lists or sets currently
			if len(diagnostics) > 0 {
				return
			}
		}
		options, ok := ii["options"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert options")
			return
		}
		for _, optionsItem := range options {
			optionsMap, ok := optionsItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert optionsMap map")
				return
			}
			disableTLSClientAuthentication, ok := optionsMap["disable_tls_client_authentication"].(bool)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert disable_tls_client_authentication enabled")
				return
			}
			policyToCreate.Spec.Options.DisableTLSClientAuthentication = disableTLSClientAuthentication

			l7Protocol, ok := optionsMap["l7_protocol"].(string)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert l7_protocol")
				return
			}
			policyToCreate.Spec.Options.L7Protocol = l7Protocol
		}

		access, ok := ii["access"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert access")
			return
		}
		for _, accessItem := range access {
			access := policy.Access{}
			accessItemMap, ok := accessItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert access value %+v", reflect.TypeOf(accessItem))
				return
			}
			roles, ok := accessItemMap["roles"].(*schema.Set)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert roles")
				return
			}
			rolesSlice := []string{}
			for _, role := range roles.List() {
				roleValue, ok := role.(string)
				if !ok {
					diagnostics = diag.FromErr(errors.New("couldn't type assert role value"))
					return
				}
				// validate here because as of terraform 1.0.6 it cannot validate on Lists or Sets
				// https://github.com/hashicorp/terraform-plugin-sdk/issues/156
				if !onlyLettersAndNumbersRegex.MatchString(roleValue) {
					diagnostics = append(diagnostics, diag.Errorf("invalid value: %q in roles, can only be alphanumeric and have '-'s", roleValue)...)
				}
				rolesSlice = append(rolesSlice, roleValue)
			}
			// early return if there are any values in diagnostics. probably came from validating role values
			if len(diagnostics) != 0 {
				return
			}
			access.Roles = append(access.Roles, rolesSlice...)
			rules, ok := accessItemMap["rules"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert rules list value %+v", reflect.TypeOf(rules))
				return
			}
			for _, rulesItem := range rules {
				rulesItemMap, ok := rulesItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert rules item %+v", reflect.TypeOf(rulesItem))
					return
				}
				conditions, ok := rulesItemMap["conditions"].([]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert conditions %+v", reflect.TypeOf(rulesItemMap["conditions"]))
					return
				}
				for _, condition := range conditions {
					conditionItemMap, ok := condition.(map[string]interface{})
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert conditions %+v", reflect.TypeOf(condition))
						return
					}
					trustLevel, ok := conditionItemMap["trust_level"].(string)
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert trust_level %+v", reflect.TypeOf(conditionItemMap["trust_level"]))
						return
					}
					access.Rules.Conditions.TrustLevel = trustLevel
				}

				l7Access, ok := rulesItemMap["l7_access"].([]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert l7Access %+v", reflect.TypeOf(rulesItemMap["l7_access"]))
					return
				}
				for _, l7AccessItem := range l7Access {
					l7AccessToCreate := policy.L7Access{}
					l7AccessItemMap, ok := l7AccessItem.(map[string]interface{})
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert l7access item %+v", reflect.TypeOf(l7AccessItem))
						return
					}
					actionsSet, ok := l7AccessItemMap["actions"].((*schema.Set))
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert actions %+v", reflect.TypeOf(l7AccessItemMap["actions"]))
						return
					}
					actions := []string{}
					for _, action := range actionsSet.List() {
						actionValue, ok := action.(string)
						if !ok {
							diagnostics = diag.FromErr(errors.New("couldn't type assert action"))
							return
						}
						if actionValue != "create" && actionValue != "write" &&
							actionValue != "read" && actionValue != "update" &&
							actionValue != "delete" && actionValue != "*" {
							diagnostics = append(diagnostics, diag.Errorf("action must be one of the following %q, but instead had %s", []string{"create", "write", "read", "update", "delete", "*"}, actionValue)...)
						}
						actions = append(actions, actionValue)
					}
					// validate action value here because terraform cannot validate list or sets at the schema level
					if len(diagnostics) != 0 {
						return
					}
					l7AccessToCreate.Actions = actions

					resourcesSet, ok := l7AccessItemMap["resources"].(*schema.Set)
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert resources  %+v", reflect.TypeOf(l7AccessItemMap["resources"]))
						return
					}
					resources := []string{}
					for _, resource := range resourcesSet.List() {
						resourceValue, ok := resource.(string)
						if !ok {
							diagnostics = diag.FromErr(errors.New("couldn't type assert resource"))
							return
						}
						resources = append(resources, resourceValue)
					}
					l7AccessToCreate.Resources = resources

					access.Rules.L7Access = append(access.Rules.L7Access, l7AccessToCreate)
				}

			}
			policyToCreate.Spec.Access = append(policyToCreate.Spec.Access, access)
		}
	}

	log.Printf("[POLICY|RES|CREATE] to be created %#v\n", policyToCreate)
	createdPolicy, err := client.Policy.Create(policyToCreate)
	if err != nil {
		diag.FromErr(errors.WithMessage(err, "couldn't create new policy"))
		return
	}
	log.Printf("[POLICY|RES|CREATE] createdPolicy %#v\n", createdPolicy)
	d.SetId(createdPolicy.ID)
	diagnostics = resourcePolicyRead(ctx, d, m)
	return
}

func resourcePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICY|RES|UPDATE] updating policy")
	diagnostics = resourcePolicyCreate(ctx, d, m)
	log.Println("[POLICY|RES|UPDATE] updated policy")
	return
}

func resourcePolicyRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICY|RES|READ] reading policy")
	client := m.(*client.ClientHolder)
	id := d.Id()
	policy, ok, err := client.Policy.Get(id)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessagef(err, "couldn't get policy with id: %s", id))
		return
	}
	if !ok {
		diagnostics = diag.Errorf("couldn't find expected resource")
		return
	}
	log.Printf("[POLICY|RES|READ]: go policy: %#v", policy)
	d.Set("name", policy.Name)
	d.Set("description", policy.Description)
	metadatatags := map[string]interface{}{
		"template": policy.UnmarshalledPolicy.Metadata.Tags.Template,
	}
	d.Set("metadatatags", []interface{}{metadatatags})
	spec := flattenPolicySpec(policy.UnmarshalledPolicy.Spec)
	d.Set("spec", spec)
	d.SetId(policy.ID)
	log.Println("[POLICY|RES|READ] read policy")
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
	e["src_addr"] = toFlatten.SourceAddress

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
