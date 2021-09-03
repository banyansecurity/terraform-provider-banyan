package banyan

import (
	"context"
	"fmt"
	"log"
	"reflect"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/policy"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

func resourcePolicy() *schema.Resource {
	log.Println("getting resource")
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
																//TODO validate actions? ValidateFunc: validatePort(),
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
										Optional:     true,
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
		if v != "High" && v != "Low" && v != "" {
			errs = append(errs, fmt.Errorf("%q must be %q or \"\", got: %q", key, "High", v))
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
	log.Println("[POLICY|RES] creating resource")
	client := m.(*client.ClientHolder)
	name, ok := d.Get("name").(string)
	if !ok {
		err := errors.New("Couldn't type assert name")
		diagnostics = diag.FromErr(err)
		return
	}
	description, ok := d.Get("description").(string)
	if !ok {
		err := errors.New("Couldn't type assert description")
		diagnostics = diag.FromErr(err)
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
		err := errors.New("Couldn't type assert metadatags, type is " + fmt.Sprintf("%+v", metadatatags))
		diagnostics = diag.FromErr(err)
		return
	}
	for _, item := range metadatatags {
		ii, ok := item.(map[string]interface{})
		if !ok {
			err := errors.New("Couldn't type assert element in metadatatags")
			diagnostics = diag.FromErr(err)
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
			err := errors.New("Couldn't type assert element in metadatatags")
			diagnostics = diag.FromErr(err)
			return
		}

		exception, ok := ii["exception"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert certsettings")
			return
		}
		for _, exceptionItem := range exception {
			exceptionItemMap, ok := exceptionItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert certsettings map")
				return
			}
			srdAddrs, ok := exceptionItemMap["src_addr"].(*schema.Set)
			if !ok {
				diagnostics = diag.Errorf("couldn't type assert src_addr to type: %+v", reflect.TypeOf(exceptionItemMap["src_addr"]))
				return
			}
			for _, srcAddr := range srdAddrs.List() {
				srcAddrValue, ok := srcAddr.(string)
				if !ok {
					diagnostics = diag.FromErr(errors.New("couldn't type assert dnsNameValue"))
					return
				}
				policyToCreate.Spec.Exception.SourceAddress = append(policyToCreate.Spec.Exception.SourceAddress, srcAddrValue)
			}
		}
		options, ok := ii["options"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert backend")
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
					diagnostics = diag.FromErr(errors.New("couldn't type assert dnsNameValue"))
					return
				}
				rolesSlice = append(rolesSlice, roleValue)
			}
			access.Roles = append(access.Roles, rolesSlice...)
			rules, ok := accessItemMap["rules"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert rules value %+v", reflect.TypeOf(rules))
				return
			}
			for _, rulesItem := range rules {
				rulesItemMap, ok := rulesItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert rules value %+v", reflect.TypeOf(rulesItemMap))
					return
				}
				conditions, ok := rulesItemMap["conditions"].([]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert conditions %+v", reflect.TypeOf(conditions))
					return
				}
				for _, condition := range conditions {
					conditionItemMap, ok := condition.(map[string]interface{})
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert conditions %+v", reflect.TypeOf(conditionItemMap))
						return
					}
					trustLevel, ok := conditionItemMap["trust_level"].(string)
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert trust_level %+v", reflect.TypeOf(trustLevel))
						return
					}
					access.Rules.Conditions.TrustLevel = trustLevel
				}

				l7Access, ok := rulesItemMap["l7_access"].([]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert l7Access %+v", reflect.TypeOf(l7Access))
					return
				}
				for _, l7AccessItem := range l7Access {
					l7AccessToCreate := policy.L7Access{}
					l7AccessItemMap, ok := l7AccessItem.(map[string]interface{})
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert l7access item %+v", reflect.TypeOf(l7AccessItemMap))
						return
					}
					actionsSet, ok := l7AccessItemMap["actions"].((*schema.Set))
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert actions %+v", reflect.TypeOf(actionsSet))
						return
					}
					actions := []string{}
					for _, action := range actionsSet.List() {
						actionValue, ok := action.(string)
						if !ok {
							diagnostics = diag.FromErr(errors.New("couldn't type assert action"))
							return
						}
						actions = append(actions, actionValue)
					}
					l7AccessToCreate.Actions = actions

					resourcesSet, ok := l7AccessItemMap["resources"].((*schema.Set))
					if !ok {
						diagnostics = diag.Errorf("Couldn't type assert resources  %+v", reflect.TypeOf(resourcesSet))
						return
					}
					resources := []string{}
					for _, resource := range actionsSet.List() {
						resourceValue, ok := resource.(string)
						if !ok {
							diagnostics = diag.FromErr(errors.New("couldn't type assert action"))
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

	//fill in null values
	// policyToCreate.Spec.Access = []policy.Access{
	// 	{
	// 		Roles: []string{"ANY"},
	// 		Rules: policy.Rules{
	// 			Conditions: policy.Conditions{
	// 				TrustLevel: "High",
	// 			},
	// 			L7Access: []policy.L7Access{
	// 				{
	// 					Actions:   []string{"*"},
	// 					Resources: []string{"*"},
	// 				},
	// 			},
	// 		},
	// 	},
	// }

	log.Printf("[POLICY|RES] to be created %#v\n", policyToCreate)
	createdPolicy, err := client.Policy.Create(policyToCreate)
	if err != nil {
		diag.FromErr(errors.WithMessage(err, "couldn't create new policy"))
		return
	}
	log.Printf("[POLICY|RES|CREATE] createdPolicy %#v\n", createdPolicy)
	d.SetId(createdPolicy.ID)
	// make sure we don't overwrite the existing one
	return resourcePolicyRead(ctx, d, m)
}

func resourcePolicyUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[POLICY|RES|UPDATE] updating policy")
	return resourceServiceCreate(ctx, d, m)
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
	d.Set("metadatatags", metadatatags)
	spec := map[string]interface{}{
		"exception": map[string]interface{}{
			"src_addr": policy.UnmarshalledPolicy.Spec.Exception.SourceAddress,
		},
		"options": map[string]interface{}{
			"disable_tls_client_authentication": policy.UnmarshalledPolicy.Spec.Options.DisableTLSClientAuthentication,
			"l7_protocl":                        policy.UnmarshalledPolicy.Spec.Options.L7Protocol,
		},
	}
	d.Set("spec", spec)
	d.SetId(policy.ID)
	return
}

func resourcePolicyDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.ClientHolder)
	err := client.Policy.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	return
}
