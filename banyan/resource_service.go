package banyan

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceService() *schema.Resource {
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
		CreateContext: resourceServiceCreate,
		ReadContext:   resourceServiceRead,
		UpdateContext: resourceServiceUpdate,
		DeleteContext: resourceServiceDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the service",
				ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
			},
			"description": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Description of the service",
			},
			"cluster": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the NetAgent cluster which the service is accessible from",
				ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
			},
			"metadatatags": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "Metadata about the service",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"template": {
							Type:         schema.TypeString,
							Required:     true,
							ValidateFunc: validateTemplate(),
						},
						"user_facing": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"protocol": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"domain": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"port": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validatePort(),
						},
						"icon": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"service_app_type": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"enforcement_mode": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"ssh_service_type": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"write_ssh_config": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"banyan_proxy_mode": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"app_listen_port": {
							Type:         schema.TypeInt,
							Optional:     true,
							ValidateFunc: validatePort(),
						},
						"allow_user_override": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"ssh_chain_mode": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"ssh_host_directive": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"kube_cluster_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"kube_ca_key": {
							Type:      schema.TypeString,
							Optional:  true,
							Sensitive: true,
						},
						"description_link": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"include_domains": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"client_cidrs": {
				Type:     schema.TypeList,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"address": {
							Type:     schema.TypeList,
							Optional: true,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"cidr": {
										Type:         schema.TypeString,
										Optional:     true,
										ValidateFunc: validateCIDR(),
									},
									"ports": {
										Type: schema.TypeString,
										// TODO figure out if this is comma separated or ranges or both and add Description: "",
										// todo validate on above
										Optional: true,
									},
								},
							},
						},
						"clusters": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"host_tag_selector": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "host tag selectors",
							Elem: &schema.Schema{
								Type: schema.TypeMap,
								Elem: &schema.Schema{Type: schema.TypeString},
							},
						},
					},
				},
			},
			"backend": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "backend settings",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allow_patterns": {
							Type:     schema.TypeList,
							Optional: true,
							Description: `
					BackendAllowPatterns is an optional section defines the patterns for the backend workload
					instance. If BackendWhitelist/BackendAllowPatterns are both not populated, then all backend
					address/name/port are allowed. This field is effective only when BackendWhitelist is not populated.
					If the BackendAllowPatterns is not populated, then the backend must match at least one entry
					in this list to establish connection with the backend service.  This could be used
					for both httpConnect and non-httpConnect cases.  In non-httpConnect cases only backend
					hostnames are effective and other fields are ignored.`,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"hostnames": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
										Description: "Allowed hostnames my include a leading and/or trailing wildcard character \"*\" to match multiple hostnames",
									},
									"cidrs": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
										Description: "Host may be a CIDR such as 10.1.1.0/24",
									},
									"ports": {
										Type:        schema.TypeList,
										MaxItems:    1,
										Optional:    true,
										Description: `List of allowed ports and port ranges`,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"port_list": {
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type:         schema.TypeInt,
														ValidateFunc: validatePort(),
													},
													Description: "List of allowed ports",
												},
												"port_range": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: `List of allowed port ranges`,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"min": {
																Type:         schema.TypeInt,
																Optional:     true,
																Description:  "min value of port range",
																ValidateFunc: validatePort(),
															},
															"max": {
																Type:         schema.TypeInt,
																Optional:     true,
																Description:  "max value of port range",
																ValidateFunc: validatePort(),
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
						"dns_overrides": {
							Type:     schema.TypeMap,
							Optional: true,
							Description: `is an optional section that specifies name-to-address or name-to-name mappings.
										 Name-to-address mapping could be used instead of DNS lookup. Format is "FQDN: ip_address".
										 Name-to-name mapping could be used to override one FQDN with the other. Format is "FQDN1: FQDN2"
										 Example: name-to-address -> "internal.myservice.com" : "10.23.0.1"
										          name-to-name    ->    "exposed.service.com" : "internal.myservice.com"
										`,
							Elem: &schema.Schema{Type: schema.TypeString},
						},
						"connector_name": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"http_connect": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"target": {
							Type:        schema.TypeList,
							MinItems:    1,
							MaxItems:    1,
							Required:    true,
							Description: "target",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"client_certificate": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"name": {
										Type:     schema.TypeString,
										Required: true,
									},
									"port": {
										Type:         schema.TypeInt,
										Required:     true,
										ValidateFunc: validatePort(),
									},
									"tls": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"tls_insecure": {
										Type:     schema.TypeBool,
										Required: true,
									},
								},
							},
						},
						"whitelist": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "also called backend allowlist ",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"frontend_address": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "frontend_address",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cidr": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validateCIDR(),
						},
						"port": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validatePort(),
						},
					},
				},
			},
			"host_tag_selector": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: `host tag selectors`,
				Elem: &schema.Schema{
					Type: schema.TypeMap,
					Elem: &schema.Schema{Type: schema.TypeString},
				},
			},
			"tls_sni": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"http_settings": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Optional:    true,
				Description: "http health check",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"oidc_settings": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Computed:    true,
							Description: "oidc settings",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"service_domain_name": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"post_auth_redirect_path": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"api_path": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"suppress_device_trust_verification": {
										Type:     schema.TypeBool,
										Optional: true,
									},
									"trust_callbacks": {
										Type:     schema.TypeMap,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"http_health_check": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Description: "http health check",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"addresses": {
										Type:     schema.TypeSet,
										Required: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"method": {
										Type:     schema.TypeString,
										Required: true,
										// TODO: validate permissible http methods ValidateFunc: validateHttpMethods(),
									},
									"path": {
										Type:     schema.TypeString,
										Required: true,
									},
									"user_agent": {
										Type:     schema.TypeString,
										Required: true,
									},
									"from_address": {
										Type:     schema.TypeSet,
										Required: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"https": {
										Type:     schema.TypeBool,
										Required: true,
									},
								},
							},
						},
						"exempted_paths": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Computed:    true,
							Description: "generally used for usecases as CORS/Source IP exception",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"patterns": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"template": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"source_cidrs": {
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"hosts": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"origin_header": {
																Type:     schema.TypeSet,
																Optional: true,
																Elem: &schema.Schema{
																	Type: schema.TypeString,
																},
															},
															"target": {
																Type:     schema.TypeSet,
																Optional: true,
																Elem: &schema.Schema{
																	Type: schema.TypeString,
																},
															},
														},
													},
												},
												"methods": {
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"paths": {
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"mandatory_headers": {
													Type:     schema.TypeSet,
													Optional: true,
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
						"headers": {
							Type:     schema.TypeMap,
							Optional: true,
							Description: `
								Headers is a list of HTTP headers to add to every request sent to the Backend;
								the key of the map is the header name, and the value is the header value you want.
								The header value may be constructed using Go template syntax, such as
								referencing values in Banyan's JWT TrustToken.
								`,
							Elem: &schema.Schema{Type: schema.TypeString},
						},
						"token_loc": {
							Type:        schema.TypeList,
							Optional:    true,
							MaxItems:    1,
							Description: "Token location",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"query_param": {
										Type:     schema.TypeString,
										Required: true,
									},
									"authorization_header": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"custom_header": {
										Type:     schema.TypeString,
										Required: true,
									},
								},
							},
						},
					},
				},
			},
			"cert_settings": {
				Type:        schema.TypeList,
				MaxItems:    1,
				MinItems:    1,
				Optional:    true,
				Description: "cert settings used for x",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"letsencrypt": {
							Type:     schema.TypeBool,
							Optional: true,
						},
						"dns_names": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"custom_tls_cert": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Computed:    true,
							Description: "cert settings used for x",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"cert_file": {
										Type:      schema.TypeString,
										Sensitive: true,
										Required:  true,
									},
									"key_file": {
										Type:      schema.TypeString,
										Required:  true,
										Sensitive: true,
									},
								},
							},
						},
					},
				},
			},
			"tag_slice": {
				Type:        schema.TypeList,
				Optional:    true,
				MinItems:    1,
				Description: "TagSlice to hold all the tags for Registered Service",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"org_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"service_id": {
							Type:     schema.TypeString,
							Required: true,
						},
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"value": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
		},
	}
}

func resourceServiceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)

	svc := service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandMetatdataTags(d.Get("metadatatags").([]interface{})),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandServiceSpec(d),
	}

	newService, err := client.Service.Create(svc)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessagef(err, "could not create service %s : %s", d.Get("name"), d.Id()))
		return
	}
	log.Printf("[SVC|RES|CREATE] Created service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return
}

func resourceServiceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating service %s : %s", d.Get("name"), d.Id())
	resourceServiceCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] Reading service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessagef(err, "couldn't get service with id: %s", id))
		return
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	log.Printf("#### readService: %#v", service)
	err = d.Set("name", service.ServiceName)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("description", service.Description)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("cluster", service.ClusterName)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	port, err := typeSwitchPortPtr(service.CreateServiceSpec.Metadata.Tags.Port)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	appListenPort, err := typeSwitchPortPtr(service.CreateServiceSpec.Metadata.Tags.AppListenPort)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	metadataTagUserFacing, err := strconv.ParseBool(*service.CreateServiceSpec.Metadata.Tags.UserFacing)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	metadatatags := map[string]interface{}{
		"template":            service.CreateServiceSpec.Metadata.Tags.Template,
		"user_facing":         metadataTagUserFacing,
		"protocol":            service.CreateServiceSpec.Metadata.Tags.Protocol,
		"domain":              service.CreateServiceSpec.Metadata.Tags.Domain,
		"port":                port,
		"icon":                service.CreateServiceSpec.Metadata.Tags.Icon,
		"service_app_type":    service.CreateServiceSpec.Metadata.Tags.ServiceAppType,
		"enforcement_mode":    service.CreateServiceSpec.Metadata.Tags.EnforcementMode,
		"ssh_service_type":    service.CreateServiceSpec.Metadata.Tags.SSHServiceType,
		"write_ssh_config":    service.CreateServiceSpec.Metadata.Tags.WriteSSHConfig,
		"banyan_proxy_mode":   service.CreateServiceSpec.Metadata.Tags.BanyanProxyMode,
		"app_listen_port":     appListenPort,
		"allow_user_override": service.CreateServiceSpec.Metadata.Tags.AllowUserOverride,
		"ssh_chain_mode":      service.CreateServiceSpec.Metadata.Tags.SSHChainMode,
		"ssh_host_directive":  service.CreateServiceSpec.Metadata.Tags.SSHHostDirective,
		"kube_cluster_name":   service.CreateServiceSpec.Metadata.Tags.KubeClusterName,
		"kube_ca_key":         service.CreateServiceSpec.Metadata.Tags.KubeCaKey,
		"description_link":    service.CreateServiceSpec.Metadata.Tags.DescriptionLink,
		"include_domains":     service.CreateServiceSpec.Metadata.Tags.IncludeDomains,
	}
	err = d.Set("metadatatags", []interface{}{metadatatags})
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_cidrs", flattenServiceClientCIDRs(service.CreateServiceSpec.Spec.ClientCIDRs))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("frontend_address", flattenServiceFrontendAddresses(service.CreateServiceSpec.Spec.Attributes.FrontendAddresses))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("host_tag_selector", service.CreateServiceSpec.Spec.Attributes.HostTagSelector)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("tls_sni", service.CreateServiceSpec.Spec.Attributes.TLSSNI)
	if err != nil {
		return diag.FromErr(err)
	}
	backend, diagnostics := flattenServiceBackend(service.CreateServiceSpec.Spec.Backend)
	if diagnostics.HasError() {
		return
	}
	err = d.Set("backend", backend)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("http_settings", flattenServiceHTTPSettings(service.CreateServiceSpec.Spec.HTTPSettings))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("cert_settings", flattenServiceCertSettings(service.CreateServiceSpec.Spec.CertSettings))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("tag_slice", flattenServiceTagSlice(service.CreateServiceSpec.Spec.TagSlice))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return
}

func resourceServiceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting service with id: %q \n", d.Id())
	client := m.(*client.ClientHolder)
	err := client.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	log.Printf("[SERVICE|RES|DELETE] deleted service with id: %q \n", d.Id())
	return
}
