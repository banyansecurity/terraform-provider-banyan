package banyan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"reflect"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

func validatePort() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(int)
		if v < 0 || v > math.MaxUint16 {
			errs = append(errs, fmt.Errorf("%q must be in range 0-%d, got: %d ", key, math.MaxUint16, v))
		}
		return
	}
}

func validateCIDR() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		_, _, err := net.ParseCIDR(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%q must be a CIDR, got: %q", key, v))
		}
		return
	}
}

func validateTemplate() func(val interface{}, key string) (warns []string, errs []error) {
	return func(val interface{}, key string) (warns []string, errs []error) {
		v := val.(string)
		if v != "WEB_USER" && v != "" {
			errs = append(errs, fmt.Errorf("%q must be %q or \"\", got: %q", key, "WEB_USER", v))
		}
		return
	}
}

func resourceService() *schema.Resource {
	log.Println("getting resource")
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
							Optional:     true,
							ValidateFunc: validateTemplate(),
						},
						"user_facing": {
							Type:     schema.TypeBool,
							Required: true,
						},
						"protocol": {
							Type:     schema.TypeString,
							Required: true,
						},
						"description_link": {
							Type:     schema.TypeString,
							Optional: true,
						},
						"domain": {
							Type:     schema.TypeString,
							Required: true,
						},
						"port": {
							Type:         schema.TypeInt,
							Required:     true,
							ValidateFunc: validatePort(),
						},
						"service_app_type": {
							Type:     schema.TypeString,
							Required: true,
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
						"include_domains": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"spec": {
				Type:        schema.TypeList,
				MinItems:    1,
				MaxItems:    1,
				Required:    true,
				Description: "The spec for the service",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
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
									"host_tag_selectors": {
										Type:     schema.TypeList,
										Optional: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"host_tag_selector": {
													Type:     schema.TypeMap,
													Optional: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
											},
										},
									},
								},
							},
						},
						"attributes": {
							Type:        schema.TypeList,
							MinItems:    1,
							MaxItems:    1,
							Required:    true,
							Description: "attributes",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"frontend_address": {
										Type:        schema.TypeList,
										MinItems:    1,
										Required:    true,
										Description: "frontend address",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"cidr": {
													Type:         schema.TypeString,
													Required:     true,
													ValidateFunc: validateCIDR(),
												},
												"port": {
													Type:         schema.TypeInt,
													Required:     true,
													ValidateFunc: validatePort(),
												},
											},
										},
									},
									"host_tag_selector": {
										Type:        schema.TypeList,
										MinItems:    1,
										Required:    true,
										Description: "host_tag_selector",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"site_name": {
													Type:     schema.TypeString,
													Required: true,
												},
											},
										},
									},
									"tls_sni": {
										Type: schema.TypeSet,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
										Optional: true,
									},
								},
							},
						},
						"backend": {
							Type:        schema.TypeList,
							MinItems:    1,
							MaxItems:    1,
							Required:    true,
							Description: "backend",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"target": {
										Type:        schema.TypeList,
										MinItems:    1,
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
									"backend_allowlist": {
										Type:        schema.TypeSet,
										Optional:    true,
										Description: "also called backend whitelist ",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"http_connect": {
										Type:     schema.TypeBool,
										Optional: true,
									},
									"connector_name": {
										Type:     schema.TypeString,
										Optional: true,
									},
									"backend_allow_pattern": {
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
																	Type: schema.TypeInt,
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
																			Type:        schema.TypeInt,
																			Optional:    true,
																			Description: "min value of port range",
																		},
																		"max": {
																			Type:        schema.TypeInt,
																			Optional:    true,
																			Description: "max value of port range",
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
							},
						},
						"http_settings": {
							Type:        schema.TypeList,
							MaxItems:    1,
							MinItems:    1,
							Required:    true,
							Description: "HTTP settings used for x",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:     schema.TypeBool,
										Required: true,
									},
									"exempted_paths": {
										Type:        schema.TypeList,
										MaxItems:    1,
										Optional:    true,
										Description: "generally used for usecases as CORS/Source IP exception",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"enabled": {
													Type:     schema.TypeBool,
													Required: true,
												},
												"paths": {
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"pattern": {
													Type:     schema.TypeList,
													Optional: true,
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
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
											The header value may be constructed using Go template syntax, such as {{.Email}}
											referencing values in Banyan's JWT TrustToken.
											`,
										Elem: &schema.Schema{Type: schema.TypeString},
									},
									"http_redirect": {
										Type:        schema.TypeList,
										MaxItems:    1,
										Optional:    true,
										Description: "http_redirect",
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"enabled": {
													Type:     schema.TypeBool,
													Required: true,
												},
												"addresses": {
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"from_address": { // todo figure out if this should be from_addresses?
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"url": {
													Type:     schema.TypeString,
													Optional: true,
													// TODO validate this is an acceptable url not something that is junk ValidateFunc: validateURLIsOk(),
												},
												"status_code": {
													Type:     schema.TypeInt,
													Optional: true,
													// TODO implement this but instead of being an error have it be a warn because not everyone is going to use valid status codes ValidateFunc: validateAcceptableStatusCode,
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
													Optional: true,
												},
												"addresses": {
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"method": {
													Type:     schema.TypeString,
													Optional: true,
													// TODO: validate permissible http methods ValidateFunc: validateHttpMethods(),
												},
												"path": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"user_agent": {
													Type:     schema.TypeString,
													Optional: true,
												},
												"from_address": { // todo figure out if this should be from_addresses?
													Type:     schema.TypeSet,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"https": { //todo naming needs to be better is_https ?
													Type:     schema.TypeBool,
													Optional: true,
												},
											},
										},
									},
									"oidc_settings": {
										Type:        schema.TypeList,
										MaxItems:    1,
										Optional:    true,
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
					},
				},
			},
		},
	}
}

func resourceServiceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("[SVC|RES|CREATE] creating resource")
	client := m.(*client.ClientHolder)
	log.Printf("#### %#v\n", d)
	name, ok := d.Get("name").(string)
	if !ok {
		err := errors.New("Couldn't type assert name")
		diagnostics = diag.FromErr(err)
		return
	}
	description, ok := d.Get("description").(string)
	if !ok {
		err := errors.New("Couldn't type assert protocol")
		diagnostics = diag.FromErr(err)
		return
	}
	cluster, ok := d.Get("cluster").(string)
	if !ok {
		err := errors.New("Couldn't type assert cluster")
		diagnostics = diag.FromErr(err)
		return
	}
	svc := service.CreateService{
		Metadata: service.Metadata{
			Name:        name,
			Description: description,
			Cluster:     cluster,
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
	}
	// pre fill in null values
	svc.Spec.Backend.AllowPatterns = []service.BackendAllowPattern{}
	svc.Spec.Backend.DNSOverrides = map[string]string{}
	svc.Spec.Backend.Whitelist = []string{}
	svc.Spec.ClientCIDRs = []service.ClientCIDRs{}
	svc.Spec.HTTPSettings.ExemptedPaths.Paths = []string{}
	svc.Spec.HTTPSettings.ExemptedPaths.Patterns = []service.Pattern{}
	svc.Spec.HTTPSettings.Headers = map[string]string{}
	svc.Spec.HTTPSettings.HTTPHealthCheck = service.HTTPHealthCheck{}

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

		domain, ok := ii["domain"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert issuerUrl"))
			return
		}
		svc.Metadata.Tags.Domain = domain
		port, ok := ii["port"].(int)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert port"))
			return
		}
		portTag := strconv.Itoa(port)
		svc.Metadata.Tags.Port = portTag
		protocol, ok := ii["protocol"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert protocol"))
			return
		}
		svc.Metadata.Tags.Protocol = protocol
		serviceAppType, ok := ii["service_app_type"].(string)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert service_app_type"))
			return
		}
		svc.Metadata.Tags.ServiceAppType = serviceAppType
		userFacingMetadataTag, ok := ii["user_facing"].(bool)
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert user_facing"))
			return
		}
		userFacing := strconv.FormatBool(userFacingMetadataTag)
		svc.Metadata.Tags.UserFacing = userFacing
		template, ok := ii["template"].(string)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert template")
			return
		}
		svc.Metadata.Tags.Template = template
		enforcementMode, ok := ii["enforcement_mode"].(string)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type enforcement_mode")
			return
		}
		svc.Metadata.Tags.EnforcementMode = enforcementMode
		sshServiceType, ok := ii["ssh_service_type"].(string)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type ssh_service_type")
			return
		}
		svc.Metadata.Tags.SSHServiceType = sshServiceType
		writeSSHConfig, ok := ii["write_ssh_config"].(bool)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type write_ssh_config")
			return
		}
		svc.Metadata.Tags.WriteSSHConfig = writeSSHConfig
		appListenPort, ok := ii["app_listen_port"].(int)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert app_listen_port")
			return
		}
		appListenPortString := strconv.Itoa(appListenPort)
		svc.Metadata.Tags.AppListenPort = appListenPortString
		allowUserOverride, ok := ii["allow_user_override"].(bool)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type enforcement_mode")
			return
		}
		svc.Metadata.Tags.AllowUserOverride = allowUserOverride
		sshChainMode, ok := ii["ssh_chain_mode"].(bool)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type ssh_chain_mode")
			return
		}
		svc.Metadata.Tags.SSHChainMode = sshChainMode
		banyanProxyMode, ok := ii["banyan_proxy_mode"].(string)
		if !ok {
			diagnostics = diag.Errorf("Couldn't type banyan_proxy_mode")
			return
		}
		svc.Metadata.Tags.BanyanProxyMode = banyanProxyMode
	}

	svc.Spec.Attributes.TLSSNI = append(svc.Spec.Attributes.TLSSNI, "sni")

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
		clientCIDRS, ok := ii["client_cidrs"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("couldn't type assert client_cidrs with type: %v", reflect.TypeOf(ii["client_cidrs"]))
			return
		}
		for _, clientCIDRItem := range clientCIDRS {
			clientCIDRs := service.ClientCIDRs{}
			clientCIDRItemMap, ok := clientCIDRItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert element in clientCIDRItem: %v", reflect.TypeOf(clientCIDRItem))
				return
			}
			clustersSet, ok := clientCIDRItemMap["clusters"].(*schema.Set)
			if !ok {
				diagnostics = diag.Errorf("couldn't type assert spec.client_cidrs.clusters, has type of: %v", reflect.TypeOf(clientCIDRItemMap["clusters"]))
				return
			}
			for _, clusterItem := range clustersSet.List() {
				cluster, ok := clusterItem.(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.client_cidrs.clusters.cluster, actually has type of: %v", reflect.TypeOf(clusterItem))
					return
				}
				clientCIDRs.Clusters = append(clientCIDRs.Clusters, cluster)
			}
			hostTagSelectors, ok := clientCIDRItemMap["host_tag_selectors"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert host_tag_selectors")
				return
			}
			for _, hostTagSelectorItem := range hostTagSelectors {
				hostTagSelectorItemMap, ok := hostTagSelectorItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert host tag selector item map, actually has type of: %v", reflect.TypeOf(hostTagSelectorItem))
					return
				}

				hostTagSelectors, err := convertEmptyInterfaceToStringMap(hostTagSelectorItemMap["host_tag_selector"])
				if err != nil {
					diagnostics = diag.Errorf("found an error: %s Couldn't type assert host_tag_selector, got %v instead", err.Error(), reflect.TypeOf(clientCIDRItemMap["host_tag_selector"]))
					return
				}
				clientCIDRs.HostTagSelector = append(clientCIDRs.HostTagSelector, hostTagSelectors)
			}
			addresses, ok := clientCIDRItemMap["address"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert address")
				return
			}
			for _, address := range addresses {
				newAddress := service.CIDRAddress{}
				addressMap, ok := address.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert element in addressMap: %v", reflect.TypeOf(address))
					return
				}
				cidr, ok := addressMap["cidr"].(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic("cidr", addressMap["cidr"])
					return
				}
				newAddress.CIDR = cidr
				ports, ok := addressMap["ports"].(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic("cidr", addressMap["cidr"])
					return
				}
				newAddress.Ports = ports

				clientCIDRs.Addresses = append(clientCIDRs.Addresses, newAddress)
			}

			svc.Spec.ClientCIDRs = append(svc.Spec.ClientCIDRs, clientCIDRs)
		}

		attributes, ok := ii["attributes"].([]interface{})
		if !ok {
			diagnostics = diag.FromErr(errors.New("couldn't type assert attributes"))
			return
		}
		for _, attributeItem := range attributes {
			jj, ok := attributeItem.(map[string]interface{})
			if !ok {
				err := errors.New("Couldn't type assert element in attributeItems")
				diagnostics = diag.FromErr(err)
				return
			}

			tlsSNISet, ok := jj["tls_sni"].(*schema.Set)
			if !ok {
				tlsSNIMAPTYPE := reflect.TypeOf(jj["tls_sni"])
				diagnostics = diag.FromErr(errors.New("couldn't type assert tls_sni_set" + fmt.Sprintf("%+v", tlsSNIMAPTYPE)))
				return
			}
			for _, tlsSNIItem := range tlsSNISet.List() {
				tlsSNIValue, ok := tlsSNIItem.(string)
				if !ok {
					diag.FromErr(errors.New("couldn't type assert tls_sni_value"))
					return
				}
				svc.Spec.Attributes.TLSSNI = append(svc.Spec.Attributes.TLSSNI, tlsSNIValue)
			}

			frontEndAddress, ok := jj["frontend_address"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert frontend_address")
				return
			}
			for _, frontEndAddressItem := range frontEndAddress {
				frontEndAddressItemMap, ok := frontEndAddressItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert frontend_address item value %+v", reflect.TypeOf(frontEndAddressItem))
					return
				}
				cidr, ok := frontEndAddressItemMap["cidr"].(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert frontend_address cidr value")
					return
				}
				port, ok := frontEndAddressItemMap["port"].(int)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert frontend_address port value")
					return
				}
				svc.Spec.Attributes.FrontendAddresses = append(svc.Spec.Attributes.FrontendAddresses, service.FrontendAddress{
					CIDR: cidr,
					Port: strconv.Itoa(port),
				})

			}
			hostTagSelector, ok := jj["host_tag_selector"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert host_tag_selector")
				return
			}
			for _, hosthostTagSelectorItem := range hostTagSelector {
				hostTagSelectorMap, ok := hosthostTagSelectorItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert host tag selector item value %+v", reflect.TypeOf(hostTagSelectorMap))
					return
				}
				siteName, ok := hostTagSelectorMap["site_name"].(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert hosttag selecyot site name value.")

				}
				svc.Spec.Attributes.HostTagSelector = append(svc.Spec.Attributes.HostTagSelector, service.HostTag{
					ComBanyanopsHosttagSiteName: siteName,
				})
			}

		}
		backend, ok := ii["backend"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert backend")
			return
		}
		for _, backendItem := range backend {
			backendItemMap, ok := backendItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't Type assert backend item")
				return
			}
			dnsOverrides, err := convertEmptyInterfaceToStringMap(backendItemMap["dns_overrides"])
			if err != nil {
				diagnostics = diag.Errorf("found an error: %s Couldn't type assert host_tag_selector, got %v instead", err.Error(), reflect.TypeOf(backendItemMap["dns_overrides"]))
				return
			}
			svc.Spec.Backend.DNSOverrides = dnsOverrides

			backendAllowlist, ok := backendItemMap["backend_allowlist"].(*schema.Set)
			if !ok {
				diagnostics = createTypeAssertDiagnostic("backend_allowlist", backendItemMap["backend_allowlist"])
				return
			}
			for _, backendAllowlistItem := range backendAllowlist.List() {
				backendAllowlistItemString, ok := backendAllowlistItem.(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic("backend_allowlist item", backendAllowlistItem)
					return
				}
				svc.Spec.Backend.Whitelist = append(svc.Spec.Backend.Whitelist, backendAllowlistItemString)
			}
			httpConnect, ok := backendItemMap["http_connect"].(bool)
			if !ok {
				diagnostics = createTypeAssertDiagnostic("http_connect", backendItemMap["http_connect"])
				return
			}
			svc.Spec.Backend.HTTPConnect = httpConnect

			connectorName, ok := backendItemMap["connector_name"].(string)
			if !ok {
				diagnostics = createTypeAssertDiagnostic("connector_name", backendItemMap["connector_name"])
				return
			}
			svc.Spec.Backend.ConnectorName = connectorName

			backendAllowPattern, ok := backendItemMap["backend_allow_pattern"].([]interface{})
			if !ok {
				diagnostics = createTypeAssertDiagnostic("backend_allow_pattern", backendItemMap["backend_allow_pattern"])
				return
			}
			for _, backendAllowPatternItem := range backendAllowPattern {
				newBackendAllowPattern := service.BackendAllowPattern{}
				backendAllowPatternMap, ok := backendAllowPatternItem.(map[string]interface{})
				if !ok {
					diagnostics = createTypeAssertDiagnostic("backend_allow_pattern.Map", backendAllowPatternItem)
					return
				}
				hostnames, ok := backendAllowPatternMap["hostnames"].(*schema.Set)
				if !ok {
					diagnostics = createTypeAssertDiagnostic("hostnames", backendAllowPatternMap["hostnames"])
					return
				}
				for _, hostname := range hostnames.List() {
					hostnameString, ok := hostname.(string)
					if !ok {
						diagnostics = createTypeAssertDiagnostic("hostname", hostname)
						return
					}
					newBackendAllowPattern.Hostnames = append(newBackendAllowPattern.Hostnames, hostnameString)
				}
				cidrs, ok := backendAllowPatternMap["cidrs"].(*schema.Set)
				if !ok {
					diagnostics = createTypeAssertDiagnostic("cidrs", backendAllowPatternMap["cidrs"])
					return
				}
				for _, cidr := range cidrs.List() {
					cidrString, ok := cidr.(string)
					if !ok {
						diagnostics = createTypeAssertDiagnostic("cidr", cidr)
						return
					}
					newBackendAllowPattern.CIDRs = append(newBackendAllowPattern.CIDRs, cidrString)
				}

				ports, ok := backendAllowPatternMap["ports"].([]interface{})
				if !ok {
					diagnostics = createTypeAssertDiagnostic("ports", backendAllowPatternMap["ports"])
					return
				}
				for _, portItem := range ports {
					portItemMap, ok := portItem.(map[string]interface{})
					if !ok {
						diagnostics = createTypeAssertDiagnostic("port item", portItem)
						return
					}
					portList, ok := portItemMap["port_list"].(*schema.Set)
					if !ok {
						diagnostics = createTypeAssertDiagnostic("port_list", portItemMap["port_list"])
						return
					}
					for _, port := range portList.List() {
						portInt, ok := port.(int)
						if !ok {
							diagnostics = createTypeAssertDiagnostic("port in port_list", port)
							return
						}
						newBackendAllowPattern.Ports.PortList = append(newBackendAllowPattern.Ports.PortList, portInt)
					}

					portRange, ok := portItemMap["port_range"].([]interface{})
					if !ok {
						diagnostics = createTypeAssertDiagnostic("port_range", portItemMap["port_range"])
						return
					}
					for _, portRangeItem := range portRange {
						newPortRange := service.PortRange{}
						portRangeItemMap, ok := portRangeItem.(map[string]interface{})
						if !ok {
							diagnostics = createTypeAssertDiagnostic("port item", portItem)
							return
						}
						min, ok := portRangeItemMap["min"].(int)
						if !ok {
							diagnostics = createTypeAssertDiagnostic("min", portRangeItemMap["min"])
							return
						}
						newPortRange.Min = min
						max, ok := portRangeItemMap["max"].(int)
						if !ok {
							diagnostics = createTypeAssertDiagnostic("max", portRangeItemMap["max"])
							return
						}
						newPortRange.Max = max
						newBackendAllowPattern.Ports.PortRanges = append(newBackendAllowPattern.Ports.PortRanges, newPortRange)
					}
				}
				svc.Spec.Backend.AllowPatterns = append(svc.Spec.Backend.AllowPatterns, newBackendAllowPattern)
			}

			target, ok := backendItemMap["target"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert target")
				return
			}
			for _, targetItem := range target {
				targetItemMap, ok := targetItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert target item map")
					return
				}
				clientCertificate, ok := targetItemMap["client_certificate"].(bool)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.client_certificate")
					return
				}
				svc.Spec.Backend.Target.ClientCertificate = clientCertificate

				tls, ok := targetItemMap["tls"].(bool)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.tls")
					return
				}
				svc.Spec.Backend.Target.TLS = tls

				TLSInsecure, ok := targetItemMap["tls_insecure"].(bool)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.tls_insecure")
					return
				}
				svc.Spec.Backend.Target.TLSInsecure = TLSInsecure

				svc.Spec.Backend.Target.Name, ok = targetItemMap["name"].(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.name")
					return
				}

				targetPortInt, ok := targetItemMap["port"].(int)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert spec.backend.target.port")
					return
				}
				svc.Spec.Backend.Target.Port = strconv.Itoa(targetPortInt)
			}
		}
		certSettings, ok := ii["cert_settings"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert certsettings")
			return
		}
		for _, certSettingsItem := range certSettings {
			certSettingsMap, ok := certSettingsItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert certsettings map")
				return
			}
			letsencrypt, ok := certSettingsMap["letsencrypt"].(bool)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert letscencrypt")
				return
			}
			svc.Spec.CertSettings.LetsEncrypt = letsencrypt

			dnsNames, ok := certSettingsMap["dns_names"].(*schema.Set)
			if !ok {
				diagnostics = diag.Errorf("couldn't type assert dns_names to type: %+v", reflect.TypeOf(certSettingsMap["dns_names"]))
				return
			}
			for _, dnsName := range dnsNames.List() {
				dnsNameValue, ok := dnsName.(string)
				if !ok {
					diagnostics = diag.FromErr(errors.New("couldn't type assert dnsNameValue"))
					return
				}
				svc.Spec.CertSettings.DNSNames = append(svc.Spec.CertSettings.DNSNames, dnsNameValue)
			}

			customTlsCert, ok := certSettingsMap["custom_tls_cert"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert custom_tls_cert")
				return
			}
			for _, customTlsCertItem := range customTlsCert {
				customTlsCertItemMap, ok := customTlsCertItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert customTlsCertItemMap")
					return
				}
				enabled, ok := customTlsCertItemMap["enabled"].(bool)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert custom_tls_cert.enabled")
					return
				}
				svc.Spec.CertSettings.CustomTLSCert.Enabled = enabled

				certFile, ok := customTlsCertItemMap["cert_file"].(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert custom_tls_cert.cert_file")
					return
				}
				svc.Spec.CertSettings.CustomTLSCert.CertFile = certFile
				keyFile, ok := customTlsCertItemMap["key_file"].(string)
				if !ok {
					diagnostics = diag.Errorf("Couldn't type assert custom_tls_cert.keyFile")
					return
				}
				svc.Spec.CertSettings.CustomTLSCert.KeyFile = keyFile

			}

		}
		httpSettings, ok := ii["http_settings"].([]interface{})
		if !ok {
			diagnostics = diag.Errorf("Couldn't type assert backend")
			return
		}
		for _, httpSettingsItem := range httpSettings {
			httpSettingsMap, ok := httpSettingsItem.(map[string]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert certsettings map")
				return
			}
			enabled, ok := httpSettingsMap["enabled"].(bool)
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert httpsetting enabled")
				return
			}
			svc.Spec.HTTPSettings.Enabled = enabled

			oidcSettingsList, ok := httpSettingsMap["oidc_settings"].([]interface{})
			if !ok {
				diagnostics = diag.Errorf("Couldn't type assert oidc_settings")
				return
			}
			for oidcSettingsIdx, oidcSettings := range oidcSettingsList {
				oidcSettingsMap, ok := oidcSettings.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("couldn't type assert oidcSettings value")
					return
				}
				enabled, ok := oidcSettingsMap["enabled"].(bool)
				if !ok {
					diagnostics = diag.Errorf("couldn't type assert spec.http_settings.oidc_settings.enabled")
					return
				}
				svc.Spec.HTTPSettings.OIDCSettings.Enabled = enabled

				serviceDomainName, ok := oidcSettingsMap["service_domain_name"].(string)
				if !ok {
					diagnostics = diag.Errorf("couldn't type assert spec.http_settings.oidc_settings.enabled")
					return
				}
				svc.Spec.HTTPSettings.OIDCSettings.ServiceDomainName = serviceDomainName

				postAuthRedirectPath, ok := oidcSettingsMap["post_auth_redirect_path"].(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.oidc_setting[%d].post_auth_redirect_path", oidcSettingsIdx), oidcSettingsMap["post_auth_redirect_path"])
					return
				}
				svc.Spec.HTTPSettings.OIDCSettings.PostAuthRedirectPath = postAuthRedirectPath

				apiPath, ok := oidcSettingsMap["api_path"].(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.oidc_setting[%d].api_path", oidcSettingsIdx), oidcSettingsMap["api_path"])
					return
				}
				svc.Spec.HTTPSettings.OIDCSettings.APIPath = apiPath

				suppressDeviceTrustVerification, ok := oidcSettingsMap["suppress_device_trust_verification"].(bool)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.oidc_setting[%d].suppress_device_trust_verification", oidcSettingsIdx), oidcSettingsMap["suppress_device_trust_verification"])
					return
				}
				svc.Spec.HTTPSettings.OIDCSettings.SuppressDeviceTrustVerification = suppressDeviceTrustVerification

				trustCallbacks, err := convertEmptyInterfaceToStringMap(oidcSettingsMap["trust_callbacks"])
				if err != nil {
					diagnostics = diag.Errorf("found an error: %s Couldn't type assert http_settings.oidc_settings[%d].trust_callbacks, got %v instead", err.Error(), oidcSettingsIdx, reflect.TypeOf(httpSettingsMap["headers"]))
					return
				}
				svc.Spec.HTTPSettings.OIDCSettings.TrustCallBacks = trustCallbacks
			}

			exemptedPaths, ok := httpSettingsMap["exempted_paths"].([]interface{})
			if !ok {
				diagnostics = createTypeAssertDiagnostic("exempted_Paths", httpSettingsMap["exempted_paths"])
				return
			}
			for _, exemptedPathItem := range exemptedPaths {
				exemptedPathMap, ok := exemptedPathItem.(map[string]interface{})
				if !ok {
					diagnostics = diag.Errorf("couldn't type assert exemptedPathMap value")
					return
				}
				enabled, ok := exemptedPathMap["enabled"].(bool)
				if !ok {
					diagnostics = createTypeAssertDiagnostic("exempted_paths.enabled", exemptedPathMap["enabled"])
					return
				}
				svc.Spec.HTTPSettings.ExemptedPaths.Enabled = enabled

				paths, ok := exemptedPathMap["paths"].(*schema.Set)
				if !ok {
					diagnostics = createTypeAssertDiagnostic("exempted_paths.paths", exemptedPathMap["paths"])
					return
				}
				for idx, path := range paths.List() {
					pathString, ok := path.(string)
					if !ok {
						diagnostics = createTypeAssertDiagnostic("exempted_paths.path["+strconv.Itoa(idx)+"]", path)
						return
					}
					svc.Spec.HTTPSettings.ExemptedPaths.Paths = append(svc.Spec.HTTPSettings.ExemptedPaths.Paths, pathString)
				}

				patterns, ok := exemptedPathMap["pattern"].([]interface{})
				if !ok {
					diagnostics = createTypeAssertDiagnostic("exempted_paths.pattern", exemptedPathMap["pattern"])
					return
				}
				for pattern_idx, patternItem := range patterns {
					newPattern := service.Pattern{}
					patternItemMap, ok := patternItem.(map[string]interface{})
					if !ok {
						diagnostics = diag.Errorf("couldn't type assert oidcSettings value")
						return
					}

					sourceCidrs, newDiagnostics := getStringSliceFromSet(patternItemMap["source_cidrs"], fmt.Sprintf("exempted_paths.patterns[%d].source_cidrs", pattern_idx))
					diagnostics = append(diagnostics, newDiagnostics...)
					if len(diagnostics) != 0 {
						return
					}
					newPattern.SourceCIDRs = append(newPattern.SourceCIDRs, sourceCidrs...)

					methods, newDiagnostics := getStringSliceFromSet(patternItemMap["methods"], fmt.Sprintf("exempted_paths.patterns[%d].methods", pattern_idx))
					diagnostics = append(diagnostics, newDiagnostics...)
					if len(diagnostics) != 0 {
						return
					}
					newPattern.Methods = append(newPattern.Methods, methods...)

					patternPaths, newDiagnostics := getStringSliceFromSet(patternItemMap["paths"], fmt.Sprintf("exempted_paths.patterns[%d].paths", pattern_idx))
					diagnostics = append(diagnostics, newDiagnostics...)
					if len(diagnostics) != 0 {
						return
					}
					newPattern.Paths = append(newPattern.Paths, patternPaths...)

					mandatoryHeaders, newDiagnostics := getStringSliceFromSet(patternItemMap["mandatory_headers"], fmt.Sprintf("exempted_paths.patterns[%d].mandatory_headers", pattern_idx))
					diagnostics = append(diagnostics, newDiagnostics...)
					if len(diagnostics) != 0 {
						return
					}
					newPattern.MandatoryHeaders = append(newPattern.MandatoryHeaders, mandatoryHeaders...)

					hosts, ok := patternItemMap["hosts"].([]interface{})
					if !ok {
						diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("exempted_paths.pattern[%d].hosts", pattern_idx), patternItemMap["hosts"])
						return
					}
					for host_idx, host := range hosts {
						newHost := service.Host{}
						hostMap, ok := host.(map[string]interface{})
						if !ok {
							diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("exempted_paths.pattern[%d].hosts[%d]", pattern_idx, host_idx), host)
							return
						}
						originHeader, newDiagnostics := getStringSliceFromSet(hostMap["origin_header"], fmt.Sprintf("exempted_paths.patterns[%d].hosts[%d].origin_header", pattern_idx, host_idx))
						diagnostics = append(diagnostics, newDiagnostics...)
						if len(diagnostics) != 0 {
							return
						}
						newHost.OriginHeader = append(newHost.OriginHeader, originHeader...)

						target, newDiagnostics := getStringSliceFromSet(hostMap["target"], fmt.Sprintf("exempted_paths.patterns[%d].hosts[%d].target", pattern_idx, host_idx))
						diagnostics = append(diagnostics, newDiagnostics...)
						if len(diagnostics) != 0 {
							return
						}
						newHost.Target = append(newHost.Target, target...)
						newPattern.Hosts = append(newPattern.Hosts, newHost)
					}

					svc.Spec.HTTPSettings.ExemptedPaths.Patterns = append(svc.Spec.HTTPSettings.ExemptedPaths.Patterns, newPattern)
				}
			}

			headers, err := convertEmptyInterfaceToStringMap(httpSettingsMap["headers"])
			if err != nil {
				diagnostics = diag.Errorf("found an error: %s Couldn't type assert http_settings.headers, got %v instead", err.Error(), reflect.TypeOf(httpSettingsMap["headers"]))
				return
			}
			svc.Spec.HTTPSettings.Headers = headers

			httpRedirect, ok := httpSettingsMap["http_redirect"].([]interface{})
			if !ok {
				diagnostics = createTypeAssertDiagnostic("http_settings.http_redirect", httpSettingsMap["http_redirect"])
				return
			}
			for httpRedirectIdx, httpRedirectItem := range httpRedirect {
				httpRedirectItemMap, ok := httpRedirectItem.(map[string]interface{})
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_redirect[%d]", httpRedirectIdx), httpRedirectItem)
					return
				}
				enabled, ok := httpRedirectItemMap["enabled"].(bool)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_redirect[%d].enabled", httpRedirectIdx), httpRedirectItemMap["enabled"])
					return
				}
				svc.Spec.HTTPSettings.HTTPRedirect.Enabled = enabled

				addresses, newDiagnostics := getStringSliceFromSet(httpRedirectItemMap["addresses"], fmt.Sprintf("http_settings.http_redirect[%d].addresses", httpRedirectIdx))
				diagnostics = append(diagnostics, newDiagnostics...)
				if len(diagnostics) != 0 {
					return
				}
				svc.Spec.HTTPSettings.HTTPRedirect.Addresses = addresses

				fromAddress, newDiagnostics := getStringSliceFromSet(httpRedirectItemMap["from_address"], fmt.Sprintf("http_settings.http_redirect[%d].from_address", httpRedirectIdx))
				diagnostics = append(diagnostics, newDiagnostics...)
				if len(diagnostics) != 0 {
					return
				}
				svc.Spec.HTTPSettings.HTTPRedirect.FromAddress = fromAddress

				url, ok := httpRedirectItemMap["url"].(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_redirect[%d].url", httpRedirectIdx), httpRedirectItemMap["url"])
					return
				}
				svc.Spec.HTTPSettings.HTTPRedirect.URL = url

				statusCode, ok := httpRedirectItemMap["status_code"].(int)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_redirect[%d].status_code", httpRedirectIdx), httpRedirectItemMap["status_code"])
					return
				}
				svc.Spec.HTTPSettings.HTTPRedirect.StatusCode = statusCode

			}

			httpHealthCheck, ok := httpSettingsMap["http_health_check"].([]interface{})
			if !ok {
				diagnostics = createTypeAssertDiagnostic("http_settings.httpHealthCheck", httpSettingsMap["http_health_check"])
				return
			}
			for httpHealthCheckIdx, httpHealthCheckItem := range httpHealthCheck {
				httpHealthCheckItemMap, ok := httpHealthCheckItem.(map[string]interface{})
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_health_check[%d]", httpHealthCheckIdx), httpHealthCheckItem)
					return
				}

				enabled, ok := httpHealthCheckItemMap["enabled"].(bool)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_health_check[%d].enabled", httpHealthCheckIdx), httpHealthCheckItemMap["enabled"])
					return
				}
				svc.Spec.HTTPSettings.HTTPHealthCheck.Enabled = enabled

				addresses, newDiagnostics := getStringSliceFromSet(httpHealthCheckItemMap["addresses"], fmt.Sprintf("http_settings.http_health_check[%d].addresses", httpHealthCheckIdx))
				diagnostics = append(diagnostics, newDiagnostics...)
				if len(diagnostics) != 0 {
					return
				}
				svc.Spec.HTTPSettings.HTTPHealthCheck.Addresses = addresses

				method, ok := httpHealthCheckItemMap["method"].(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_health_check[%d].method", httpHealthCheckIdx), httpHealthCheckItemMap["method"])
					return
				}
				svc.Spec.HTTPSettings.HTTPHealthCheck.Method = method

				path, ok := httpHealthCheckItemMap["path"].(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_health_check[%d].path", httpHealthCheckIdx), httpHealthCheckItemMap["path"])
					return
				}
				svc.Spec.HTTPSettings.HTTPHealthCheck.Path = path

				userAgent, ok := httpHealthCheckItemMap["user_agent"].(string)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_health_check[%d].user_agent", httpHealthCheckIdx), httpHealthCheckItemMap["user_agent"])
					return
				}
				svc.Spec.HTTPSettings.HTTPHealthCheck.UserAgent = userAgent

				fromAddress, newDiagnostics := getStringSliceFromSet(httpHealthCheckItemMap["from_address"], fmt.Sprintf("http_settings.http_health_check[%d].from_address", httpHealthCheckIdx))
				diagnostics = append(diagnostics, newDiagnostics...)
				if len(diagnostics) != 0 {
					return
				}
				svc.Spec.HTTPSettings.HTTPHealthCheck.FromAddress = fromAddress

				https, ok := httpHealthCheckItemMap["https"].(bool)
				if !ok {
					diagnostics = createTypeAssertDiagnostic(fmt.Sprintf("http_settings.http_health_check[%d].https", httpHealthCheckIdx), httpHealthCheckItemMap["https"])
					return
				}
				svc.Spec.HTTPSettings.HTTPHealthCheck.HTTPS = https
			}
		}
	}
	toCreate, _ := json.MarshalIndent(svc, "", "   ")
	log.Printf("!!!#### toBeSetService \n%s\n", string(toCreate))
	newService, err := client.Service.Create(svc)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessage(err, "couldn't create new service"))
		return
	}
	log.Printf("#### newservice%#v\n", newService)
	d.SetId(newService.ServiceID)
	// make sure we don't overwrite the existing one
	return resourceServiceRead(ctx, d, m)
}

func resourceServiceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("updating resource")
	return resourceServiceCreate(ctx, d, m)
}

func resourceServiceRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Println("reading resource")
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		diagnostics = diag.FromErr(errors.WithMessagef(err, "couldn't get service with id: %s", id))
		return
	}
	if !ok {
		diagnostics = diag.Errorf("couldn't find expected resource")
		return
	}
	log.Printf("#### readService: %#v", service)
	d.Set("name", service.ServiceName)
	d.Set("description", service.Description)
	d.Set("cluster", service.ClusterName)
	port, err := strconv.Atoi(service.CreateServiceSpec.Metadata.Tags.Port)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	appListenPort, err := strconv.Atoi(service.CreateServiceSpec.Metadata.Tags.AppListenPort)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	metadataTagUserFacing, err := strconv.ParseBool(service.CreateServiceSpec.Metadata.Tags.UserFacing)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	metadatatags := map[string]interface{}{
		"template":            service.CreateServiceSpec.Metadata.Tags.Template,
		"user_facing":         metadataTagUserFacing,
		"protocol":            service.CreateServiceSpec.Metadata.Tags.Protocol,
		"description_link":    service.CreateServiceSpec.Metadata.Tags.DescriptionLink,
		"domain":              service.CreateServiceSpec.Metadata.Tags.Domain,
		"port":                port,
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
		"include_domains":     service.CreateServiceSpec.Metadata.Tags.IncludeDomains,
	}
	d.Set("metadatatags", []interface{}{metadatatags})
	// frontendPort, err := strconv.Atoi(service.CreateServiceSpec.Spec.Attributes.FrontendAddresses[0].Port)
	// if err != nil {
	// 	diagnostics = diag.FromErr(err)
	// 	return
	// }
	// backendPort, err := strconv.Atoi(service.CreateServiceSpec.Spec.Attributes.FrontendAddresses[0].Port)
	// if err != nil {
	// 	diagnostics = diag.FromErr(err)
	// 	return
	// }
	// spec := map[string]interface{}{
	// 	"attributes": map[string]interface{}{
	// 		//todo make this be able to handle n frontend addresses
	// 		"frontend_address": map[string]interface{}{
	// 			"cidr": service.CreateServiceSpec.Spec.Attributes.FrontendAddresses[0].CIDR,
	// 			"port": frontendPort,
	// 		},
	// 		//todo make this handle n host tag selectors
	// 		"host_tag_selector": map[string]interface{}{
	// 			"site_name": service.CreateServiceSpec.Spec.Attributes.HostTagSelector[0],
	// 		},
	// 		"tls_sni": service.CreateServiceSpec.Spec.Attributes.TLSSNI,
	// 	},
	// 	"backend": map[string]interface{}{
	// 		"target": map[string]interface{}{
	// 			"client_certificate": service.CreateServiceSpec.Spec.Backend.Target.ClientCertificate,
	// 			"name":               service.CreateServiceSpec.Spec.Backend.Target.Name,
	// 			"port":               backendPort,
	// 			"tls":                service.CreateServiceSpec.Spec.Backend.Target.TLS,
	// 			"tls_insecure":       service.CreateServiceSpec.Spec.Backend.Target.TLSInsecure,
	// 		},
	// 	},
	// }
	d.Set("spec", flattenServiceSpec(service.CreateServiceSpec.Spec))
	d.SetId(service.ServiceID)
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

func flattenServiceSpec(toFlatten service.Spec) (flattened []interface{}) {
	s := make(map[string]interface{})
	s["attributes"] = flattenServiceAttributes(toFlatten.Attributes)
	s["backend"] = flattenServiceBackend(toFlatten.Backend)
	s["cert_settings"] = flattenServiceCertSettings(toFlatten.CertSettings)
	s["http_settings"] = flattenServiceHTTPSettings(toFlatten.HTTPSettings)
	s["client_cidrs"] = flattenServiceClientCIDRs(toFlatten.ClientCIDRs)

	flattened = append(flattened, s)
	return
}

func flattenServiceAttributes(toFlatten service.Attributes) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["frontend_address"] = flattenServiceFrontendAddresses(toFlatten.FrontendAddresses)
	v["host_tag_selector"] = flattenServiceHostTagSelector(toFlatten.HostTagSelector)
	v["tls_sni"] = toFlatten.TLSSNI
	flattened = append(flattened, v)
	return
}

func flattenServiceFrontendAddresses(toFlatten []service.FrontendAddress) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))

	for idx, item := range toFlatten {
		v := make(map[string]interface{})
		v["cidr"] = item.CIDR
		v["cidr"] = item.Port
		flattened[idx] = v
	}
	return
}

func flattenServiceHostTagSelector(toFlatten []service.HostTag) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))

	for idx, item := range toFlatten {
		v := make(map[string]interface{})
		v["site_name"] = item.ComBanyanopsHosttagSiteName
		flattened[idx] = v
	}
	return
}

func flattenServiceBackend(toFlatten service.Backend) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["backend_allow_pattern"] = flattenServiceAllowPatterns(toFlatten.AllowPatterns)
	v["connector_name"] = toFlatten.ConnectorName
	v["dns_overrides"] = toFlatten.DNSOverrides
	v["target"] = flattenServiceTarget(toFlatten.Target)
	v["backend_allowlist"] = toFlatten.Whitelist

	flattened = append(flattened, v)
	return
}

func flattenServiceAllowPatterns(toFlatten []service.BackendAllowPattern) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))

	for idx, item := range toFlatten {
		v := make(map[string]interface{})
		v["cidrs"] = item.CIDRs
		v["hostnames"] = item.Hostnames
		v["ports"] = flattenServiceBackendAllowPorts(item.Ports)
		flattened[idx] = v
	}
	return
}

func flattenServiceBackendAllowPorts(toFlatten service.BackendAllowPorts) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["port_list"] = toFlatten.PortList
	v["port_range"] = flattenServicePortRanges(toFlatten.PortRanges)
	flattened = append(flattened, v)
	return
}

func flattenServicePortRanges(toFlatten []service.PortRange) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))

	for idx, item := range toFlatten {
		v := make(map[string]interface{})
		v["max"] = item.Max
		v["min"] = item.Min
		flattened[idx] = v
	}
	return
}

func flattenServiceTarget(toFlatten service.Target) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["client_certificate"] = toFlatten.ClientCertificate
	v["name"] = toFlatten.Name
	// todo: handle this error
	v["port"], _ = strconv.Atoi(toFlatten.Port) // need to convert this to int
	v["tls"] = toFlatten.TLS                    // might need to convert this to string
	v["tls_insecure"] = toFlatten.TLSInsecure   // might need to convert this to string

	flattened = append(flattened, v)
	return
}

func flattenServiceCertSettings(toFlatten service.CertSettings) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["custom_tls_cert"] = flattenServiceCustomTLSCert(toFlatten.CustomTLSCert)
	v["dns_names"] = toFlatten.DNSNames
	v["letsencrypt"] = toFlatten.LetsEncrypt

	flattened = append(flattened, v)
	return
}

func flattenServiceCustomTLSCert(toFlatten service.CustomTLSCert) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["cert_file"] = toFlatten.CertFile
	v["enabled"] = toFlatten.Enabled
	v["key_file"] = toFlatten.KeyFile
	flattened = append(flattened, v)
	return
}

func flattenServiceHTTPSettings(toFlatten service.HTTPSettings) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["enabled"] = toFlatten.Enabled
	v["exempted_paths"] = flattenServiceExemptedPaths(toFlatten.ExemptedPaths)
	v["http_health_check"] = flattenServiceHTTPHealthCheck(toFlatten.HTTPHealthCheck)
	v["http_redirect"] = flattenServiceHTTPRedirect(toFlatten.HTTPRedirect)
	v["headers"] = toFlatten.Headers
	v["oidc_settings"] = flattenServiceOIDCSettings(toFlatten.OIDCSettings)
	flattened = append(flattened, v)
	return
}

func flattenServiceExemptedPaths(toFlatten service.ExemptedPaths) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["enabled"] = toFlatten.Enabled
	v["paths"] = toFlatten.Paths
	v["pattern"] = flattenServicePatterns(toFlatten.Patterns)
	flattened = append(flattened, v)
	return
}

func flattenServicePatterns(toFlatten []service.Pattern) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))

	for idx, item := range toFlatten {
		v := make(map[string]interface{})
		v["hosts"] = flattenServiceHosts(item.Hosts)
		v["mandatory_headers"] = item.MandatoryHeaders
		v["methods"] = item.Methods
		v["paths"] = item.Paths
		v["source_cidrs"] = item.SourceCIDRs
		flattened[idx] = v
	}
	return
}

func flattenServiceHosts(toFlatten []service.Host) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))

	for idx, item := range toFlatten {
		v := make(map[string]interface{})
		v["origin_header"] = item.OriginHeader
		v["target"] = item.Target
		flattened[idx] = v
	}
	return
}

func flattenServiceHTTPHealthCheck(toFlatten service.HTTPHealthCheck) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["addresses"] = toFlatten.Addresses
	v["enabled"] = toFlatten.Enabled
	v["from_address"] = toFlatten.FromAddress
	v["https"] = toFlatten.HTTPS
	v["path"] = toFlatten.Path
	v["user_agent"] = toFlatten.UserAgent
	flattened = append(flattened, v)
	return
}

func flattenServiceHTTPRedirect(toFlatten service.HTTPRedirect) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["addresses"] = toFlatten.Addresses
	v["enabled"] = toFlatten.Enabled
	v["from_address"] = toFlatten.FromAddress
	v["status_code"] = toFlatten.StatusCode
	v["url"] = toFlatten.URL
	flattened = append(flattened, v)
	return
}

func flattenServiceOIDCSettings(toFlatten service.OIDCSettings) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["api_path"] = toFlatten.APIPath
	v["enabled"] = toFlatten.Enabled
	v["post_auth_redirect_path"] = toFlatten.PostAuthRedirectPath
	v["service_domain_name"] = toFlatten.ServiceDomainName
	v["suppress_device_trust_verification"] = toFlatten.SuppressDeviceTrustVerification
	v["trust_callbacks"] = toFlatten.TrustCallBacks
	flattened = append(flattened, v)
	return
}

func flattenServiceClientCIDRs(toFlatten []service.ClientCIDRs) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))

	for idx, item := range toFlatten {
		v := make(map[string]interface{})
		v["address"] = flattenServiceCIDRAddresses(item.Addresses)
		v["clusters"] = item.Clusters
		v["host_tag_selector"] = item.HostTagSelector
		flattened[idx] = v
	}
	return
}

func flattenServiceCIDRAddresses(toFlatten []service.CIDRAddress) (flattened []interface{}) {
	flattened = make([]interface{}, len(toFlatten), len(toFlatten))

	for idx, item := range toFlatten {
		v := make(map[string]interface{})
		v["cidr"] = item.CIDR
		v["ports"] = item.Ports
		flattened[idx] = v
	}
	return
}
