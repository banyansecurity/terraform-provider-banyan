package banyan

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"log"
	"strconv"
	"strings"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceWebService() *schema.Resource {
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
		CreateContext: resourceWebServiceCreate,
		ReadContext:   resourceWebServiceRead,
		UpdateContext: resourceWebServiceUpdate,
		DeleteContext: resourceWebServiceDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the service",
				ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
			},
			"id": {
				Type:        schema.TypeString,
				Description: "Id of the service",
				Computed:    true,
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
			"access_tiers": {
				Type:        schema.TypeSet,
				Required:    true,
				Description: "Access tier names the service is accessible from",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"user_facing": {
				Type:        schema.TypeBool,
				Description: "Whether the service is user-facing or not",
				Optional:    true,
				Default:     true,
			},
			"domain": {
				Type:     schema.TypeString,
				Required: true,
			},
			"protocol": {
				Type:         schema.TypeString,
				Description:  "The protocol of the service, must be tcp, http or https",
				Required:     true,
				ValidateFunc: validation.StringInSlice([]string{"http", "https", "tcp"}, false),
			},
			"icon": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"description_link": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"client_cidrs": {
				Type:     schema.TypeList,
				Optional: true,
				Description: `
					ClientCIDRs is used in environments with Network Address Translation (NAT) to list
					the IP addresses that are used to access the Service; Netagent will then automatically
					intercept traffic to these IP addresses.`,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cidr_address": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "CIDRAddress uses the Classless Inter-Domain Routing (CIDR) format for flexible allocation of IP addresses",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"cidr": {
										Type:         schema.TypeString,
										Optional:     true,
										Description:  "Must be in CIDR format i.e. 192.168.0.0/16",
										ValidateFunc: validation.IsCIDRNetwork(0, 32),
									},
									"ports": {
										Type:        schema.TypeString,
										Description: "",
										Optional:    true,
									},
								},
							},
						},
						"clusters": {
							Type:        schema.TypeSet,
							Optional:    true,
							Description: "Tells Netagent to set Client CIDRs on only a specific subset of clusters",
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"host_tag_selector": {
							Type:        schema.TypeList,
							Optional:    true,
							Description: "Tells Netagent to set Client CIDRs on only a specific subset of hosts and ports",
							Elem: &schema.Schema{
								Type: schema.TypeMap,
								Elem: &schema.Schema{Type: schema.TypeString},
							},
						},
					},
				},
			},
			"backend": {
				Type:     schema.TypeList,
				Required: true,
				Description: `
					Backend specifies how Netagent, when acting as a reverse proxy, forwards incoming 
					“frontend connections” to a backend workload instance that implements a registered service`,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"allow_patterns": {
							Type:     schema.TypeList,
							Optional: true,
							Description: `
								Defines the patterns for the backend workload instance. If the BackendAllowPatterns is set,
								then the backend must match at least one entry in this list to establish connection with the backend service. 
   								Note that this field is effective only when BackendWhitelist is not populated.
   								If BackendWhitelist and BackendAllowPatterns are both not populated, then all backend
   								address/name/port are allowed. This field could be used with httpConnect set to TRUE or FALSE. With HttpConnect set to FALSE, 
   								only backend hostnames are supported, all other fields are ignored. With HttpConnect set to TRUE, 
   								all fields of BackendAllowPatterns are supported and effective.`,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"hostnames": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
										Description: "Allowed hostnames my include a leading and/or trailing wildcard character * to match multiple hostnames",
									},
									"cidrs": {
										Type:     schema.TypeSet,
										Optional: true,
										Elem: &schema.Schema{
											Type:         schema.TypeString,
											ValidateFunc: validation.IsCIDRNetwork(0, 32),
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
																Description:  "Minimum value of port range",
																ValidateFunc: validatePort(),
															},
															"max": {
																Type:         schema.TypeInt,
																Optional:     true,
																Description:  "Maximum value of port range",
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
							Computed: true,
							Description: `
								Specifies name-to-address or name-to-name mappings.
								Name-to-address mapping could be used instead of DNS lookup. Format is "FQDN: ip_address".
								Name-to-name mapping could be used to override one FQDN with the other. Format is "FQDN1: FQDN2"
								Example: name-to-address -> "internal.myservice.com" : "10.23.0.1"
								ame-to-name    ->    "exposed.service.com" : "internal.myservice.com"
										`,
							Elem: &schema.Schema{Type: schema.TypeString},
						},
						"connector_name": {
							Type:        schema.TypeString,
							Description: "If Banyan Connector is used to access this service, this must be set to the name of the connector with network access to the service",
							Optional:    true,
						},
						"http_connect": {
							Type:        schema.TypeBool,
							Description: "Indicates to use HTTP Connect request to derive the backend target address.",
							Optional:    true,
						},
						"target": {
							Type:        schema.TypeList,
							MinItems:    1,
							MaxItems:    1,
							Required:    true,
							Description: "Specifies the backend workload instance's address or name ports, and TLS properties.",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"client_certificate": {
										Type:        schema.TypeBool,
										Description: "Indicates whether to provide Netagent's client TLS certificate to the server if the server asks for it in the TLS handshake.",
										Optional:    true,
										Default:     false,
									},
									"name": {
										Type: schema.TypeString,
										Description: `
											Name specifies the DNS name of the backend workload instance. 
											If it is the empty string, then Netagent will use the destination
											IP address of the incoming frontend connection as the workload 
											instance's address`,
										Optional: true,
										Default:  "",
									},
									"port": {
										Type:         schema.TypeInt,
										Description:  "Port specifies the backend server's TCP port number",
										Required:     true,
										ValidateFunc: validatePort(),
									},
									"tls": {
										Type:        schema.TypeBool,
										Description: "TLS indicates whether the connection to the backend server uses TLS.",
										Optional:    true,
										Default:     false,
									},
									"tls_insecure": {
										Type:        schema.TypeBool,
										Description: "TLSInsecure indicates whether the backend TLS connection does not validate the server's TLS certificate",
										Optional:    true,
										Default:     false,
									},
								},
							},
						},
						"whitelist": {
							Type:     schema.TypeSet,
							Optional: true,
							Computed: true,
							Description: `
								Indicates the allowed names for the backend workload instance. 
								If this field is populated, then the backend name must match at least one entry
								in this field list to establish connection with the backend service.
								The names in this list are allowed to start with the wildcard character "*" to match more
								than one backend name. This field is used generally with HttpConnect=FALSE. For all HttpConnect=TRUE cases, or where 
								more advanced backend defining patterns are required, use BackendAllowPatterns.`,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
					},
				},
			},
			"frontend": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "Specifies the IP addresses and ports the frontend of the service listens on",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cidr": {
							Type:     schema.TypeString,
							Optional: true,
							// TODO: verify this
							Description:  "A list of IP addresses in string format specified in CIDR notation that the Service should match",
							ValidateFunc: validation.IsCIDRNetwork(0, 32),
						},
						"port": {
							Type:         schema.TypeString,
							Required:     true,
							Description:  "The port that the service listens on",
							ValidateFunc: validatePort(),
						},
					},
				},
			},
			"tls_sni": {
				Type:     schema.TypeSet,
				Optional: true,
				Computed: true,
				Description: `
					If TLSSNI is set, Netagent will reject all non-TLS connections.
					It will only forward on TLS connections where the SNI matches for Policy validation"`,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"http_settings": {
				Type:        schema.TypeList,
				MaxItems:    1,
				Optional:    true,
				Computed:    true,
				Description: "Used by HTTP services for use-case specific functionality",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"enabled": {
							Type:        schema.TypeBool,
							Description: "Enables http service specific settings",
							Required:    true,
						},
						"oidc_settings": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Computed: true,
							Description: `
								OIDCSettings provides Netagent specific parameters needed to use 
								OpenID Connect to authenticate an Entity for access to a Service
								`,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:        schema.TypeBool,
										Description: "Turns on the OIDC capability",
										Required:    true,
									},
									"service_domain_name": {
										Type:        schema.TypeString,
										Description: "The URL used to access the service",
										Required:    true,
									},
									"post_auth_redirect_path": {
										Type:        schema.TypeString,
										Default:     "/",
										Description: "The path to return the user to after OpenID Connect flow",
										Optional:    true,
									},
									"api_path": {
										Type: schema.TypeString,
										Description: `
											default: /api) is the path serving AJAX requests. 
											If a request is not authenticated, paths starting with the APIPath 
											will receive a 403 Unauthorized response
											instead of a 302 Redirect to the authentication provider`,
										Optional: true,
									},
									"suppress_device_trust_verification": {
										Type:        schema.TypeBool,
										Optional:    true,
										Description: "SuppressDeviceTrustVerification disables Device Trust Verification for a service if set to true",
									},
									"trust_callbacks": {
										Type:        schema.TypeMap,
										Optional:    true,
										Description: "",
										Elem:        &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"http_health_check": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Description: "Tells Netagent that specific HTTP paths should be exempted from access control policies",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:        schema.TypeBool,
										Description: "Turns on the HTTP health check capability",
										Required:    true,
									},
									"addresses": {
										Type:        schema.TypeSet,
										Required:    true,
										Description: "Addresses of the http health check",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"method": {
										Type:         schema.TypeString,
										Optional:     true,
										Default:      "GET",
										Description:  "Specifies the health check HTTP method",
										ValidateFunc: validateHttpMethods(),
									},
									"path": {
										Type:        schema.TypeString,
										Description: "Specifies the HTTP health check path",
										Required:    true,
									},
									"user_agent": {
										Type:        schema.TypeString,
										Description: "A string to check for in the HTTP user-agent header (no check if omitted)",
										Optional:    true,
									},
									"from_address": {
										Type:        schema.TypeSet,
										Required:    true,
										Description: "Allowed source addresses of the health checker (all allowed if omitted)",
										Elem: &schema.Schema{
											Type: schema.TypeString,
										},
									},
									"https": {
										Type:        schema.TypeBool,
										Required:    true,
										Description: "Specifies that the health check uses https instead of https",
									},
								},
							},
						},
						"exempted_paths": {
							Type:        schema.TypeList,
							MaxItems:    1,
							Optional:    true,
							Computed:    true,
							Description: "Tells Netagent that specific HTTP paths should be whitelisted/exempted from OIDC authentication",
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:        schema.TypeBool,
										Description: "Turns on the HTTP exempted paths capability",
										Required:    true,
									},
									"patterns": {
										Type:     schema.TypeList,
										Optional: true,
										Description: `
											Pattern tells Netagent to exempt HTTP requests based on matching HTTP request attributes 
											such as source IP, host, headers, methods, paths, etc. 
											For example, use this section when exempting CORS requests by source IP address.
											`,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"template": {
													Type:        schema.TypeString,
													Description: "",
													Optional:    true,
												},
												"source_cidrs": {
													Type: schema.TypeSet,
													Description: `
														Specifies the source IP address of the HTTP request. 
														The matching request should match or should be in the range of the CIDR specified.
														SourceCIDRs is an array and multiple CIDRs with/without prefix 
														could be specified like, 127.0.0.1, 192.168.1.0/29, 10.0.0.0/8 etc.
														If source-ip matching is not required, please skip this field`,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"hosts": {
													Type:        schema.TypeList,
													Optional:    true,
													Description: "The host/origin header values in the HTTP request",
													Elem: &schema.Resource{
														Schema: map[string]*schema.Schema{
															"origin_header": {
																Type: schema.TypeSet,
																Description: `
																	OriginHeader (mandatory)-is list of web host address. 
																	The web-host address matches to contents of Origin header in the HTTP request.
																	The value should have "scheme:host:port", ex: "https://www.banyansecurity.io:443".
																	This field supports single domain wildcards also, like 
																	https://*.banyansecurity.com or https://api.*.banyansecurity.com:443
																	`,
																Optional: true,
																Elem: &schema.Schema{
																	Type: schema.TypeString,
																},
															},
															"target": {
																Type: schema.TypeSet,
																Description: `
																	Target (mandatory) list of web host address. In this web-host address,
																	the hostname matches to host header in the HTTP request.
																	The value should have "scheme:host:port",
																	ex: https://www.banyansecurity.io:443. This field supports single domain wildcards also,
																	like https://*.banyansecurity.com or https://api.*.banyansecurity.com:443.
																	This should be filled only while hosting multi-domain services. In single domain
																	service deployments, this field to be filled as [*] to have "DONT CARE" effect.
																	`,
																Optional: true,
																Elem: &schema.Schema{
																	Type: schema.TypeString,
																},
															},
														},
													},
												},
												"methods": {
													Type: schema.TypeSet,
													Description: `
														Matches the HTTP request methods. The matching request 
														will have any one of the listed methods.
														To list all the methods supported "like GET/POST/OPTIONS etc.
														["*"] value will have "DONT CARE" effect and will skip matching methods.
														`,
													Optional: true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"paths": {
													Type:        schema.TypeSet,
													Description: "Matches the HTTP request URI. The matching request will have any one of the paths/strings listed.",
													Optional:    true,
													Elem: &schema.Schema{
														Type: schema.TypeString,
													},
												},
												"mandatory_headers": {
													Type: schema.TypeSet,
													Description: `
														MandatoryHeaders (mandatory) matches the HTTP request headers.
														The matching request will have all of the headers listed.
														To list all the headers that a matching HTTP request should have for instance
														"Content-Type"/"Access-Control-Allow-Origin" etc.
														["*"] will have "DONT CARE" effect and will skip matching headers.`,
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
				Computed:    true,
				Description: "Specifies the X.509 server certificate to use for this Service",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"letsencrypt": {
							Type:        schema.TypeBool,
							Description: "Letsencrypt flag will be used whether to request a letsencrypt certificate for given domains",
							Optional:    true,
						},
						"dns_names": {
							Type: schema.TypeSet,
							Description: `
								DNSNames specifies how to populate the CommonName field in the X.509
								server certificate for this Service. If DNSNames is not specified the 
								CommonName field will be set to the ServiceName`,
							Optional: true,
							Elem: &schema.Schema{
								Type: schema.TypeString,
							},
						},
						"custom_tls_cert": {
							Type:     schema.TypeList,
							MaxItems: 1,
							Optional: true,
							Computed: true,
							Description: `
								CustomTLSCert enables Netagent to override the default behavior
								of obtaining a X.509 server certificate for this Service from Shield,
								and instead use a TLS certificate on the local file system`,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"enabled": {
										Type:        schema.TypeBool,
										Description: "Turns on the custom TLS certificate capability",
										Required:    true,
									},
									"cert_file": {
										Type:        schema.TypeString,
										Sensitive:   true,
										Description: "Specifies the local path of the public certificate (ex: /etc/letsencrypt/live/intks.net-0001/fullchain.pem) on the netagent / connector filesystem",
										Required:    true,
									},
									"key_file": {
										Type:        schema.TypeString,
										Required:    true,
										Description: "Specifies the local path of the private key (ex: /etc/letsencrypt/live/intks.net-0001/fullchain.pem) on the netagent / connector filesystem",
										Sensitive:   true,
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

func resourceWebServiceCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)

	svc := service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandWebMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandAbstractServiceSpec(d),
	}

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] Created service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceWebServiceRead(ctx, d, m)
}

func expandWebMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacingMetadataTag := d.Get("user_facing").(bool)
	userFacing := strconv.FormatBool(userFacingMetadataTag)
	protocol := d.Get("protocol").(string)
	domain := d.Get("domain").(string)
	port := d.Get("frontend.0.port").(string)
	icon := d.Get("icon").(string)
	serviceAppType := "WEB"
	alp := d.Get("backend.0.target.0.port").(int)
	appListenPort := strconv.Itoa(alp)
	descriptionLink := d.Get("description_link").(string)

	metadatatags = service.Tags{
		Template:        &template,
		UserFacing:      &userFacing,
		Protocol:        &protocol,
		Domain:          &domain,
		Port:            &port,
		Icon:            &icon,
		ServiceAppType:  &serviceAppType,
		AppListenPort:   &appListenPort,
		DescriptionLink: &descriptionLink,
	}
	return
}

func resourceWebServiceUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating service %s : %s", d.Get("name"), d.Id())
	resourceWebServiceCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceWebServiceRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] Reading service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get service with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
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
	hostTagSelector := service.CreateServiceSpec.Spec.HostTagSelector[0]
	siteName := hostTagSelector["com.banyanops.hosttag.site_name"]
	accessTiers := strings.Split(siteName, "|")
	err = d.Set("access_tiers", accessTiers)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("cluster", service.ClusterName)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	var metadataTagUserFacing bool
	metadataTagUserFacingPtr := service.CreateServiceSpec.Metadata.Tags.UserFacing
	if metadataTagUserFacingPtr != nil {
		metadataTagUserFacing, err = strconv.ParseBool(*service.CreateServiceSpec.Metadata.Tags.UserFacing)
		if err != nil {
			diagnostics = diag.FromErr(err)
			return
		}
	}
	d.Set("user_facing", metadataTagUserFacing)
	d.Set("domain", service.CreateServiceSpec.Metadata.Tags.Domain)
	d.Set("protocol", service.CreateServiceSpec.Metadata.Tags.Protocol)
	d.Set("icon", service.CreateServiceSpec.Metadata.Tags.Icon)
	d.Set("description_link", service.CreateServiceSpec.Metadata.Tags.DescriptionLink)
	err = d.Set("client_cidrs", flattenServiceClientCIDRs(service.CreateServiceSpec.Spec.ClientCIDRs))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("frontend", flattenServiceFrontendAddresses(service.CreateServiceSpec.Spec.Attributes.FrontendAddresses))
	if err != nil {
		return diag.FromErr(err)
	}
	tlsSNI := removeFromSlice(service.CreateServiceSpec.Spec.Attributes.TLSSNI, *service.CreateServiceSpec.Metadata.Tags.Domain)
	err = d.Set("tls_sni", tlsSNI)
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
	err = d.Set("cert_settings", flattenAbstractServiceCertSettings(service.CreateServiceSpec.Spec.CertSettings, *service.CreateServiceSpec.Metadata.Tags.Domain))
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

func resourceWebServiceDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting service with id: %q \n", d.Id())
	client := m.(*client.ClientHolder)
	err := client.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	log.Printf("[SERVICE|RES|DELETE] deleted service with id: %q \n", d.Id())
	return
}
