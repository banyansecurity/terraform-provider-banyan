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
func resourceServiceInfraWeb() *schema.Resource {
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
		CreateContext: resourceServiceInfraWebCreate,
		ReadContext:   resourceServiceInfraWebRead,
		UpdateContext: resourceServiceInfraWebUpdate,
		DeleteContext: resourceServiceInfraWebDelete,
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
				Optional:    true,
				Description: "Access tier names the service is accessible from",
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
			},
			"connector": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of the connector which will proxy requests to your service backend; set to \"\" if using Private Edge deployment",
				Default:     "",
			},
			"domain": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The external-facing network address for this service; ex. website.example.com",
			},
			"port": {
				Type:         schema.TypeInt,
				Optional:     true,
				Description:  "The external-facing port for this service",
				Default:      8443,
				ValidateFunc: validatePort(),
			},
			"user_facing": {
				Type:        schema.TypeBool,
				Description: "Whether the service is user-facing or not",
				Optional:    true,
				Default:     true,
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
			"backend_domain": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The internal network address where this service is hosted; ex. 192.168.1.2; set to \"\" if using backend_http_connect",
			},
			"backend_port": {
				Type:         schema.TypeInt,
				Required:     true,
				Description:  "The internal port where this service is hosted; set to 0 if using backend_http_connect",
				ValidateFunc: validatePort(),
			},
			"backend_http_connect": {
				Type:        schema.TypeBool,
				Description: "Indicates to use HTTP Connect request to derive the backend target address.",
				Optional:    true,
				Default:     false,
			},
			"dns_overrides": {
				Type:     schema.TypeMap,
				Optional: true,
				Description: `
								Specifies name-to-address or name-to-name mappings.
								Name-to-address mapping could be used instead of DNS lookup. Format is "FQDN: ip_address".
								Name-to-name mapping could be used to override one FQDN with the other. Format is "FQDN1: FQDN2"
								Example: name-to-address -> "internal.myservice.com" : "10.23.0.1"
								ame-to-name    ->    "exposed.service.com" : "internal.myservice.com"
										`,
				Elem: &schema.Schema{Type: schema.TypeString},
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
			"client_certificate": {
				Type:        schema.TypeBool,
				Description: "Indicates whether to provide Netagent's client TLS certificate to the server if the server asks for it in the TLS handshake.",
				Optional:    true,
				Default:     false,
			},
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
							Computed:    true,
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
							Computed: true,
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
							Computed:    true,
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

func resourceServiceInfraWebCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating web service %s : %s", d.Get("name"), d.Id())
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
		Spec:       expandWebServiceSpec(d),
	}

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create web service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] Created web service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraWebRead(ctx, d, m)
}

func expandWebMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "WEB_USER"
	userFacingMetadataTag := d.Get("user_facing").(bool)
	userFacing := strconv.FormatBool(userFacingMetadataTag)
	protocol := d.Get("protocol").(string)
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "WEB"
	descriptionLink := d.Get("description_link").(string)

	metadatatags = service.Tags{
		Template:        &template,
		UserFacing:      &userFacing,
		Protocol:        &protocol,
		Domain:          &domain,
		Port:            &port,
		Icon:            &icon,
		ServiceAppType:  &serviceAppType,
		DescriptionLink: &descriptionLink,
	}
	return
}

func resourceServiceInfraWebUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating web service %s : %s", d.Get("name"), d.Id())
	resourceServiceInfraWebCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated web service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraWebRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] Reading web service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get web servicewith id: %s", id))
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
	err = d.Set("cluster", service.ClusterName)
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
	var metadataTagUserFacing bool
	metadataTagUserFacingPtr := service.CreateServiceSpec.Metadata.Tags.UserFacing
	if metadataTagUserFacingPtr != nil {
		metadataTagUserFacing, err = strconv.ParseBool(*service.CreateServiceSpec.Metadata.Tags.UserFacing)
		if err != nil {
			diagnostics = diag.FromErr(err)
			return
		}
	}
	err = d.Set("connector", service.CreateServiceSpec.Spec.Backend.ConnectorName)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("user_facing", metadataTagUserFacing)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("domain", service.CreateServiceSpec.Metadata.Tags.Domain)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("icon", service.CreateServiceSpec.Metadata.Tags.Icon)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("description_link", service.CreateServiceSpec.Metadata.Tags.DescriptionLink)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_cidrs", flattenServiceClientCIDRs(service.CreateServiceSpec.Spec.ClientCIDRs))
	if err != nil {
		return diag.FromErr(err)
	}
	tlsSNI := removeFromSlice(service.CreateServiceSpec.Spec.Attributes.TLSSNI, *service.CreateServiceSpec.Metadata.Tags.Domain)
	err = d.Set("tls_sni", tlsSNI)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("http_settings", flattenServiceHTTPSettings(service.CreateServiceSpec.Spec.HTTPSettings))
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("cert_settings", flattenWebServiceCertSettings(service.CreateServiceSpec.Spec.CertSettings, *service.CreateServiceSpec.Metadata.Tags.Domain))
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

func resourceServiceInfraWebDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting web service with id: %q \n", d.Id())
	client := m.(*client.ClientHolder)
	err := client.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	log.Printf("[SERVICE|RES|DELETE] deleted web service with id: %q \n", d.Id())
	return
}

func expandWebServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	clientCidrs := expandClientCIDRs(d.Get("client_cidrs").([]interface{}))
	if len(clientCidrs) == 0 {
		clientCidrs = []service.ClientCIDRs{}
	}
	spec = service.Spec{
		Attributes:   expandWebAttributes(d),
		Backend:      expandWebBackend(d),
		CertSettings: expandInfraCertSettings(d),
		HTTPSettings: expandWebHTTPSettings(d),
		ClientCIDRs:  clientCidrs,
		TagSlice:     expandTagSlice(d.Get("tag_slice").([]interface{})),
	}
	return
}

func expandWebHTTPSettings(d *schema.ResourceData) (httpSettings service.HTTPSettings) {
	httpSettingsItem := d.Get("http_settings").([]interface{})
	if len(httpSettingsItem) == 0 {
		httpSettings = service.HTTPSettings{
			Enabled: true,
			OIDCSettings: service.OIDCSettings{
				Enabled:                         true,
				ServiceDomainName:               fmt.Sprintf("https://%s", d.Get("domain").(string)),
				PostAuthRedirectPath:            "",
				APIPath:                         "",
				TrustCallBacks:                  nil,
				SuppressDeviceTrustVerification: false,
			},
			HTTPHealthCheck: service.HTTPHealthCheck{
				Enabled:     false,
				Addresses:   nil,
				Method:      "",
				Path:        "",
				UserAgent:   "",
				FromAddress: []string{},
				HTTPS:       false,
			},
			HTTPRedirect: service.HTTPRedirect{
				Enabled:     false,
				Addresses:   nil,
				FromAddress: nil,
				URL:         "",
				StatusCode:  0,
			},
			ExemptedPaths: service.ExemptedPaths{
				Enabled:  false,
				Paths:    nil,
				Patterns: nil,
			},
			Headers:  map[string]string{},
			TokenLoc: nil,
		}
		return
	}

	itemMap := httpSettingsItem[0].(map[string]interface{})
	tokenLoc := expandTokenLoc(itemMap["token_loc"].([]interface{}))
	httpSettings = service.HTTPSettings{
		Enabled:         itemMap["enabled"].(bool),
		OIDCSettings:    expandWebOIDCSettings(d, itemMap["oidc_settings"].([]interface{})),
		HTTPHealthCheck: expandHTTPHealthCheck(itemMap["http_health_check"].([]interface{})),
		// will be deprecated from api
		HTTPRedirect:  service.HTTPRedirect{},
		ExemptedPaths: expandExemptedPaths(itemMap["exempted_paths"].([]interface{})),
		Headers:       convertInterfaceMapToStringMap(itemMap["headers"].(map[string]interface{})),
		TokenLoc:      &tokenLoc,
	}
	return
}

func expandWebOIDCSettings(d *schema.ResourceData, m []interface{}) (oidcSettings service.OIDCSettings) {
	if len(m) == 0 {
		return
	}
	itemMap := m[0].(map[string]interface{})
	oidcSettings = service.OIDCSettings{
		Enabled:                         true,
		ServiceDomainName:               fmt.Sprintf("https://%s", d.Get("domain").(string)),
		PostAuthRedirectPath:            itemMap["post_auth_redirect_path"].(string),
		APIPath:                         itemMap["api_path"].(string),
		TrustCallBacks:                  convertInterfaceMapToStringMap(itemMap["trust_callbacks"].(map[string]interface{})),
		SuppressDeviceTrustVerification: itemMap["suppress_device_trust_verification"].(bool),
	}
	return
}

func expandWebAttributes(d *schema.ResourceData) (attributes service.Attributes) {
	var tlsSNI []string
	additionalTlsSni := convertSchemaSetToStringSlice(d.Get("tls_sni").(*schema.Set))
	for _, s := range additionalTlsSni {
		tlsSNI = append(tlsSNI, s)
	}
	tlsSNI = append(tlsSNI, d.Get("domain").(string))
	tlsSNI = removeDuplicateStr(tlsSNI)

	// build HostTagSelector from access_tiers
	var hostTagSelector []map[string]string
	accessTiers := d.Get("access_tiers").(*schema.Set)
	accessTiersSlice := convertSchemaSetToStringSlice(accessTiers)
	siteNamesString := strings.Join(accessTiersSlice, "|")
	siteNameSelector := map[string]string{"com.banyanops.hosttag.site_name": siteNamesString}
	hostTagSelector = append(hostTagSelector, siteNameSelector)

	attributes = service.Attributes{
		TLSSNI:            tlsSNI,
		FrontendAddresses: expandWebFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandWebBackend(d *schema.ResourceData) (backend service.Backend) {
	whitelist := convertSchemaSetToStringSlice(d.Get("whitelist").(*schema.Set))
	if len(whitelist) == 0 {
		whitelist = []string{}
	}
	backend = service.Backend{
		AllowPatterns: expandAllowPatterns(d.Get("allow_patterns").([]interface{})),
		DNSOverrides:  convertEmptyInterfaceToStringMap(d.Get("dns_overrides").(map[string]interface{})),
		ConnectorName: d.Get("connector").(string),
		HTTPConnect:   d.Get("backend_http_connect").(bool),
		Target:        expandWebTarget(d),
		Whitelist:     whitelist,
	}
	return
}

func expandWebTarget(d *schema.ResourceData) (target service.Target) {
	return service.Target{
		Name:              d.Get("backend_domain").(string),
		Port:              strconv.Itoa(d.Get("backend_port").(int)),
		TLS:               d.Get("tls").(bool),
		TLSInsecure:       d.Get("tls_insecure").(bool),
		ClientCertificate: d.Get("client_certificate").(bool),
	}
}

func expandWebFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
	portInt := d.Get("port").(int)
	frontendAddresses = append(
		frontendAddresses,
		service.FrontendAddress{
			CIDR: "",
			Port: strconv.Itoa(portInt),
		},
	)
	return
}

func flattenWebServiceCertSettings(toFlatten service.CertSettings, domain string) (flattened []interface{}) {
	v := make(map[string]interface{})
	v["custom_tls_cert"] = flattenServiceCustomTLSCert(toFlatten.CustomTLSCert)
	v["dns_names"] = removeFromSlice(toFlatten.DNSNames, domain)
	v["letsencrypt"] = toFlatten.Letsencrypt
	flattened = append(flattened, v)
	return
}
