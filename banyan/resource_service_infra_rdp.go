package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/pkg/errors"
	"log"
	"strconv"
)

func resourceServiceInfraRdp() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of infrastructure RDP services.",
		CreateContext: resourceServiceInfraRdpCreate,
		ReadContext:   resourceServiceInfraRdpRead,
		UpdateContext: resourceServiceInfraRdpUpdate,
		DeleteContext: resourceServiceInfraRdpDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the service; use lowercase alphanumeric characters or \"-\"",
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
				Description: "Name of the cluster used for your deployment; for Global Edge set to \"global-edge\", for Private Edge set to \"cluster1\"",
				ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
			},
			"access_tiers": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Names of the access_tier which will proxy requests to your service backend; set to \"\" if using Global Edge deployment'",
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
			"icon": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"description_link": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"allow_user_override": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
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
			"allow_patterns": {
				Type:     schema.TypeList,
				Optional: true,
				Computed: true,
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
			"cert_settings": {
				Type:        schema.TypeList,
				MaxItems:    1,
				MinItems:    1,
				Optional:    true,
				Computed:    true,
				Description: "Specifies the X.509 server certificate to use for this Service",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
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
					},
				},
			},
		},
	}
}

func resourceServiceInfraRdpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating RDP service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)

	svc := service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandRDPMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandInfraServiceSpec(d),
	}

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create RDP service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] Created RDP service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraRdpRead(ctx, d, m)
}

func expandRDPMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacingMetadataTag := d.Get("user_facing").(bool)
	userFacing := strconv.FormatBool(userFacingMetadataTag)
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "RDP"
	banyanProxyMode := "TCP"
	alp := d.Get("backend_port").(int)
	appListenPort := strconv.Itoa(alp)
	allowUserOverride := d.Get("allow_user_override").(bool)
	descriptionLink := d.Get("description_link").(string)

	metadatatags = service.Tags{
		Template:          &template,
		UserFacing:        &userFacing,
		Protocol:          &protocol,
		Domain:            &domain,
		Port:              &port,
		Icon:              &icon,
		ServiceAppType:    &serviceAppType,
		BanyanProxyMode:   &banyanProxyMode,
		AppListenPort:     &appListenPort,
		AllowUserOverride: &allowUserOverride,
		DescriptionLink:   &descriptionLink,
	}
	return
}

func resourceServiceInfraRdpUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating RDP service %s : %s", d.Get("name"), d.Id())
	resourceServiceInfraRdpCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated RDP service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraRdpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] Reading RDP service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get database service with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	d.Set("allow_user_override", service.CreateServiceSpec.Metadata.Tags.AllowUserOverride)
	diagnostics = resourceServiceInfraCommonRead(service, d, m)
	log.Printf("[SVC|RES|READ] read RDP service %s : %s", d.Get("name"), d.Id())
	d.SetId(id)
	return
}

func resourceServiceInfraRdpDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting RDP service %s : %s", d.Get("name"), d.Id())
	diagnostics = resourceServiceInfraCommonDelete(d, m)
	log.Printf("[SERVICE|RES|DELETE] deleted RDP service %s : %s", d.Get("name"), d.Id())
	return
}
