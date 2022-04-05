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
func resourceServiceInfraDb() *schema.Resource {
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
		CreateContext: resourceServiceInfraDbCreate,
		ReadContext:   resourceServiceInfraDbRead,
		UpdateContext: resourceServiceInfraDbUpdate,
		DeleteContext: resourceServiceInfraDbDelete,
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
			"icon": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"description_link": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"backend": {
				Type:     schema.TypeList,
				Required: true,
				Description: `
					Backend specifies how Netagent, when acting as a reverse proxy, forwards incoming 
					“frontend connections” to a backend workload instance that implements a registered service`,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
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

func resourceServiceInfraDbCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating database service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)

	svc := service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandDatabaseMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandInfraServiceSpec(d),
	}

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create database service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] Created database service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraDbRead(ctx, d, m)
}

func expandDatabaseMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacingMetadataTag := d.Get("user_facing").(bool)
	userFacing := strconv.FormatBool(userFacingMetadataTag)
	protocol := "tcp"
	domain := d.Get("domain").(string)
	port := d.Get("frontend.0.port").(string)
	icon := d.Get("icon").(string)
	serviceAppType := "DATABASE"
	alp := d.Get("backend.0.target.0.port").(int)
	appListenPort := strconv.Itoa(alp)
	banyanProxyMode := "TCP"
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
		BanyanProxyMode: &banyanProxyMode,
		DescriptionLink: &descriptionLink,
	}
	return
}

func resourceServiceInfraDbUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating database service %s : %s", d.Get("name"), d.Id())
	resourceServiceInfraDbCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated database service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraDbRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] Reading database service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get database service with id: %s", id))
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
	d.Set("icon", service.CreateServiceSpec.Metadata.Tags.Icon)
	d.Set("description_link", service.CreateServiceSpec.Metadata.Tags.DescriptionLink)
	err = d.Set("frontend", flattenServiceFrontendAddresses(service.CreateServiceSpec.Spec.Attributes.FrontendAddresses))
	if err != nil {
		return diag.FromErr(err)
	}
	tlsSNI := removeFromSlice(service.CreateServiceSpec.Spec.Attributes.TLSSNI, *service.CreateServiceSpec.Metadata.Tags.Domain)
	err = d.Set("tls_sni", tlsSNI)
	if err != nil {
		return diag.FromErr(err)
	}
	backend, diagnostics := flattenInfraServiceBackend(service.CreateServiceSpec.Spec.Backend)
	if diagnostics.HasError() {
		return
	}
	err = d.Set("backend", backend)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("cert_settings", flattenInfraServiceCertSettings(service.CreateServiceSpec.Spec.CertSettings, *service.CreateServiceSpec.Metadata.Tags.Domain))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return
}

func resourceServiceInfraDbDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting database service with id: %q \n", d.Id())
	client := m.(*client.ClientHolder)
	err := client.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	log.Printf("[SERVICE|RES|DELETE] deleted database service with id: %q \n", d.Id())
	return
}
