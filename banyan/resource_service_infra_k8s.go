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
	"strings"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceInfraK8s() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of database services",
		CreateContext: resourceServiceInfraK8sCreate,
		ReadContext:   resourceServiceInfraK8sRead,
		UpdateContext: resourceServiceInfraK8sUpdate,
		DeleteContext: resourceServiceInfraK8sDelete,
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
			"client_kube_cluster_name": {
				Type:        schema.TypeString,
				Description: "Creates an entry in the Banyan KUBE config file under this name and populates the associated configuration parameters",
				Required:    true,
			},
			"client_kube_ca_key": {
				Type:        schema.TypeString,
				Description: "CA Public Key generated during Kube-OIDC-Proxy deployment",
				Required:    true,
			},
			"backend_dns_override_for_domain": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Override DNS for service domain name with this value",
			},
			"allow_user_override": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
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

func resourceServiceInfraK8sCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating kubernetes service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)

	svc := service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandK8sMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandk8sServiceSpec(d),
	}

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create kubernetes service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] created kubernetes service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraK8sRead(ctx, d, m)
}

func expandK8sMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacingMetadataTag := d.Get("user_facing").(bool)
	userFacing := strconv.FormatBool(userFacingMetadataTag)
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "K8S"
	alp := 8443
	appListenPort := strconv.Itoa(alp)
	banyanProxyMode := "CHAIN"
	descriptionLink := d.Get("description_link").(string)
	kubeClusterName := d.Get("client_kube_cluster_name").(string)
	kubeCaKey := d.Get("client_kube_ca_key").(string)
	allowUserOverride := d.Get("allow_user_override").(bool)

	metadatatags = service.Tags{
		Template:          &template,
		UserFacing:        &userFacing,
		Protocol:          &protocol,
		Domain:            &domain,
		Port:              &port,
		Icon:              &icon,
		ServiceAppType:    &serviceAppType,
		AppListenPort:     &appListenPort,
		BanyanProxyMode:   &banyanProxyMode,
		DescriptionLink:   &descriptionLink,
		KubeClusterName:   &kubeClusterName,
		KubeCaKey:         &kubeCaKey,
		AllowUserOverride: &allowUserOverride,
	}
	return
}

func resourceServiceInfraK8sRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|READ] reading kubernetes service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get kubernetes service with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	d.Set("client_kube_cluster_name", service.CreateServiceSpec.Metadata.Tags.KubeClusterName)
	d.Set("client_kube_ca_key", service.CreateServiceSpec.Metadata.Tags.KubeCaKey)
	diagnostics = resourceServiceInfraCommonRead(service, d, m)
	log.Printf("[SVC|RES|READ] read kubernetes service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraK8sUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating kubernetes service %s : %s", d.Get("name"), d.Id())
	resourceServiceInfraK8sCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated kubernetes service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraK8sDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting kubernetes service %s : %s", d.Get("name"), d.Id())
	diagnostics = resourceServiceInfraCommonDelete(d, m)
	log.Printf("[SERVICE|RES|DELETE] deleted kubernetes service %s : %s", d.Get("name"), d.Id())
	return
}

func expandk8sServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	spec = service.Spec{
		Attributes:   expandk8sAttributes(d),
		Backend:      expandk8sBackend(d),
		CertSettings: expandk8sCertSettings(d),
		HTTPSettings: service.HTTPSettings{},
		ClientCIDRs:  []service.ClientCIDRs{},
		TagSlice:     service.TagSlice{},
	}
	return
}

func expandk8sAttributes(d *schema.ResourceData) (attributes service.Attributes) {
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
		FrontendAddresses: expandk8sFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandk8sBackend(d *schema.ResourceData) (backend service.Backend) {
	var allowPatterns []service.BackendAllowPattern
	hostnames := []string{d.Get("domain").(string)}
	allowPatterns = append(allowPatterns, service.BackendAllowPattern{
		Hostnames: hostnames,
		CIDRs:     nil,
		Ports:     service.BackendAllowPorts{},
	})
	dnsOverride := make(map[string]string)
	dnsOverride[d.Get("domain").(string)] = d.Get("backend_dns_override_for_domain").(string)
	backend = service.Backend{
		AllowPatterns: allowPatterns,
		DNSOverrides:  dnsOverride,
		ConnectorName: d.Get("connector").(string),
		HTTPConnect:   true,
		Target:        expandk8sTarget(d),
		Whitelist:     []string{},
	}
	return
}

func expandk8sTarget(d *schema.ResourceData) (target service.Target) {
	return service.Target{
		Name:              "",
		Port:              "",
		TLS:               false,
		TLSInsecure:       false,
		ClientCertificate: false,
	}
}

func expandk8sFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
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

func expandk8sCertSettings(d *schema.ResourceData) (certSettings service.CertSettings) {
	dnsNames := []string{d.Get("domain").(string)}
	customTLSCert := service.CustomTLSCert{
		Enabled:  false,
		CertFile: "",
		KeyFile:  "",
	}
	m := d.Get("cert_settings").([]interface{})
	if len(m) >= 1 {
		itemMap := m[0].(map[string]interface{})
		for _, d := range convertSchemaSetToStringSlice(itemMap["dns_names"].(*schema.Set)) {
			dnsNames = append(dnsNames, d)
		}
		dnsNames = removeDuplicateStr(dnsNames)
		customTLSCert = service.CustomTLSCert{}
	}

	certSettings = service.CertSettings{
		DNSNames:      dnsNames,
		CustomTLSCert: customTLSCert,
		Letsencrypt:   false,
	}
	return
}
