package banyan

import (
	"context"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceTcp() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of generic TCP services. For more information on generic TCP services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/tcp-services/)",
		CreateContext: resourceServiceInfraTcpCreate,
		ReadContext:   resourceServiceInfraTcpRead,
		UpdateContext: resourceServiceInfraTcpUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        TcpSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func TcpSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"id": {
			Type:        schema.TypeString,
			Description: "Id of the service in Banyan",
			Computed:    true,
		},
		"name": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the service; use lowercase alphanumeric characters or \"-\"",
			ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
		},
		"description": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Description of the service",
		},
		"description_link": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Link shown to the end user of the banyan app for this service",
		},
		"autorun": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Autorun for the service, if set true service would autorun on the app",
		},
		"access_tier": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Name of the access_tier which will proxy requests to your service backend",
			Default:       "",
			ConflictsWith: []string{"connector"},
		},
		"connector": {
			Type:          schema.TypeString,
			Optional:      true,
			Description:   "Name of the connector which will proxy requests to your service backend",
			Default:       "",
			ConflictsWith: []string{"access_tier"},
		},
		"domain": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The external-facing network address for this service; ex. website.example.com",
		},
		"suppress_device_trust_verification": {
			Type:        schema.TypeBool,
			Description: "suppress_device_trust_verification disables Device Trust Verification for a service if set to true",
			Optional:    true,
			Default:     false,
		},
		"backend_domain": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "The internal network address where this service is hosted; ex. 192.168.1.2; set to \"\" if using http_connect",
		},
		"backend_port": {
			Type:         schema.TypeInt,
			Required:     true,
			Description:  "The internal port where this service is hosted; set to 0 if using http_connect",
			ValidateFunc: validatePort(),
		},
		"port": {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "The external-facing port for this service",
			Default:      8443,
			ValidateFunc: validatePort(),
		},
		"available_in_app": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Whether this service is available in the app for users with permission to access this service",
		},
		"icon": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "Name of the icon which will be displayed to the end user. The icon names can be found in the UI in the service config",
		},
		"disable_private_dns": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "By default, Private DNS Override will be set to true i.e disable_private_dns is false. On the device, the domain name will resolve over the service tunnel to the correct Access Tier's public IP address. If you turn off Private DNS Override i.e. disable_private_dns is set to true, you need to explicitly set a private DNS entry for the service domain name.",
		},
		"policy": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Policy ID to be attached to this service",
		},
		"cluster": {
			Type:        schema.TypeString,
			Description: "(Depreciated) Sets the cluster / shield for the service",
			Computed:    true,
			Optional:    true,
			Deprecated:  "This attribute is now configured automatically. This attribute will be removed in a future release of the provider.",
			ForceNew:    true,
		},
		"backend_dns_override_for_domain": {
			Type:        schema.TypeString,
			Description: "Override DNS for service domain name with this value",
			Optional:    true,
		},
		"client_banyanproxy_listen_port": {
			Type:        schema.TypeString,
			Description: "Sets the listen port of the service for the end user Banyan app",
			Optional:    true,
		},
		"client_banyanproxy_allowed_domains": {
			Type:        schema.TypeSet,
			Description: "Restrict which domains can be proxied through the banyanproxy; only used with Client Specified connectivity",
			Optional:    true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},
		"http_connect": {
			Type:        schema.TypeBool,
			Description: "Indicates to use HTTP Connect request to derive the backend target address.",
			Optional:    true,
			Default:     false,
		},
		"allow_patterns": {
			Type:     schema.TypeSet,
			MaxItems: 1,
			Optional: true,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"cidrs": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"hostnames": {
						Type:     schema.TypeList,
						Optional: true,
						Elem: &schema.Schema{
							Type: schema.TypeString,
						},
					},
					"ports": {
						Type:     schema.TypeSet,
						Optional: true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"port_list": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Schema{
										Type: schema.TypeInt,
									},
								},
								"port_range": {
									Type:     schema.TypeList,
									Optional: true,
									Elem: &schema.Resource{
										Schema: map[string]*schema.Schema{
											"min": {
												Type:     schema.TypeInt,
												Required: true,
											},
											"max": {
												Type:     schema.TypeInt,
												Required: true,
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
		"end_user_override": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Allow the end user to override the backend_port for this service",
		},
		"policy_enforcing": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "mode in which policy should be. If this is true policy is in enforcing mode else policy is in Permissive mode",
		},
	}
}

func resourceServiceInfraTcpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := TcpFromState(d)
	diagnostics = resourceServiceCreate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	return resourceServiceInfraTcpRead(ctx, d, m)
}

func resourceServiceInfraTcpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	id := d.Id()
	svc, err := c.Service.Get(id)
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	domain := *svc.CreateServiceSpec.Metadata.Tags.Domain
	override := svc.CreateServiceSpec.Spec.Backend.BackendDNSOverrides[domain]
	err = d.Set("backend_dns_override_for_domain", override)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_banyanproxy_allowed_domains", svc.CreateServiceSpec.Metadata.Tags.IncludeDomains)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("end_user_override", svc.CreateServiceSpec.Metadata.Tags.AllowUserOverride)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("http_connect", svc.CreateServiceSpec.Spec.HttpConnect)
	if err != nil {
		return diag.FromErr(err)
	}
	if svc.CreateServiceSpec.Spec.HttpConnect {
		err = d.Set("backend_domain", "")
		if err != nil {
			return diag.FromErr(err)
		}
		err = d.Set("backend_port", 0)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	allowPatterns, err := flattenAllowPatterns(svc.CreateServiceSpec.Spec.HttpConnect, svc.CreateServiceSpec.Spec.BackendAllowPatterns)
	if err != nil {
		return diag.FromErr(err)
	}
	if len(allowPatterns) > 0 {
		err = d.Set("allow_patterns", allowPatterns)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	diagnostics = resourceServiceInfraCommonRead(svc, d, m)
	return
}

func resourceServiceInfraTcpUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	svc := TcpFromState(d)
	diagnostics = resourceServiceUpdate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	diagnostics = resourceServiceInfraTcpRead(ctx, d, m)
	return
}

func TcpFromState(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandTCPMetatdataTags(d),
			Autorun:     expandAutorun(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandInfraServiceSpec(d),
	}
	return
}

func expandTCPMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := strconv.FormatBool(d.Get("available_in_app").(bool))
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "GENERIC"
	descriptionLink := d.Get("description_link").(string)
	allowUserOverride := d.Get("end_user_override").(bool)
	banyanProxyMode := "TCP"
	if d.Get("http_connect").(bool) {
		banyanProxyMode = "CHAIN"
	}
	alp := d.Get("client_banyanproxy_listen_port")
	appListenPort := ""
	if alp != nil {
		appListenPort = alp.(string)
	}
	includeDomains := convertSchemaSetToStringSlice(d.Get("client_banyanproxy_allowed_domains").(*schema.Set))
	if includeDomains == nil {
		includeDomains = []string{}
	}
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
		AllowUserOverride: &allowUserOverride,
		IncludeDomains:    &includeDomains,
	}
	return
}
