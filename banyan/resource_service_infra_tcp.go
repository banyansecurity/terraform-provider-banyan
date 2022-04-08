package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
	"log"
	"strconv"
)

var resourceServiceInfraTcpSchema = map[string]*schema.Schema{
	"id": {
		Type:        schema.TypeString,
		Description: "Id of the service",
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
		Required:    true,
		Description: "Description of the service",
	},
	"cluster": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "Name of the cluster used for your deployment; for Global Edge set to \"global-edge\", for Private Edge set to \"cluster1\"",
		ForceNew:    true, //this is part of the id, meaning if you change the cluster name it will create a new service instead of updating it
	},
	"access_tier": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Name of the access_tier which will proxy requests to your service backend; set to \"\" if using Global Edge deployment'",
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
	"icon": {
		Type:     schema.TypeString,
		Optional: true,
	},
	"description_link": {
		Type:     schema.TypeString,
		Optional: true,
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
	"client_banyanproxy_listen_port": {
		Type:         schema.TypeInt,
		Optional:     true,
		Description:  "The external-facing port for this service",
		Default:      8443,
		ValidateFunc: validatePort(),
	},
	"allow_user_override": {
		Type:     schema.TypeBool,
		Optional: true,
		Default:  false,
	},
	"include_domains": {
		Type:     schema.TypeSet,
		Optional: true,
		Computed: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
	},
	"dns_override": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: `Backend DNS Override for Service Domain Name`,
		Elem:        &schema.Schema{Type: schema.TypeString},
	},
}

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceInfraTcp() *schema.Resource {
	return &schema.Resource{
		Description:   "This is an org wide setting. There can only be one of these per organization.",
		CreateContext: resourceServiceInfraTcpCreate,
		ReadContext:   resourceServiceInfraTcpRead,
		UpdateContext: resourceServiceInfraTcpUpdate,
		DeleteContext: resourceServiceInfraTcpDelete,
		Schema:        resourceServiceInfraTcpSchema,
	}
}

func resourceServiceInfraTcpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating TCP service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)

	svc := service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandTCPMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandInfraServiceSpec(d),
	}

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create TCP service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] Created TCP service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraTcpRead(ctx, d, m)
}

func expandTCPMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := "true"
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "GENERIC"
	alp := d.Get("client_banyanproxy_listen_port").(int)
	appListenPort := strconv.Itoa(alp)
	banyanProxyMode := "TCP"
	descriptionLink := d.Get("description_link").(string)
	allowUserOverride := d.Get("allow_user_override").(bool)
	includeDomains := convertSchemaSetToStringSlice(d.Get("include_domains").(*schema.Set))
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

func resourceServiceInfraTcpUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating TCP service %s : %s", d.Get("name"), d.Id())
	resourceServiceInfraTcpCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated TCP service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraTcpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|READ] reading TCP service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get TCP service with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	err = d.Set("backend_domain", service.CreateServiceSpec.Spec.Backend.Target.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("backend_http_connect", service.CreateServiceSpec.Spec.Backend.HTTPConnect)
	if err != nil {
		return diag.FromErr(err)
	}
	bpInt, _ := strconv.Atoi(service.CreateServiceSpec.Spec.Backend.Target.Port)
	err = d.Set("backend_port", bpInt)
	alpInt, _ := strconv.Atoi(service.CreateServiceSpec.Spec.Backend.Target.Port)
	err = d.Set("client_banyanproxy_listen_port", alpInt)
	diagnostics = resourceServiceInfraCommonRead(service, d, m)
	log.Printf("[SVC|RES|READ] read TCP service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraTcpDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SERVICE|RES|DELETE] deleting TCP service %s : %s", d.Get("name"), d.Id())
	diagnostics = resourceServiceInfraCommonDelete(d, m)
	log.Printf("[SERVICE|RES|DELETE] deleted TCP service %s : %s", d.Get("name"), d.Id())
	return
}
