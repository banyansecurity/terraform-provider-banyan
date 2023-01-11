package banyan

import (
	"context"
	"fmt"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceServiceInfraDb() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of database services. For more information on database services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/databases/)",
		CreateContext: resourceServiceInfraDbCreate,
		ReadContext:   resourceServiceInfraDbRead,
		UpdateContext: resourceServiceInfraDbUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        DbSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func DbSchema() map[string]*schema.Schema {
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
		"port": {
			Type:         schema.TypeInt,
			Optional:     true,
			Description:  "The external-facing port for this service",
			Default:      8443,
			ValidateFunc: validatePort(),
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
		"cluster": {
			Type:        schema.TypeString,
			Description: "(Depreciated) Sets the cluster / shield for the service",
			Computed:    true,
			Optional:    true,
			Deprecated:  "This attribute is now configured automatically. This attribute will be removed in a future release of the provider.",
			ForceNew:    true,
		},
		"client_banyanproxy_listen_port": {
			Type:         schema.TypeInt,
			Description:  "Sets the listen port of the service for the end user Banyan app",
			Optional:     true,
			ValidateFunc: validatePort(),
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
		"policy": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Policy ID to be attached to this service",
		},
		"end_user_override": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Allow the end user to override the backend_port for this service",
		},
	}
}

func resourceServiceInfraDbCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := DbFromState(d)
	diagnostics = resourceServiceCreate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	return resourceServiceInfraDbRead(ctx, d, m)
}

func resourceServiceInfraDbRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	svc, err := c.Service.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("client_banyanproxy_allowed_domains", svc.CreateServiceSpec.Metadata.Tags.IncludeDomains)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set(fmt.Sprintf("http_connect"), svc.CreateServiceSpec.Spec.Backend.HTTPConnect)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("end_user_override", svc.CreateServiceSpec.Metadata.Tags.AllowUserOverride)
	if err != nil {
		return diag.FromErr(err)
	}
	diagnostics = resourceServiceInfraCommonRead(svc, d, m)
	return
}

func resourceServiceInfraDbUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	svc := DbFromState(d)
	return resourceServiceUpdate(svc, d, m)
}

func DbFromState(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
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
	return
}

func expandDatabaseMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := strconv.FormatBool(d.Get("available_in_app").(bool))
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "DATABASE"
	descriptionLink := d.Get("description_link").(string)
	allowUserOverride := d.Get("end_user_override").(bool)
	banyanProxyMode := "TCP"
	if d.Get("http_connect").(bool) {
		banyanProxyMode = "CHAIN"
	}
	alpInt := d.Get("client_banyanproxy_listen_port").(int)
	appListenPort := strconv.Itoa(alpInt)
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
