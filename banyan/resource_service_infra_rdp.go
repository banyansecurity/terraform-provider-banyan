package banyan

import (
	"context"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceServiceInfraRdp() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of microsoft remote desktop services. For more information on microsoft remote desktop services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/rdp-servers/)",
		CreateContext: resourceServiceInfraRdpCreate,
		ReadContext:   resourceServiceInfraRdpRead,
		UpdateContext: resourceServiceInfraRdpUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        RdpSchema(),
	}
}

func resourceServiceInfraRdpDepreciated() *schema.Resource {
	return &schema.Resource{
		Description:        "(Depreciated) Resource used for lifecycle management of microsoft remote desktop services. Please utilize `banyan_service_rdp` instead",
		CreateContext:      resourceServiceInfraRdpCreate,
		ReadContext:        resourceServiceInfraRdpReadDepreciated,
		UpdateContext:      resourceServiceInfraRdpUpdate,
		DeleteContext:      resourceServiceDelete,
		Schema:             RdpSchemaDepreciated(),
		DeprecationMessage: "This resource has been renamed and will be depreciated from the provider in a future release. Please migrate this resource to banyan_service_rdp",
	}
}

func RdpSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
		"policy": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Policy ID to be attached to this service",
		},
		"http_connect": {
			Type:        schema.TypeBool,
			Description: "Indicates whether to use HTTP Connect request to derive the backend target address. Set to true for an RDP gateway",
			Optional:    true,
			Default:     false,
		},
		"end_user_override": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Allow the end user to override the backend_port for this service",
		},
	}
	return combineSchema(s, resourceServiceInfraCommonSchema)
}

func RdpSchemaDepreciated() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
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
		"http_connect": {
			Type:        schema.TypeBool,
			Description: "Indicates whether to use HTTP Connect request to derive the backend target address. Set to true for an RDP gateway",
			Optional:    true,
			Default:     false,
		},
		"end_user_override": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Allow the end user to override the backend_port for this service",
		},
	}
	return combineSchema(s, resourceServiceInfraCommonSchema)
}

func resourceServiceInfraRdpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := RdpFromState(d)
	diagnostics = resourceServiceCreate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	return resourceServiceInfraRdpRead(ctx, d, m)
}

func resourceServiceInfraRdpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	svc, err := c.Service.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	err = d.Set("end_user_override", svc.CreateServiceSpec.Metadata.Tags.AllowUserOverride)
	if err != nil {
		return diag.FromErr(err)
	}
	return resourceServiceInfraCommonRead(svc, d, m)
}

func resourceServiceInfraRdpReadDepreciated(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	svc, err := c.Service.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	diagnostics = resourceServiceInfraCommonRead(svc, d, m)
	// trick to allow this key to stay in the schema
	err = d.Set("policy", nil)
	return
}

func resourceServiceInfraRdpUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	svc := RdpFromState(d)
	return resourceServiceUpdate(svc, d, m)
}

func RdpFromState(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
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
	return
}

func expandRDPMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := strconv.FormatBool(d.Get("available_in_app").(bool))
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "RDP"
	descriptionLink := d.Get("description_link").(string)
	allowUserOverride := d.Get("end_user_override").(bool)
	banyanProxyMode := "TCP"
	httpConnect, ok := d.GetOk("http_connect")
	if ok {
		if httpConnect.(bool) {
			banyanProxyMode = "RDPGATEWAY"
		}
	}
	alpInt := d.Get("client_banyanproxy_listen_port").(int)
	appListenPort := strconv.Itoa(alpInt)
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
