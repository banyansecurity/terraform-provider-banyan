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

func resourceServiceInfraRdp() *schema.Resource {
	return &schema.Resource{
		Description:   "resourceServiceInfraRdp",
		CreateContext: resourceServiceInfraRdpCreate,
		ReadContext:   resourceServiceInfraRdpRead,
		UpdateContext: resourceServiceInfraRdpUpdate,
		DeleteContext: resourceServiceInfraRdpDelete,
		Schema:        buildResourceServiceInfraRdpSchema(),
	}
}

func buildResourceServiceInfraRdpSchema() (schemaRdp map[string]*schema.Schema) {
	schemaRdp = map[string]*schema.Schema{
		"http_connect": {
			Type:        schema.TypeBool,
			Description: "Indicates to use HTTP Connect request to derive the backend target address.",
			Optional:    true,
			Default:     false,
		},
	}
	for key, val := range resourceServiceInfraCommonSchema {
		if schemaRdp[key] == nil {
			schemaRdp[key] = val
		}
	}
	return
}

func RdpSchema(prefix string) (schemaRdp map[string]*schema.Schema) {
	schemaRdp = map[string]*schema.Schema{
		fmt.Sprintf("%shttp_connect", prefix): {
			Type:        schema.TypeBool,
			Description: "Indicates to use HTTP Connect request to derive the backend target address.",
			Optional:    true,
			Default:     false,
		},
	}
	return
}

func resourceServiceInfraRdpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	svc := RdpFromState(d, "")

	newService, err := c.Service.Create(svc)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(newService.ServiceID)
	return resourceServiceInfraRdpRead(ctx, d, m)
}

func RdpFromState(d *schema.ResourceData, prefix string) (svc service.CreateService) {
	svc = service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandRDPMetatdataTags(d, prefix),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandInfraServiceSpec(d),
	}
	return
}

func expandRDPMetatdataTags(d *schema.ResourceData, prefix string) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := "true"
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := ""
	serviceAppType := "RDP"
	descriptionLink := ""
	allowUserOverride := true
	banyanProxyMode := "TCP"
	_, ok := d.GetOk(fmt.Sprintf("%shttp_connect", prefix))
	if ok {
		if d.Get(fmt.Sprintf("%shttp_connect", prefix)).(bool) {
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

func resourceServiceInfraRdpUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	resourceServiceInfraRdpCreate(ctx, d, m)
	return
}

func resourceServiceInfraRdpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	id := d.Id()
	svc, err := c.Service.Get(id)
	handleNotFoundError(d, id, err)
	diagnostics = resourceServiceInfraCommonRead(c, svc, d)
	d.SetId(id)
	return
}

func resourceServiceInfraRdpDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourceServiceInfraCommonDelete(d, m)
	d.SetId("")
	return
}
