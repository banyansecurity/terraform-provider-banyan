package banyan

import (
	"context"
	"fmt"
	"log"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/pkg/errors"
)

func resourceServiceInfraRdp() *schema.Resource {
	return &schema.Resource{
		Description:   "resourceServiceInfraRdp",
		CreateContext: resourceServiceInfraRdpCreate,
		ReadContext:   resourceServiceInfraRdpRead,
		UpdateContext: resourceServiceInfraRdpUpdate,
		DeleteContext: resourceServiceInfraRdpDelete,
		Schema:        resourceServiceInfraCommonSchema,
	}
}

func resourceServiceInfraRdpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating RDP service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	svc := expandRDPCreateService(d)

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create RDP service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] Created RDP service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraRdpRead(ctx, d, m)
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
		if schemaRdp[key] == nil {
			schemaRdp[key] = val
		}
	}
	return
}

func expandRDPCreateService(d *schema.ResourceData) (svc service.CreateService) {
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
	if d.Get("http_connect").(bool) {
		banyanProxyMode = "RDPGATEWAY"
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
	log.Printf("[SVC|RES|UPDATE] updating RDP service %s : %s", d.Get("name"), d.Id())
	resourceServiceInfraRdpCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated RDP service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraRdpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] Reading RDP service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get database service with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
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
