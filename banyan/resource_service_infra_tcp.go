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

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceInfraTcp() *schema.Resource {
	return &schema.Resource{
		Description:   "resourceServiceInfraTcp",
		CreateContext: resourceServiceInfraTcpCreate,
		ReadContext:   resourceServiceInfraTcpRead,
		UpdateContext: resourceServiceInfraTcpUpdate,
		DeleteContext: resourceServiceInfraTcpDelete,
		Schema:        buildResourceServiceInfraTcpSchema(),
	}
}

func buildResourceServiceInfraTcpSchema() (schemaDb map[string]*schema.Schema) {
	schemaDb = map[string]*schema.Schema{
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
	}
	for key, val := range resourceServiceInfraCommonSchema {
		if schemaDb[key] == nil {
			schemaDb[key] = val
		}
	}
	return
}

func resourceServiceInfraTcpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating TCP service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	svc := expandTcpCreateService(d)

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create TCP service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] Created TCP service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraTcpRead(ctx, d, m)
}

func expandTcpCreateService(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
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
	return
}

func expandTCPMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := "true"
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := ""
	serviceAppType := "GENERIC"
	descriptionLink := ""
	allowUserOverride := true

	banyanProxyMode := "TCP"
	if d.Get("http_connect").(bool) {
		banyanProxyMode = "CHAIN"
	}
	alp := d.Get("client_banyanproxy_listen_port").(int)
	appListenPort := strconv.Itoa(alp)
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

func resourceServiceInfraTcpUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|UPDATE] updating TCP service %s : %s", d.Get("name"), d.Id())
	resourceServiceInfraTcpCreate(ctx, d, m)
	log.Printf("[SVC|RES|UPDATE] updated TCP service %s : %s", d.Get("name"), d.Id())
	return
}

func resourceServiceInfraTcpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|READ] reading TCP service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.Holder)
	id := d.Id()
	service, ok, err := client.Service.Get(id)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "couldn't get TCP service with id: %s", id))
	}
	if !ok {
		return handleNotFoundError(d, fmt.Sprintf("service %q", d.Id()))
	}
	err = d.Set("client_banyanproxy_allowed_domains", service.CreateServiceSpec.Metadata.Tags.IncludeDomains)
	if err != nil {
		return diag.FromErr(err)
	}
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
