package banyan

import (
	"context"
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

func TcpSchema() (schemaDb map[string]*schema.Schema) {
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

func TcpFromState(d *schema.ResourceData) (svc service.CreateService) {
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

func resourceServiceInfraTcpCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	svc := TcpFromState(d)
	newService, err := c.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create TCP service %s : %s", d.Get("name"), d.Id()))
	}
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
	resourceServiceInfraTcpCreate(ctx, d, m)
	return
}

func resourceServiceInfraTcpRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	id := d.Id()
	svc, err := c.Service.Get(id)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_banyanproxy_allowed_domains", svc.CreateServiceSpec.Metadata.Tags.IncludeDomains)
	if err != nil {
		return diag.FromErr(err)
	}
	diagnostics = resourceServiceInfraCommonRead(c, svc, d)
	return
}

func resourceServiceInfraTcpDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourceServiceInfraCommonDelete(d, m)
	d.SetId("")
	return
}
