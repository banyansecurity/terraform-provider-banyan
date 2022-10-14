package banyan

import (
	"context"
	"log"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceInfraDb() *schema.Resource {
	return &schema.Resource{
		Description:   "resourceServiceInfraDb",
		CreateContext: resourceServiceInfraDbCreate,
		ReadContext:   resourceServiceInfraDbRead,
		UpdateContext: resourceServiceInfraDbUpdate,
		DeleteContext: resourceServiceInfraDbDelete,
		Schema:        buildResourceServiceInfraDbSchema(),
	}
}

func buildResourceServiceInfraDbSchema() (schemaDb map[string]*schema.Schema) {
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

func DbSchema() (schemaDb map[string]*schema.Schema) {
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
	return
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

func resourceServiceInfraDbCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	created, err := c.Service.Create(DbFromState(d))
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(created.ServiceID)
	return resourceServiceInfraDbRead(ctx, d, m)
}

func expandDatabaseMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := "true"
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := ""
	serviceAppType := "DATABASE"
	descriptionLink := ""
	allowUserOverride := true
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

func resourceServiceInfraDbRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	resp, err := c.Service.Get(d.Id())
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(resp.ServiceID)
	err = d.Set("client_banyanproxy_allowed_domains", resp.CreateServiceSpec.Metadata.Tags.IncludeDomains)
	if err != nil {
		return diag.FromErr(err)
	}
	diagnostics = resourceServiceInfraCommonRead(c, resp, d)
	return
}

func resourceServiceInfraDbUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	resourceServiceInfraDbCreate(ctx, d, m)
	return
}

func resourceServiceInfraDbDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	diagnostics = resourceServiceInfraCommonDelete(d, m)
	log.Printf("[SERVICE|RES|DELETE] deleted database service %s : %s", d.Get("name"), d.Id())
	return
}
