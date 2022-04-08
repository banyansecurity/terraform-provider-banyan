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
func resourceServiceInfraK8s() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of database services",
		CreateContext: resourceServiceInfraK8sCreate,
		ReadContext:   resourceServiceInfraK8sRead,
		UpdateContext: resourceServiceInfraK8sUpdate,
		DeleteContext: resourceServiceInfraK8sDelete,
		Schema:        buildResourceServiceInfraK8sSchema(),
	}
}

func buildResourceServiceInfraK8sSchema() (schemaK8s map[string]*schema.Schema) {
	schemaK8s = map[string]*schema.Schema{
		"backend_http_connect": {
			Type:        schema.TypeBool,
			Description: "For K8S, we use Client Specified connectivity",
			Computed:    true,
			Default:     true,
		},
		"backend_domain": {
			Type:        schema.TypeString,
			Description: "For K8S, we use Client Specified connectivity",
			Computed:    true,
			Default:     "",
		},
		"backend_port": {
			Type:        schema.TypeInt,
			Description: "For K8S, we use Client Specified connectivity",
			Computed:    true,
			Default:     "",
		},
		"backend_dns_override_for_domain": {
			Type:        schema.TypeString,
			Description: "Override DNS for service domain name with this value",
			Required:    true,
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
	}
	for key, val := range resourceServiceInfraCommonSchema {
		if schemaK8s[key] == nil {
			schemaK8s[key] = val
		}
	}
	return
}

func resourceServiceInfraK8sCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	log.Printf("[SVC|RES|CREATE] creating kubernetes service %s : %s", d.Get("name"), d.Id())
	client := m.(*client.ClientHolder)
	svc := expandK8sCreateService(d)

	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(errors.WithMessagef(err, "could not create kubernetes service %s : %s", d.Get("name"), d.Id()))
	}
	log.Printf("[SVC|RES|CREATE] created kubernetes service %s : %s", d.Get("name"), d.Id())
	d.SetId(newService.ServiceID)
	return resourceServiceInfraK8sRead(ctx, d, m)
}

func expandK8sCreateService(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandK8sMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandK8sServiceSpec(d),
	}
	return
}

func expandK8sMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "TCP_USER"
	userFacing := "true"
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := ""
	serviceAppType := "K8S"
	descriptionLink := ""
	allowUserOverride := true

	alpInt := d.Get("client_banyanproxy_listen_port").(int)
	appListenPort := strconv.Itoa(alpInt)
	banyanProxyMode := "CHAIN"
	kubeClusterName := d.Get("client_kube_cluster_name").(string)
	kubeCaKey := d.Get("client_kube_ca_key").(string)

	metadatatags = service.Tags{
		Template:          &template,
		UserFacing:        &userFacing,
		Protocol:          &protocol,
		Domain:            &domain,
		Port:              &port,
		Icon:              &icon,
		ServiceAppType:    &serviceAppType,
		DescriptionLink:   &descriptionLink,
		AllowUserOverride: &allowUserOverride,

		AppListenPort:   &appListenPort,
		BanyanProxyMode: &banyanProxyMode,
		KubeClusterName: &kubeClusterName,
		KubeCaKey:       &kubeCaKey,
	}
	return
}

func expandK8sServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	spec = expandInfraServiceSpec(d)

	domain := d.Get("domain").(string)
	backend_override := d.Get("backend_dns_override_for_domain").(string)

	spec.Backend.DNSOverrides = map[string]string{
		domain: backend_override,
	}
	spec.Backend.AllowPatterns[0].Hostnames = []string{domain}
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
