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
func resourceServiceInfraK8s() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of k8s services",
		CreateContext: resourceServiceInfraK8sCreate,
		ReadContext:   resourceServiceInfraK8sRead,
		UpdateContext: resourceServiceInfraK8sUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        K8sSchema(),
	}
}

func K8sSchema() map[string]*schema.Schema {
	s := map[string]*schema.Schema{
		"backend_dns_override_for_domain": {
			Type:        schema.TypeString,
			Description: "Override DNS for service domain name with this value",
			Optional:    true,
		},
		"client_kube_cluster_name": {
			Type:        schema.TypeString,
			Description: "Creates an entry in the Banyan KUBE config file under this name and populates the associated configuration parameters",
			Optional:    true,
		},
		"client_kube_ca_key": {
			Type:        schema.TypeString,
			Description: "CA Public Key generated during Kube-OIDC-Proxy deployment",
			Optional:    true,
		},
	}
	return combineSchema(s, resourceServiceInfraCommonSchema)
}

func resourceServiceInfraK8sCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := K8sFromState(d)
	return resourceServiceCreate(svc, d, m)
}

func resourceServiceInfraK8sRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	svc, err := c.Service.Get(d.Id())
	if err != nil {
		handleNotFoundError(d, err)
		return
	}
	domain := *svc.CreateServiceSpec.Metadata.Tags.Domain
	override := svc.CreateServiceSpec.Spec.Backend.DNSOverrides[domain]
	err = d.Set("backend_dns_override_for_domain", override)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_kube_cluster_name", svc.CreateServiceSpec.Metadata.Tags.KubeClusterName)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("client_kube_ca_key", svc.CreateServiceSpec.Metadata.Tags.KubeCaKey)
	if err != nil {
		return diag.FromErr(err)
	}
	return resourceServiceInfraCommonRead(svc, d, m)
}

func resourceServiceInfraK8sUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	svc := K8sFromState(d)
	return resourceServiceUpdate(svc, d, m)
}

func K8sFromState(d *schema.ResourceData) (svc service.CreateService) {
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
	banyanProxyMode := "CHAIN"
	alpInt := d.Get("client_banyanproxy_listen_port").(int)
	appListenPort := strconv.Itoa(alpInt)
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
		AppListenPort:     &appListenPort,
		BanyanProxyMode:   &banyanProxyMode,
		KubeClusterName:   &kubeClusterName,
		KubeCaKey:         &kubeCaKey,
	}
	return
}

// cannot use expandInfraServiceSpec for k8s services
func expandK8sServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	spec = expandInfraServiceSpec(d)
	domain := d.Get("domain").(string)
	backendOverride := d.Get("backend_dns_override_for_domain").(string)
	spec.Backend.DNSOverrides = map[string]string{
		domain: backendOverride,
	}
	allowPatterns := []service.BackendAllowPattern{
		{
			Hostnames: []string{domain},
		},
	}
	spec.Backend.AllowPatterns = allowPatterns
	// force these for http_connect which is required for k8s
	spec.Backend.HTTPConnect = true
	spec.Backend.Target.Port = ""
	return
}
