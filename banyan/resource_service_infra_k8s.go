package banyan

import (
	"context"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceServiceInfraK8s() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of kubernetes services. For more information on kubernetes services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/k8s-api/)",
		CreateContext: resourceServiceInfraK8sCreate,
		ReadContext:   resourceServiceInfraK8sRead,
		UpdateContext: resourceServiceInfraK8sUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        K8sSchema(),
	}
}

func resourceServiceInfraK8sDepreciated() *schema.Resource {
	return &schema.Resource{
		Description:        "(Depreciated) Resource used for lifecycle management of kubernetes services. Please utilize `banyan_service_k8s` instead",
		CreateContext:      resourceServiceInfraK8sCreate,
		ReadContext:        resourceServiceInfraK8sReadDepreciated,
		UpdateContext:      resourceServiceInfraK8sUpdate,
		DeleteContext:      resourceServiceDelete,
		Schema:             K8sSchemaDepreciated(),
		DeprecationMessage: "This resource has been renamed and will be depreciated from the provider in a future release. Please migrate this resource to banyan_service_k8s",
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
	return combineSchema(s, resourceServiceInfraCommonSchema)
}

func K8sSchemaDepreciated() map[string]*schema.Schema {
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
		"cluster": {
			Type:        schema.TypeString,
			Description: "(Depreciated) Sets the cluster / shield for the service",
			Computed:    true,
			Optional:    true,
			Deprecated:  "This attribute is now configured automatically. This attribute will be removed in a future release of the provider.",
			ForceNew:    true,
		},
		"policy": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Policy ID to be attached to this service",
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

func resourceServiceInfraK8sCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	err := setCluster(d, m)
	if err != nil {
		return diag.FromErr(err)
	}
	svc := K8sFromState(d)
	diagnostics = resourceServiceCreate(svc, d, m)
	if diagnostics.HasError() {
		return diagnostics
	}
	return resourceServiceInfraK8sRead(ctx, d, m)
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
	err = d.Set("end_user_override", svc.CreateServiceSpec.Metadata.Tags.AllowUserOverride)
	if err != nil {
		return diag.FromErr(err)
	}
	return resourceServiceInfraCommonRead(svc, d, m)
}

func resourceServiceInfraK8sReadDepreciated(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
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
	diagnostics = resourceServiceInfraCommonRead(svc, d, m)
	// trick to allow this key to stay in the schema
	err = d.Set("policy", nil)
	return
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
	userFacing := strconv.FormatBool(d.Get("available_in_app").(bool))
	protocol := "tcp"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := d.Get("icon").(string)
	serviceAppType := "K8S"
	descriptionLink := d.Get("description_link").(string)
	allowUserOverride := d.Get("end_user_override").(bool)
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
	return
}
