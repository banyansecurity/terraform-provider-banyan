package banyan

import (
	"context"
	"strconv"

	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceServiceK8s() *schema.Resource {
	return &schema.Resource{
		Description:   "Resource used for lifecycle management of kubernetes services. For more information on kubernetes services see the [documentation](https://docs.banyansecurity.io/docs/feature-guides/infrastructure/k8s-api/)",
		CreateContext: resourceServiceInfraK8sCreate,
		ReadContext:   resourceServiceInfraK8sRead,
		UpdateContext: resourceServiceInfraK8sUpdate,
		DeleteContext: resourceServiceDelete,
		Schema:        K8sSchema(),
		Importer: &schema.ResourceImporter{
			StateContext: schema.ImportStatePassthroughContext,
		},
	}
}

func K8sSchema() map[string]*schema.Schema {
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
		"autorun": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Autorun for the service, if set true service would autorun on the app",
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
		"policy": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: "Policy ID to be attached to this service",
		},
		"client_banyanproxy_listen_port": {
			Type:         schema.TypeInt,
			Description:  "Sets the listen port of the service for the end user Banyan app",
			Optional:     true,
			ValidateFunc: validatePort(),
		},
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
		"end_user_override": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     true,
			Description: "Allow the end user to override the backend_port for this service",
		},
	}
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
			Autorun:     extractAutorun(d),
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

// cannot use expandK8sServiceSpec for k8s services due to http_connect always required
func expandK8sServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	attributes, err := expandK8sAttributes(d)
	if err != nil {
		return
	}
	spec = service.Spec{
		Attributes:   attributes,
		Backend:      expandK8sBackend(d),
		CertSettings: expandInfraCertSettings(d),
		HTTPSettings: expandInfraHTTPSettings(d),
		ClientCIDRs:  []service.ClientCIDRs{},
	}
	return
}

func expandK8sAttributes(d *schema.ResourceData) (attributes service.Attributes, err error) {
	hostTagSelector, err := buildHostTagSelector(d)
	if err != nil {
		return
	}
	attributes = service.Attributes{
		TLSSNI:            []string{d.Get("domain").(string)},
		FrontendAddresses: expandK8sFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandK8sFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
	frontendAddresses = []service.FrontendAddress{
		{
			CIDR: "",
			Port: strconv.Itoa(d.Get("port").(int)),
		},
	}
	return
}

func expandK8sBackend(d *schema.ResourceData) (backend service.Backend) {
	domain := d.Get("domain").(string)
	backendOverride := d.Get("backend_dns_override_for_domain").(string)
	allowPatterns := []service.BackendAllowPattern{
		{
			Hostnames: []string{domain},
		},
	}
	backend = service.Backend{
		Target: expandK8sTarget(d),
		// required for k8s services
		HTTPConnect:   true,
		ConnectorName: d.Get("connector").(string),
		DNSOverrides: map[string]string{
			domain: backendOverride,
		},
		AllowPatterns: allowPatterns,
		Whitelist:     []string{}, // deprecated
	}
	return
}

func expandK8sTarget(d *schema.ResourceData) (target service.Target) {
	// if http_connect, need to set Name to "" and Port to ""
	return service.Target{
		Name:              "",
		Port:              "",
		TLS:               false,
		TLSInsecure:       false,
		ClientCertificate: false,
	}
}
