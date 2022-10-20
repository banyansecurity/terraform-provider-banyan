package banyan

import (
	"context"
	"fmt"
	"github.com/banyansecurity/terraform-banyan-provider/client"
	"github.com/banyansecurity/terraform-banyan-provider/client/service"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"strconv"
)

// Schema for the service resource. For more information on Banyan services, see the documentation
func resourceServiceWeb() *schema.Resource {
	return &schema.Resource{
		Description:   "resourceServiceWeb",
		CreateContext: resourceServiceWebCreate,
		ReadContext:   resourceServiceWebRead,
		UpdateContext: resourceServiceWebUpdate,
		DeleteContext: resourceServiceWebDelete,
		Schema:        resourceServiceWebSchema,
	}
}

var resourceServiceWebSchema = map[string]*schema.Schema{
	"id": {
		Type:        schema.TypeString,
		Description: "Id of the service",
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
		Default:     "resourceServiceWeb",
	},
	"cluster": {
		Type:        schema.TypeString,
		Optional:    true,
		Computed:    true,
		Description: "Sets the cluster / shield of the service",
		ForceNew:    true,
	},
	"access_tier": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Name of the access_tier which will proxy requests to your service backend; set to \"\" if using Global Edge deployment'",
		Default:     "",
	},
	"connector": {
		Type:        schema.TypeString,
		Optional:    true,
		Description: "Name of the connector which will proxy requests to your service backend; set to \"\" if using Private Edge deployment",
		Default:     "",
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
		Default:      443,
		ValidateFunc: validatePort(),
	},
	"letsencrypt": {
		Type:        schema.TypeBool,
		Description: "Use a Public CA-issued server certificate instead of a Private CA-issued one",
		Optional:    true,
		Default:     false,
	},
	"backend_domain": {
		Type:        schema.TypeString,
		Required:    true,
		Description: "The internal network address where this service is hosted; ex. 192.168.1.2; set to \"\" if using http_connect",
	},
	"backend_port": {
		Type:         schema.TypeInt,
		Required:     true,
		Description:  "The internal port where this service is hosted",
		ValidateFunc: validatePort(),
	},
	"backend_tls": {
		Type:        schema.TypeBool,
		Description: "Indicates whether the connection to the backend server uses TLS",
		Optional:    true,
		Default:     false,
	},
	"backend_tls_insecure": {
		Type:        schema.TypeBool,
		Description: "Indicates the connection to the backend should not validate the backend server TLS certificate",
		Optional:    true,
		Default:     false,
	},
}

func WebSchema() (s map[string]*schema.Schema) {
	s = map[string]*schema.Schema{
		"letsencrypt": {
			Type:        schema.TypeBool,
			Description: "Use a Public CA-issued server certificate instead of a Private CA-issued one",
			Optional:    true,
			Default:     false,
		},
		"backend_tls": {
			Type:        schema.TypeBool,
			Description: "Indicates whether the connection to the backend server uses TLS",
			Optional:    true,
			Default:     false,
		},
		"backend_tls_insecure": {
			Type:        schema.TypeBool,
			Description: "Indicates the connection to the backend should not validate the backend server TLS certificate",
			Optional:    true,
			Default:     false,
		},
	}
	return
}

func resourceServiceWebCreate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.Holder)
	svc := WebFromState(d)
	newService, err := client.Service.Create(svc)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(newService.ServiceID)
	return resourceServiceWebRead(ctx, d, m)
}

func resourceServiceWebRead(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	c := m.(*client.Holder)
	id := d.Id()
	resp, err := c.Service.Get(id)
	handleNotFoundError(d, resp.ServiceID, err)
	err = d.Set("name", resp.ServiceName)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("description", resp.Description)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = d.Set("cluster", resp.ClusterName)
	if err != nil {
		diagnostics = diag.FromErr(err)
		return
	}
	err = SetAccessTier(d, resp, diagnostics)
	err = d.Set("connector", resp.CreateServiceSpec.Spec.Backend.ConnectorName)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("domain", resp.CreateServiceSpec.Metadata.Tags.Domain)
	if err != nil {
		return diag.FromErr(err)
	}
	portVal := *resp.CreateServiceSpec.Metadata.Tags.Port
	portInt, _ := strconv.Atoi(portVal)
	err = d.Set("port", portInt)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("letsencrypt", resp.CreateServiceSpec.Spec.CertSettings.Letsencrypt)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("backend_domain", resp.CreateServiceSpec.Spec.Backend.Target.Name)
	if err != nil {
		return diag.FromErr(err)
	}
	bpInt, _ := strconv.Atoi(resp.CreateServiceSpec.Spec.Backend.Target.Port)
	err = d.Set("backend_port", bpInt)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("backend_tls", resp.CreateServiceSpec.Spec.Backend.Target.TLS)
	if err != nil {
		return diag.FromErr(err)
	}
	err = d.Set("backend_tls_insecure", resp.CreateServiceSpec.Spec.Backend.Target.TLSInsecure)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(id)
	return
}

func resourceServiceWebUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	resourceServiceWebCreate(ctx, d, m)
	return
}

func resourceServiceWebDelete(ctx context.Context, d *schema.ResourceData, m interface{}) (diagnostics diag.Diagnostics) {
	client := m.(*client.Holder)
	diagnostics = resourceServiceDetachPolicy(d, m)
	if diagnostics.HasError() {
		return
	}
	err := client.Service.Delete(d.Id())
	if err != nil {
		diagnostics = diag.FromErr(err)
	}
	d.SetId("")
	return
}

func WebFromState(d *schema.ResourceData) (svc service.CreateService) {
	svc = service.CreateService{
		Metadata: service.Metadata{
			Name:        d.Get("name").(string),
			Description: d.Get("description").(string),
			ClusterName: d.Get("cluster").(string),
			Tags:        expandWebMetatdataTags(d),
		},
		Kind:       "BanyanService",
		APIVersion: "rbac.banyanops.com/v1",
		Type:       "origin",
		Spec:       expandWebServiceSpec(d),
	}
	return
}

func expandWebMetatdataTags(d *schema.ResourceData) (metadatatags service.Tags) {
	template := "WEB_USER"
	userFacing := "true"
	protocol := "https"
	domain := d.Get("domain").(string)
	portInt := d.Get("port").(int)
	port := strconv.Itoa(portInt)
	icon := ""
	serviceAppType := "WEB"
	descriptionLink := ""

	metadatatags = service.Tags{
		Template:        &template,
		UserFacing:      &userFacing,
		Protocol:        &protocol,
		Domain:          &domain,
		Port:            &port,
		Icon:            &icon,
		ServiceAppType:  &serviceAppType,
		DescriptionLink: &descriptionLink,
	}
	return
}

func expandWebServiceSpec(d *schema.ResourceData) (spec service.Spec) {
	spec = service.Spec{
		Attributes:   expandWebAttributes(d),
		Backend:      expandWebBackend(d),
		CertSettings: expandWebCertSettings(d),
		HTTPSettings: expandWebHTTPSettings(d),
		ClientCIDRs:  []service.ClientCIDRs{},
	}
	return
}

func expandWebAttributes(d *schema.ResourceData) (attributes service.Attributes) {
	// if connector is set, ensure access_tier is *
	accessTier := d.Get("access_tier").(string)
	connector := d.Get("connector").(string)
	if connector != "" {
		accessTier = "*"
	}

	// build HostTagSelector from access_tier
	var hostTagSelector []map[string]string
	siteNameSelector := map[string]string{"com.banyanops.hosttag.site_name": accessTier}
	hostTagSelector = append(hostTagSelector, siteNameSelector)

	attributes = service.Attributes{
		TLSSNI:            []string{d.Get("domain").(string)},
		FrontendAddresses: expandWebFrontendAddresses(d),
		HostTagSelector:   hostTagSelector,
	}
	return
}

func expandWebFrontendAddresses(d *schema.ResourceData) (frontendAddresses []service.FrontendAddress) {
	frontendAddresses = []service.FrontendAddress{
		{
			CIDR: "",
			Port: strconv.Itoa(d.Get("port").(int)),
		},
	}
	return
}

func expandWebBackend(d *schema.ResourceData) (backend service.Backend) {
	backend = service.Backend{
		Target:        expandWebTarget(d),
		ConnectorName: d.Get("connector").(string),
		DNSOverrides:  map[string]string{},
		Whitelist:     []string{},
	}
	return
}

func expandWebTarget(d *schema.ResourceData) (target service.Target) {
	return service.Target{
		Name:        d.Get("backend_domain").(string),
		Port:        strconv.Itoa(d.Get("backend_port").(int)),
		TLS:         d.Get("backend_tls").(bool),
		TLSInsecure: d.Get("backend_tls_insecure").(bool),
	}
}

func expandWebCertSettings(d *schema.ResourceData) (certSettings service.CertSettings) {
	certSettings = service.CertSettings{
		DNSNames:    []string{d.Get("domain").(string)},
		Letsencrypt: d.Get("letsencrypt").(bool),
	}
	return
}

func expandWebHTTPSettings(d *schema.ResourceData) (httpSettings service.HTTPSettings) {
	httpSettings = service.HTTPSettings{
		Enabled:         true,
		OIDCSettings:    expandWebOIDCSettings(d),
		ExemptedPaths:   expandWebExemptedPaths(d),
		Headers:         map[string]string{},
		HTTPHealthCheck: expandWebHTTPHealthCheck(),
	}
	return
}

func expandWebOIDCSettings(d *schema.ResourceData) (oidcSettings service.OIDCSettings) {
	oidcSettings = service.OIDCSettings{
		Enabled:           true,
		ServiceDomainName: fmt.Sprintf("https://%s", d.Get("domain").(string)),
	}
	return
}

func expandWebExemptedPaths(d *schema.ResourceData) (exemptedPaths service.ExemptedPaths) {
	exemptedPaths = service.ExemptedPaths{
		Enabled: false,
	}
	return
}

func expandWebHTTPHealthCheck() (httpHealthCheck service.HTTPHealthCheck) {
	httpHealthCheck = service.HTTPHealthCheck{
		Enabled:     false,
		Addresses:   nil,
		Method:      "",
		Path:        "",
		UserAgent:   "",
		FromAddress: []string{},
		HTTPS:       false,
	}
	return
}
